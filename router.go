package main

import (
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	//"github.com/aeden/traceroute"
	"github.com/Azure/go-ntlmssp"
	"github.com/darren/gpac"
)

const (
	pacCacheTTL   = 6 * time.Hour
	pacFetchEvery = 30 * time.Second
	pacFetchTo    = 10 * time.Second
)

type ProxyRoute struct {
	name     string
	gateway  string
	iface    string
	net      string
	pacUrl   string
	proxyUrl string
	user     string
	password string
	cred     string

	mu             sync.Mutex
	pac            *gpac.Parser
	pacError       string
	refreshing     bool
	lastPacAttempt time.Time
	rtCache        map[string]http.RoundTripper
	transports     []*http.Transport
}

var (
	stateMu    sync.RWMutex
	discoverMu sync.Mutex

	iface      net.Interface
	defaultGw  net.IP
	network    *net.IPNet
	routes     []*ProxyRoute
	forceRoute *ProxyRoute

	ifaceNames  map[string]bool
	networkNets map[string]bool
	localIPs    []net.IP

	timer *time.Timer
)

type netState struct {
	iface       net.Interface
	defaultGw   net.IP
	network     *net.IPNet
	ifaceNames  map[string]bool
	networkNets map[string]bool
	localIPs    []net.IP
}

var pacFetchClient = &http.Client{
	Timeout: pacFetchTo,
	Transport: &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   pacFetchTo,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          4,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: pacFetchTo,
	},
}

func init() {
	discoverNetwork()

	const interval = 3 * time.Second

	timer = time.NewTimer(interval)
	go func() {
		for {
			<-timer.C
			discoverNetwork()
			timer.Reset(interval)
		}
	}()
}

func loadRoutes() {
	newRoutes := make([]*ProxyRoute, 0, len(configuration.Routes)+1)
	for _, r := range configuration.Routes {
		var cfgCred *ConfigCredential
		var user string
		var password string
		if r.Credential != "" {
			cfgCred = GetCredential(r.Credential)
			if cfgCred != nil {
				user = cfgCred.User
				password = cfgCred.Password
			}
		}
		newRoutes = append(newRoutes, &ProxyRoute{
			name:     r.Name,
			gateway:  r.Gateway,
			iface:    r.IFace,
			net:      r.Net,
			pacUrl:   r.PacUrl,
			proxyUrl: r.ProxyUrl,
			user:     user,
			password: password,
			cred:     r.Credential,
		})
		log.Printf("Loaded route %q (iface=%q gateway=%q net=%q pac=%q proxy=%q)",
			r.Name, r.IFace, r.Gateway, r.Net, r.PacUrl, r.ProxyUrl)
	}
	newRoutes = append(newRoutes, &ProxyRoute{
		name: "Direct",
	})

	stateMu.Lock()
	routes = newRoutes
	stateMu.Unlock()
}

func getRoutes() []*ProxyRoute {
	stateMu.RLock()
	defer stateMu.RUnlock()
	return routes
}

func getNetState() netState {
	stateMu.RLock()
	defer stateMu.RUnlock()
	return netState{
		iface:       iface,
		defaultGw:   defaultGw,
		network:     network,
		ifaceNames:  ifaceNames,
		networkNets: networkNets,
		localIPs:    localIPs,
	}
}

func setForceRoute(r *ProxyRoute) {
	stateMu.Lock()
	forceRoute = r
	stateMu.Unlock()
}

func getForceRoute() *ProxyRoute {
	stateMu.RLock()
	defer stateMu.RUnlock()
	return forceRoute
}

func discoverNetwork() {
	discoverMu.Lock()
	defer discoverMu.Unlock()

	ip, diface, ipnet, err := FindGatewayAndNetwork()
	if err != nil {
		log.Printf("Unable to determine default interface: %+v", err)
		return
	}

	ifaces, _ := net.Interfaces()
	newIfaceNames := make(map[string]bool)
	newNetworkNets := make(map[string]bool)
	var newLocalIPs []net.IP
	for _, i := range ifaces {
		newIfaceNames[i.Name] = true
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			iIP, inet, err := net.ParseCIDR(a.String())
			if err == nil {
				newNetworkNets[inet.String()] = true
				newLocalIPs = append(newLocalIPs, iIP)
			}
		}
	}

	log.Printf("Found default gateway (or local IP) %s, default interface %s with net %s", ip.String(), diface.Name, ipnet.String())

	stateMu.Lock()
	firstRun := defaultGw == nil
	changed := defaultGw == nil || !defaultGw.Equal(ip) ||
		iface.Name != diface.Name ||
		network == nil || network.String() != ipnet.String()

	if !changed {
		if len(ifaceNames) != len(newIfaceNames) {
			changed = true
		} else {
			for k := range newIfaceNames {
				if !ifaceNames[k] {
					changed = true
					break
				}
			}
		}
	}
	if !changed {
		if len(networkNets) != len(newNetworkNets) {
			changed = true
		} else {
			for k := range newNetworkNets {
				if !networkNets[k] {
					changed = true
					break
				}
			}
		}
	}

	ifaceChanged := iface.Name != diface.Name
	if changed {
		defaultGw = ip
		iface = diface
		network = ipnet
		ifaceNames = newIfaceNames
		networkNets = newNetworkNets
		localIPs = newLocalIPs
	}
	stateMu.Unlock()

	if !changed {
		return
	}

	// DNS mappings only become invalid when the interface itself changes, not
	// on every address renewal (e.g. VPN address flapping).
	if ifaceChanged && dnsCache != nil {
		dnsCache.Purge()
	}
	for _, r := range getRoutes() {
		r.invalidatePAC()
		r.resetTransports()
	}
	// On a real network change every existing connection is doomed: kill them
	// all so clients fail fast and reconnect through the new route. Also
	// re-apply the system proxy, which VPN clients tend to overwrite.
	if !firstRun {
		resetConnections()
		go applySystemProxy()
	}
}

func FindGatewayAndNetwork() (net.IP, net.Interface, *net.IPNet, error) {
	// Preferred: the real default route (gateway + interface). This is what
	// determines where traffic actually goes, regardless of leftover VPN
	// interfaces.
	if gateway, ifaceName, err := defaultRouteInfo(); err == nil {
		if ni, err := net.InterfaceByName(ifaceName); err == nil {
			addrs, err := ni.Addrs()
			if err == nil {
				for _, addr := range addrs {
					if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
						gwIP := net.ParseIP(gateway)
						if gwIP == nil {
							gwIP = ipnet.IP
						}
						return gwIP, *ni, ipnet, nil
					}
				}
			}
		}
	}

	// Fallback: find the interface owning the outbound IP.
	oip, err := GetOutboundIP()
	if err != nil {
		log.Printf("Error: method UDP out failed: %+v", err)
		return nil, net.Interface{}, nil, err
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, net.Interface{}, nil, err
	}
	for _, liface := range interfaces {
		addrs, err := liface.Addrs()
		if err != nil {
			return nil, net.Interface{}, nil, err
		}
		for _, addr := range addrs {
			_, ifaceIpNet, err := net.ParseCIDR(addr.String())
			if err != nil {
				return nil, net.Interface{}, nil, err
			}
			if ifaceIpNet.Contains(oip) {
				return oip, liface, ifaceIpNet, nil
			}
		}
	}
	return nil, net.Interface{}, nil, fmt.Errorf("unable to find ip and default interface")
}

func GetOutboundIP() (net.IP, error) {
	// UDP dialing does not send any packet, it just resolves the route; try
	// several well-known targets in case some are not routed (e.g. VPN).
	targets := []string{"8.8.8.8:80", "1.1.1.1:80", "9.9.9.9:80", "208.67.222.222:80"}
	var lastErr error
	for _, target := range targets {
		conn, err := net.DialTimeout("udp", target, 2*time.Second)
		if err != nil {
			lastErr = err
			continue
		}
		localAddr := conn.LocalAddr().(*net.UDPAddr)
		conn.Close()
		return localAddr.IP, nil
	}
	return nil, lastErr
}

func (p *ProxyRoute) pacCacheFile() string {
	digest := md5.Sum([]byte(p.pacUrl))
	return GetCacheDir() + fmt.Sprintf("/pac-%x", digest)
}

// Check makes sure the route is usable. For PAC routes it loads the local
// cache (or starts a background refresh) and never blocks on the network:
// the cached version is always used when available.
func (p *ProxyRoute) Check() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pacUrl == "" {
		return nil
	}
	if p.pac != nil {
		return nil
	}
	if b, err := os.ReadFile(p.pacCacheFile()); err == nil {
		if pac, err := gpac.New(string(b)); err == nil {
			p.pac = pac
			return nil
		}
	}
	if !p.refreshing {
		p.refreshing = true
		go p.tryFetchPac()
	}
	return fmt.Errorf("PAC not available for %s", p.pacUrl)
}

func (p *ProxyRoute) tryFetchPac() {
	bytes, err := fetchPac(p.pacUrl)

	p.mu.Lock()
	defer p.mu.Unlock()
	p.refreshing = false
	p.lastPacAttempt = time.Now()
	if err != nil {
		p.pacError = err.Error()
		log.Printf("Error fetching PAC %s: %+v (keeping cached version)", p.pacUrl, err)
		return
	}
	pac, err := gpac.New(string(bytes))
	if err != nil {
		p.pacError = err.Error()
		log.Printf("Error parsing PAC %s: %+v", p.pacUrl, err)
		return
	}
	p.pac = pac
	p.pacError = ""
	if err := os.WriteFile(p.pacCacheFile(), bytes, 0644); err != nil {
		log.Printf("Error caching PAC file: %+v", err)
	}
	log.Printf("PAC refreshed from %s (%d bytes)", p.pacUrl, len(bytes))
}

// forceRefreshPAC refreshes the PAC in background, bypassing the throttle
// (used by the web UI).
func (p *ProxyRoute) forceRefreshPAC() {
	p.mu.Lock()
	if p.pacUrl == "" || p.refreshing {
		p.mu.Unlock()
		return
	}
	p.refreshing = true
	p.mu.Unlock()
	go p.tryFetchPac()
}

func fetchPac(pacUrl string) ([]byte, error) {
	resp, err := pacFetchClient.Get(pacUrl)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d fetching %s", resp.StatusCode, pacUrl)
	}
	return io.ReadAll(resp.Body)
}

func (p *ProxyRoute) invalidatePAC() {
	p.mu.Lock()
	if p.pacUrl == "" {
		p.mu.Unlock()
		return
	}
	p.mu.Unlock()
	p.refreshPAC()
}

// refreshPAC starts a background PAC refresh (at most one in flight, and at
// most one per pacFetchEvery). The request path is never blocked.
func (p *ProxyRoute) refreshPAC() {
	p.mu.Lock()
	if p.refreshing || time.Since(p.lastPacAttempt) < pacFetchEvery {
		p.mu.Unlock()
		return
	}
	p.refreshing = true
	p.mu.Unlock()
	go p.tryFetchPac()
}

// applicable checks the cheap network filters and returns the reason why the
// route is not applicable, if any. The PAC is checked only by Check().
func (p *ProxyRoute) applicable(st netState) (bool, string) {
	if p.gateway != "" && (st.defaultGw == nil || st.defaultGw.String() != p.gateway) {
		return false, fmt.Sprintf("gateway %s != %s", st.defaultGw.String(), p.gateway)
	}
	if p.iface != "" && st.iface.Name != p.iface {
		return false, fmt.Sprintf("default iface %q != %q", st.iface.Name, p.iface)
	}
	if p.net != "" {
		found := false
		if st.networkNets[p.net] {
			found = true
		} else {
			_, pNet, err := net.ParseCIDR(p.net)
			if err == nil {
				for _, ip := range st.localIPs {
					if pNet.Contains(ip) {
						found = true
						break
					}
				}
			}
		}
		if !found {
			netStr := ""
			if st.network != nil {
				netStr = st.network.String()
			}
			return false, fmt.Sprintf("net %q not found (default is %q)", p.net, netStr)
		}
	}
	return true, ""
}

func (p *ProxyRoute) isApplicable(st netState) bool {
	ok, _ := p.applicable(st)
	if !ok {
		return false
	}
	return p.Check() == nil
}

func (p *ProxyRoute) IsApplicable() bool {
	return p.isApplicable(getNetState())
}

// info returns the route details for the web UI.
func (p *ProxyRoute) info(st netState) routeInfoJSON {
	applicable, why := p.applicable(st)
	if applicable {
		applicable = p.Check() == nil
		if !applicable {
			why = "PAC not available"
		}
	}
	p.mu.Lock()
	pacStatus := "none"
	if p.pacUrl != "" {
		switch {
		case p.refreshing:
			pacStatus = "loading"
		case p.pac != nil:
			pacStatus = "loaded"
		default:
			pacStatus = "error"
		}
	}
	pacError := p.pacError
	p.mu.Unlock()

	return routeInfoJSON{
		Name:       p.name,
		Gateway:    p.gateway,
		IFace:      p.iface,
		Net:        p.net,
		PacUrl:     p.pacUrl,
		ProxyUrl:   p.proxyUrl,
		Credential: p.cred,
		Applicable: applicable,
		WhyNot:     why,
		PacStatus:  pacStatus,
		PacError:   pacError,
	}
}

func (p *ProxyRoute) FindProxy(urlStr string) *gpac.Proxy {
	p.mu.Lock()
	pac := p.pac
	proxyUrl := p.proxyUrl
	p.mu.Unlock()

	if pac != nil {
		proxies, err := pac.FindProxy(urlStr)
		if err != nil {
			log.Printf("Error evaluating PAC for %s: %+v", urlStr, err)
		} else if len(proxies) > 0 {
			return proxies[0]
		} else {
			log.Printf("PAC returned no proxy for %s", urlStr)
		}
		return &gpac.Proxy{Type: "DIRECT"}
	}
	if proxyUrl != "" {
		if pUrl, err := url.Parse(proxyUrl); err == nil && pUrl.Host != "" {
			return &gpac.Proxy{
				Type:    "PROXY",
				Address: pUrl.Host,
			}
		}
		return &gpac.Proxy{
			Type:    "PROXY",
			Address: proxyUrl,
		}
	}
	return &gpac.Proxy{
		Type: "DIRECT",
	}
}

// getRoundTripper returns a cached http.RoundTripper for the given upstream
// configuration. Transports are cached per proxy address so that connections
// are kept alive and reused across requests.
func (p *ProxyRoute) getRoundTripper(direct bool, proxyAddr string, auth bool) http.RoundTripper {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.rtCache == nil {
		p.rtCache = make(map[string]http.RoundTripper)
	}
	key := "DIRECT"
	if !direct {
		key = proxyAddr
	}
	if auth {
		key += "|auth"
	}
	if rt, ok := p.rtCache[key]; ok {
		return rt
	}

	var proxyURL *url.URL
	if !direct {
		u, err := url.Parse("http://" + proxyAddr)
		if err != nil {
			u = nil
		}
		proxyURL = u
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			rec := connReg.newConn("transport", "", "", addr, proxyURLString(proxyURL), p.name, p.cred, "", "")
			if auth {
				rec.setAuth("ntlm")
			}
			rec.setState(StateEstablished)
			activeConns.add(conn)
			tc := &trackedConn{
				Conn: conn,
				remove: func() {
					activeConns.remove(conn)
					rec.finish(StateClosed)
				},
				in:  &rec.bytesUpIn,
				out: &rec.bytesUpOut,
			}
			rec.setCloseFn(func() { tc.Close() })
			return tc, nil
		},
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}

	var rt http.RoundTripper = transport
	if auth {
		rt = ntlmssp.Negotiator{RoundTripper: &proxyAuthRT{base: transport}}
	}

	p.rtCache[key] = rt
	p.transports = append(p.transports, transport)
	return rt
}

// resetTransports closes the idle connections of every transport used by this
// route and drops the transport cache, so that after a network change new
// requests open fresh connections instead of reusing dead ones.
func (p *ProxyRoute) resetTransports() {
	p.mu.Lock()
	for _, t := range p.transports {
		t.CloseIdleConnections()
	}
	p.transports = nil
	p.rtCache = make(map[string]http.RoundTripper)
	p.mu.Unlock()
}

func proxyURLString(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.Host
}

// GetApplicableRoute returns the first route whose configured criteria
// (gateway, interface, network) match the current network state, with the
// forced route taking precedence when set. Direct is always last and always
// applicable.
func GetApplicableRoute() *ProxyRoute {
	st := getNetState()
	if fr := getForceRoute(); fr != nil {
		err := fr.Check()
		if err == nil {
			return fr
		}
		log.Printf("Error checking route %s: %+v", fr.name, err)
	}
	for _, r := range getRoutes() {
		if r.isApplicable(st) {
			return r
		}
	}
	return nil
}
