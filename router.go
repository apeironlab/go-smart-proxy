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
	"strings"
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
	name      string
	gateway   string
	iface     string
	net       string
	ifaceUp   string
	vpn       string
	exitVPN   string
	exitLabel string
	pacUrl    string
	proxyUrl  string
	user      string
	password  string
	cred      string
	chain     []*chainHop
	hops      []ConfigHop // chain as configured, for editing
	rulesOnly bool        // usable only by destination rules, not as default route

	// automaticChain is the chain cut before the first RulesOnly hop; it is
	// what the automatic selection uses. auto is its lazily built route.
	autoChain []*chainHop
	autoHops  []ConfigHop
	autoCut   bool
	auto      *ProxyRoute

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
	analysis    netAnalysis

	timer *time.Timer
)

type netState struct {
	iface       net.Interface
	defaultGw   net.IP
	network     *net.IPNet
	ifaceNames  map[string]bool
	networkNets map[string]bool
	localIPs    []net.IP
	analysis    netAnalysis
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

// migrateRouteUpstreams converts the legacy route-level upstream fields into a
// single hop in Chain. The change is in memory: the startup path persists it,
// while tests and reconfigurations simply use the migrated route.
func migrateRouteUpstreams() bool {
	changed := false
	for i := range configuration.Routes {
		r := &configuration.Routes[i]
		if len(r.Chain) == 0 && (r.PacUrl != "" || r.ProxyUrl != "") {
			cred := r.Credential
			if cred != "" && GetCredential(cred) == nil {
				log.Printf("Route %q: legacy credential %q not found; migrating without credentials", r.Name, cred)
				cred = ""
			}
			hop := ConfigHop{Credential: cred}
			if r.PacUrl != "" {
				if r.ProxyUrl != "" {
					log.Printf("Route %q: both PacUrl and ProxyUrl set; migrating PacUrl (it took precedence)", r.Name)
				}
				hop.PacUrl = r.PacUrl
			} else {
				hop.ProxyUrl = r.ProxyUrl
			}
			r.Chain = []ConfigHop{hop}
			changed = true
		}
		if r.PacUrl != "" || r.ProxyUrl != "" || r.Credential != "" {
			r.PacUrl, r.ProxyUrl, r.Credential = "", "", ""
			changed = true
		}
	}
	return changed
}

// newProxyRoute validates a configured route and builds its runtime form.
func newProxyRoute(r *ConfigRoute) (*ProxyRoute, error) {
	p := &ProxyRoute{
		name:      r.Name,
		gateway:   r.Gateway,
		iface:     r.IFace,
		net:       r.Net,
		ifaceUp:   strings.TrimSpace(r.IFaceUp),
		vpn:       strings.ToLower(strings.TrimSpace(r.VPN)),
		exitVPN:   strings.ToLower(strings.TrimSpace(r.ExitVPN)),
		exitLabel: strings.TrimSpace(r.ExitLabel),
		rulesOnly: r.RulesOnly,
		hops:      append([]ConfigHop(nil), r.Chain...),
	}
	if p.vpn != "" && p.vpn != "up" && p.vpn != "down" {
		return nil, fmt.Errorf("invalid VPN %q (use \"up\" or \"down\")", r.VPN)
	}
	if !validExitVPN(p.exitVPN) {
		return nil, fmt.Errorf("invalid ExitVPN %q (use \"up\" or \"down\")", r.ExitVPN)
	}
	if !validLabelPattern(p.exitLabel) {
		return nil, fmt.Errorf("invalid ExitLabel %q", r.ExitLabel)
	}
	chain, err := buildChain(r.Chain)
	if err != nil {
		return nil, fmt.Errorf("invalid Chain: %w", err)
	}

	// A PAC hop is not a proxy: the route evaluates the PAC file per request.
	if len(chain) == 1 && chain[0].scheme == "pac" {
		p.pacUrl = chain[0].addr
		p.cred = chain[0].cred
		p.user, p.password = chain[0].user, chain[0].password
		if chain[0].rulesOnly {
			// A PAC cannot be cut: only-rules means the whole route is.
			p.rulesOnly = true
		}
		return p, nil
	}

	// A single unflagged HTTP proxy keeps the legacy request path: plain HTTP
	// is forwarded in absolute form and NTLM uses the connection-based
	// negotiator, exactly as before chains were introduced.
	if len(chain) == 1 && chain[0].scheme == "http" && !chain[0].rulesOnly {
		p.proxyUrl = chain[0].addr
		p.cred = chain[0].cred
		p.user, p.password = chain[0].user, chain[0].password
		return p, nil
	}

	p.chain = chain
	p.autoChain, p.autoHops, p.autoCut = automaticChain(chain, r.Chain)
	return p, nil
}

func loadRoutes() {
	migrateRouteUpstreams()

	newRoutes := make([]*ProxyRoute, 0, len(configuration.Routes)+1)
	for i := range configuration.Routes {
		r := &configuration.Routes[i]
		route, err := newProxyRoute(r)
		if err != nil {
			log.Printf("Route %q: %v (route skipped)", r.Name, err)
			continue
		}
		newRoutes = append(newRoutes, route)
		log.Printf("Loaded route %q (iface=%q gateway=%q net=%q ifaceUp=%q vpn=%q upstream=%q)",
			r.Name, route.iface, route.gateway, route.net, route.ifaceUp, route.vpn, configHopsLabel(route.hops))
	}
	newRoutes = append(newRoutes, &ProxyRoute{
		name: "Direct",
	})

	stateMu.Lock()
	routes = newRoutes
	stateMu.Unlock()

	compiled := make([]*routingRule, 0, len(configuration.Rules))
	for _, c := range configuration.Rules {
		rule, err := compileRule(c)
		if err != nil {
			log.Printf("Skipping invalid rule: %v", err)
			continue
		}
		compiled = append(compiled, rule)
		log.Printf("Loaded rule %q -> route %q", c.Name, c.Route)
	}
	rulesMu.Lock()
	routeRules = compiled
	rulesMu.Unlock()

	refreshTrayMenu()
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
		analysis:    analysis,
	}
}

func setForceRoute(r *ProxyRoute) {
	if r != nil && r.rulesOnly {
		// Rules-only routes are never forced: destination rules are their only
		// entry point.
		r = nil
	}
	stateMu.Lock()
	forceRoute = r
	stateMu.Unlock()
	refreshTrayMenu()
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

	newAnalysis, aerr := detectNetwork()
	if aerr != nil {
		log.Printf("Network detection: %v (VPN state unknown)", aerr)
	}
	log.Printf("Found default gateway (or local IP) %s, default interface %s with net %s, VPN: %s",
		ip.String(), diface.Name, ipnet.String(), vpnLabel(newAnalysis))

	stateMu.Lock()
	firstRun := defaultGw == nil
	changed := defaultGw == nil || !defaultGw.Equal(ip) ||
		iface.Name != diface.Name ||
		network == nil || network.String() != ipnet.String()

	if !changed && analysis.signature() != newAnalysis.signature() {
		changed = true
	}
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
		analysis = newAnalysis
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
		// Contacts see whether this device is on a VPN: tell them it changed.
		go relayHub.PublishContext()
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
	c := netCriteria{Gateway: p.gateway, IFace: p.iface, Net: p.net, IFaceUp: p.ifaceUp, VPN: p.vpn}
	if ok, why := c.match(st); !ok {
		return false, why
	}
	if ok, why := exitConditionsMet(p, p.exitVPN, p.exitLabel); !ok {
		return false, why
	}
	return true, ""
}

// vpnLabel summarizes the VPN detection for logs.
func vpnLabel(a netAnalysis) string {
	if len(a.VPN) == 0 {
		return "none"
	}
	return strings.Join(a.VPN, ", ")
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
		IFaceUp:    p.ifaceUp,
		VPN:        p.vpn,
		ExitVPN:    p.exitVPN,
		ExitLabel:  p.exitLabel,
		Chain:      chainStrings(p.chain),
		Hops:       append([]ConfigHop{}, p.hops...),
		RulesOnly:  p.rulesOnly,
		Applicable: applicable,
		WhyNot:     why,
		PacStatus:  pacStatus,
		PacError:   pacError,
	}
}

func (p *ProxyRoute) FindProxy(urlStr string) *gpac.Proxy {
	if len(p.chain) > 0 {
		return &gpac.Proxy{Type: "PROXY", Address: firstChainAddr(p.chain)}
	}
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

// autoRoute returns the route variant used by the automatic selection: its
// chain stops before the first hop marked RulesOnly. Routes without such hops
// are returned unchanged.
func (p *ProxyRoute) autoRoute() *ProxyRoute {
	if !p.autoCut {
		return p
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.auto == nil {
		p.auto = &ProxyRoute{
			name:  p.name,
			cred:  p.cred,
			chain: p.autoChain,
			hops:  p.autoHops,
		}
	}
	return p.auto
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

	if len(p.chain) > 0 && !direct {
		transport := p.newChainTransport()
		p.rtCache[key] = transport
		p.transports = append(p.transports, transport)
		return transport
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
// forced route taking precedence when set. Routes marked RulesOnly are skipped
// (only destination rules can select them). Direct is always last and always
// applicable.
func GetApplicableRoute() *ProxyRoute {
	return getApplicableRoute(func(r *ProxyRoute) bool { return r.rulesOnly })
}

// getApplicableRoute is GetApplicableRoute with a filter: the routes for which
// skip returns true are ignored. For instance the relay connection skips the
// rules-only routes (unless it can stop before their relay hop), and the
// normal selection skips every rules-only route.
func getApplicableRoute(skip func(*ProxyRoute) bool) *ProxyRoute {
	st := getNetState()
	if fr := getForceRoute(); fr != nil && (skip == nil || !skip(fr)) {
		err := fr.Check()
		if err == nil {
			return fr
		}
		log.Printf("Error checking route %s: %+v", fr.name, err)
	}
	for _, r := range getRoutes() {
		if skip != nil && skip(r) {
			continue
		}
		if r.isApplicable(st) {
			return r
		}
	}
	return nil
}
