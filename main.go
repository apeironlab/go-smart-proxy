package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Azure/go-ntlmssp"
	"github.com/darren/gpac"
	"github.com/getlantern/systray"
	"github.com/projectdiscovery/expirablelru"
)

type MyRoundTripper struct {
	conn net.Conn
	br   *bufio.Reader
}

// connTracker keeps a registry of all active connections so that a network
// change can close them all at once and force clients to reconnect through
// the new route.
type connTracker struct {
	mu    sync.Mutex
	conns map[net.Conn]int
}

var activeConns = &connTracker{conns: make(map[net.Conn]int)}

func (t *connTracker) add(c net.Conn) {
	if c == nil {
		return
	}
	t.mu.Lock()
	t.conns[c]++
	t.mu.Unlock()
}

func (t *connTracker) remove(c net.Conn) {
	if c == nil {
		return
	}
	t.mu.Lock()
	if n := t.conns[c]; n > 1 {
		t.conns[c] = n - 1
	} else {
		delete(t.conns, c)
	}
	t.mu.Unlock()
}

func (t *connTracker) closeAll() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := len(t.conns)
	for c := range t.conns {
		c.Close()
	}
	return n
}

// trackedConn wraps a connection used by http.Transport so that it is removed
// from the registry when closed and its traffic is counted.
type trackedConn struct {
	net.Conn
	once   sync.Once
	remove func()
	in     *atomic.Int64
	out    *atomic.Int64
}

func (t *trackedConn) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	if n > 0 && t.in != nil {
		t.in.Add(int64(n))
	}
	if err != nil {
		t.once.Do(t.remove)
	}
	return n, err
}

func (t *trackedConn) Write(p []byte) (int, error) {
	n, err := t.Conn.Write(p)
	if n > 0 && t.out != nil {
		t.out.Add(int64(n))
	}
	if err != nil {
		t.once.Do(t.remove)
	}
	return n, err
}

func (t *trackedConn) Close() error {
	err := t.Conn.Close()
	t.once.Do(t.remove)
	return err
}

func (t *trackedConn) CloseWrite() error {
	if cw, ok := t.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return t.Conn.Close()
}

var (
	connResetMu   sync.Mutex
	lastConnReset time.Time
)

// resetConnections closes every active connection (client-side, tunnels and
// transport connections) so that in-flight requests fail immediately instead
// of hanging until a timeout, and clients reconnect through the new route.
// It is debounced to survive network flaps.
func resetConnections() {
	connResetMu.Lock()
	if time.Since(lastConnReset) < 2*time.Second {
		connResetMu.Unlock()
		return
	}
	lastConnReset = time.Now()
	connResetMu.Unlock()

	if n := activeConns.closeAll(); n > 0 {
		log.Printf("Network change: closed %d active connection(s)", n)
	}
}

var dnsCache *expirablelru.Cache

const (
	dialTimeout        = 10 * time.Second
	readHeaderTimeout  = 30 * time.Second
	dnsTimeout         = 2 * time.Second
	handshakeTimeout   = 30 * time.Second
	bodySpoolThreshold = 4 << 20
)

func main() {

	dnsCache = expirablelru.NewExpirableLRU(500, nil, 1*time.Hour, 2*time.Hour)

	fmt.Println("Available interfaces:")
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			fmt.Printf(" - %s\n", iface.Name)
		}
	} else {
		fmt.Printf("Error: %+v\n", err)
	}

	loadConfiguration()
	relayMgr.Start()

	if configuration.PacHijack {
		if err := ensureHostsEntry(pacHijackHost()); err != nil {
			log.Printf("PAC hijack: cannot update %s: %+v (sudo needed?)", hostsFile, err)
		}
	}
	applyChromePolicy()
	go watchSystemProxy()
	go servePac()
	go applySystemProxy()

	go serve()

	systray.Run(systrayReady, systrayExit)

}

var (
	listenMu       sync.Mutex
	activeListener net.Listener
)

func serve() {
	server := &http.Server{
		Handler:           http.HandlerFunc(proxyHandler),
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       2 * time.Minute,
	}

	for {
		ln, err := net.Listen("tcp", configuration.Address)
		if err != nil {
			log.Printf("Error listening on %s: %+v", configuration.Address, err)
			time.Sleep(3 * time.Second)
			continue
		}
		listenMu.Lock()
		activeListener = ln
		listenMu.Unlock()
		log.Printf("Listening on %s", configuration.Address)

		for {
			c, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					break // listener replaced
				}
				log.Printf("Error accepting connection: %+v", err)
				continue
			}
			log.Printf("New connection from %s", c.RemoteAddr().String())
			activeConns.add(c)
			go func(conn net.Conn) {
				defer activeConns.remove(conn)
				server.Serve(&singleConnListener{conn: conn})
			}(c)
		}
	}
}

// restartListener closes the current listener: the serve loop re-opens it
// with the new address from the configuration.
func restartListener() {
	listenMu.Lock()
	ln := activeListener
	listenMu.Unlock()
	if ln != nil {
		ln.Close()
	}
}

var (
	pacMu             sync.Mutex
	activePacListener net.Listener
)

// pacHijackHost returns the hostname to map to 127.0.0.1 in /etc/hosts.
func pacHijackHost() string {
	configMu.Lock()
	host := configuration.PacHijackHost
	configMu.Unlock()
	if host == "" {
		return "wpad"
	}
	return host
}

// pacProxyAddr is the address the generated PAC points browsers at.
func pacProxyAddr() string {
	configMu.Lock()
	address := configuration.Address
	configMu.Unlock()
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || host == "0.0.0.0" || host == "::" {
		return "127.0.0.1:3128"
	}
	return net.JoinHostPort(host, port)
}

// pacHandler serves the PAC that routes every non-local host to this proxy.
func pacHandler(w http.ResponseWriter, r *http.Request) {
	pac := fmt.Sprintf(`function FindProxyForURL(url, host) {
  if (host == "127.0.0.1" || host == "localhost" || dnsDomainIs(host, ".local")) return "DIRECT";
  return "PROXY %s";
}`, pacProxyAddr())
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	io.WriteString(w, pac)
}

// servePac serves the PAC on port 80 (the port the corporate PAC URL uses),
// so that "http://wpad/wpad.dat" resolves to 127.0.0.1 and returns a PAC that
// points at this proxy. The VPN's proxy settings are never touched.
func servePac() {
	server := &http.Server{
		Handler:           http.HandlerFunc(pacHandler),
		ReadHeaderTimeout: 10 * time.Second,
	}
	for {
		configMu.Lock()
		enabled := configuration.PacHijack
		configMu.Unlock()
		if !enabled {
			time.Sleep(3 * time.Second)
			continue
		}
		ln, err := net.Listen("tcp", "127.0.0.1:80")
		if err != nil {
			log.Printf("PAC hijack: cannot listen on 127.0.0.1:80: %+v (sudo needed?)", err)
			time.Sleep(10 * time.Second)
			continue
		}
		pacMu.Lock()
		activePacListener = ln
		pacMu.Unlock()
		log.Printf("PAC hijack: serving http://%s/wpad.dat -> %s", pacHijackHost(), pacProxyAddr())
		server.Serve(ln)
		pacMu.Lock()
		if activePacListener == ln {
			activePacListener = nil
		}
		pacMu.Unlock()
	}
}

// watchSystemProxy periodically re-applies the system proxy settings: VPN
// clients re-apply their own proxy when the tunnel reconnects, so the
// runtime override must be refreshed. applySystemProxy is idempotent and
// cheap when nothing changed.
func watchSystemProxy() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		applySystemProxy()
	}
}

// restartPacListener restarts the PAC listener (e.g. when the PAC hijack
// setting or the proxy address changes).
func restartPacListener() {
	pacMu.Lock()
	ln := activePacListener
	pacMu.Unlock()
	if ln != nil {
		ln.Close()
	}
}

type singleConnListener struct {
	conn net.Conn
	mu   sync.Mutex
	used bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.used {
		return nil, io.EOF
	}
	l.used = true
	return l.conn, nil
}

func (l *singleConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

func (l *singleConnListener) Close() error {
	return nil
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "CONNECT not supported", http.StatusInternalServerError)
			return
		}
		conn, brw, err := hj.Hijack()
		if err != nil {
			log.Printf("Error hijacking connection: %+v", err)
			return
		}
		handleConnect(conn, brw.Reader, r.Host)
		return
	}

	// Requests without an absolute-form target are addressed to this proxy
	// itself: the web UI and the API are served on the same port.
	if r.URL.Host == "" {
		if !isLoopbackRequest(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			apiMux.ServeHTTP(w, r)
			return
		}
		webUIHandler().ServeHTTP(w, r)
		return
	}

	if r.URL.Scheme != "http" {
		http.Error(w, "unsupported proxy request", http.StatusBadRequest)
		return
	}

	route, ruleName := routeFor(r.URL.Hostname())
	if route == nil {
		http.Error(w, "no route available", http.StatusServiceUnavailable)
		return
	}
	proxy := route.FindProxy(r.URL.String())

	direct := proxy.Type == "DIRECT"
	proxyAddr := ""
	if !direct {
		proxyAddr = proxy.Address
	}

	user, password := route.user, route.password
	if proxy.Username != "" {
		user, password = proxy.Username, proxy.Password
	}
	if len(route.chain) > 0 {
		// Hop credentials are used while building the tunnel, not per request.
		user, password = "", ""
		proxyAddr = chainLabel(route.chain)
	}

	rec := connReg.newConn("request", r.RemoteAddr, "", r.URL.Host, proxyAddr, route.name, route.cred, r.Method, r.URL.String())
	rec.setAuth("none")
	if !direct && user != "" {
		rec.setAuth("ntlm")
	}
	rec.event(fmt.Sprintf("%s %s", r.Method, r.URL.String()))
	if ruleName != "" {
		rec.event(fmt.Sprintf("rule %q -> route %q", ruleName, route.name))
	}

	// For DIRECT requests resolve the hostname locally (falling back to the
	// transport's own resolution). For proxied requests the URL is forwarded
	// in absolute form, which is the standard HTTP proxy behavior.
	targetHost := ""
	port := ""
	if direct {
		host := r.URL.Hostname()
		targetHost = host
		if ip := resolveHost(host); ip != "" {
			targetHost = ip
		}
		port = r.URL.Port()
		if port == "" {
			port = "80"
		}
	}

	log.Printf("Proxying %s through %s (%s) via route %q", r.URL.Host, proxy.Type, proxyAddr, route.name)

	rt := route.getRoundTripper(direct, proxyAddr, !direct && user != "")

	if spooled := spoolRequestBody(r, !direct && user != ""); spooled != nil {
		defer func() {
			spooled.Close()
			os.Remove(spooled.Name())
		}()
	}

	rp := &httputil.ReverseProxy{
		Director: func(outreq *http.Request) {
			outreq.URL.Scheme = "http"
			if direct {
				outreq.URL.Host = net.JoinHostPort(targetHost, port)
			}
			if !direct && user != "" {
				outreq.SetBasicAuth(user, password)
			}
		},
		Transport:     rt,
		FlushInterval: -1,
	}

	ctx := context.WithValue(r.Context(), connRecKey{}, rec)
	r = r.WithContext(ctx)
	if r.Body != nil && r.Body != http.NoBody {
		r.Body = &countingReadCloser{ReadCloser: r.Body, counter: &rec.bytesClientIn}
	}
	cw := &countingResponseWriter{ResponseWriter: w, counter: &rec.bytesClientOut}
	rp.ServeHTTP(cw, r)

	rec.setStatus(cw.status)
	switch {
	case rec.auth() == "failed":
		rec.finish(StateFailed)
	case cw.status >= 400:
		rec.finish(StateFailed)
	default:
		rec.finish(StateDone)
	}
	rec.event(fmt.Sprintf("response status %d", cw.status))
}

// spoolRequestBody copies large or unknown-size request bodies to a temporary
// file and returns it as a seekable reader, so that the NTLM negotiator can
// resend the body during the authentication handshake without buffering it
// entirely in memory.
func spoolRequestBody(r *http.Request, needSpool bool) *os.File {
	if !needSpool || r.Body == nil || r.ContentLength == 0 {
		return nil
	}
	if r.ContentLength > 0 && r.ContentLength <= bodySpoolThreshold {
		return nil
	}
	f, err := os.CreateTemp("", "goproxy-body-*")
	if err != nil {
		return nil
	}
	n, err := io.Copy(f, r.Body)
	r.Body.Close()
	if err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil
	}
	r.Body = f
	r.ContentLength = n
	log.Printf("Spooled request body to %s (%d bytes)", f.Name(), n)
	return f
}

func handleConnect(client net.Conn, clientBr *bufio.Reader, hostport string) {
	rawClient := client
	activeConns.add(rawClient)
	defer activeConns.remove(rawClient)
	defer rawClient.Close()

	client.SetReadDeadline(time.Time{})
	client.SetWriteDeadline(time.Time{})

	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
		port = "443"
	}

	route, ruleName := routeFor(host)
	if route == nil {
		connectError(client, http.StatusServiceUnavailable)
		return
	}
	proxy := route.FindProxy("https://" + net.JoinHostPort(host, port) + "/")

	target := net.JoinHostPort(host, port)
	if ip := resolveHost(host); ip != "" {
		target = net.JoinHostPort(ip, port)
	}

	proxyAddr := ""
	if proxy.Type != "DIRECT" {
		proxyAddr = proxy.Address
		if len(route.chain) > 0 {
			proxyAddr = chainLabel(route.chain)
		}
	}

	rec := connReg.newConn("tunnel", client.RemoteAddr().String(), host, target, proxyAddr, route.name, route.cred, "CONNECT", "")
	defer func() {
		if rec.state() != StateFailed {
			rec.finish(StateClosed)
		}
	}()
	rec.event(fmt.Sprintf("CONNECT %s", target))
	if ruleName != "" {
		rec.event(fmt.Sprintf("rule %q -> route %q", ruleName, route.name))
	}
	if proxyAddr != "" {
		rec.event(fmt.Sprintf("upstream proxy %s", proxyAddr))
	} else {
		rec.event("direct connection")
	}

	cc := &countingConn{Conn: client, in: &rec.bytesClientIn, out: &rec.bytesClientOut}
	client = cc

	var upstream net.Conn
	var upstreamBr *bufio.Reader
	rec.setCloseFn(func() {
		client.Close()
		if upstream != nil {
			upstream.Close()
		}
	})
	defer func() {
		if upstream != nil {
			activeConns.remove(upstream)
			upstream.Close()
		}
	}()

	if proxy.Type == "DIRECT" {
		upstream, err = net.DialTimeout("tcp", target, dialTimeout)
		if err != nil {
			rec.setError(err.Error())
			rec.finish(StateFailed)
			log.Printf("Error connecting to %s: %+v", target, err)
			connectError(client, http.StatusBadGateway)
			return
		}
		upstream = &countingConn{Conn: upstream, in: &rec.bytesUpIn, out: &rec.bytesUpOut}
		upstreamBr = bufio.NewReader(upstream)
	} else {
		upstream, upstreamBr, err = dialProxyAndConnect(route, proxy, target, rec)
		if err != nil {
			rec.setError(err.Error())
			rec.finish(StateFailed)
			log.Printf("Error connecting to %s through %s: %+v", target, proxy.Address, err)
			connectError(client, http.StatusBadGateway)
			return
		}
	}
	activeConns.add(upstream)

	rec.setState(StateEstablished)
	rec.event("tunnel established")

	log.Printf("Tunnel established to %s through %s via route %q", target, proxy.Address, route.name)

	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		upstream.Close()
		return
	}

	tunnel(client, clientBr, upstream, upstreamBr)
}

func dialProxyAndConnect(route *ProxyRoute, proxy *gpac.Proxy, target string, rec *ConnInfo) (net.Conn, *bufio.Reader, error) {
	if len(route.chain) > 0 {
		return dialChain(route, target, rec)
	}
	upstream, err := net.DialTimeout("tcp", proxy.Address, dialTimeout)
	if err != nil {
		return nil, nil, err
	}

	// Count handshake traffic as well as tunnel traffic.
	upstream = &countingConn{Conn: upstream, in: &rec.bytesUpIn, out: &rec.bytesUpOut}

	// Single buffered reader for the whole NTLM handshake and the tunnel:
	// bytes read ahead while parsing a response must not be lost.
	upstreamBr := bufio.NewReader(upstream)

	user, password := route.user, route.password
	if proxy.Username != "" {
		user, password = proxy.Username, proxy.Password
	}
	if err := httpConnect(upstream, upstreamBr, user, password, target, rec); err != nil {
		upstream.Close()
		return nil, nil, err
	}
	return upstream, upstreamBr, nil
}

// httpConnect performs an HTTP CONNECT to target over an already open
// connection to a proxy, with NTLM/Basic authentication when user is set.
func httpConnect(upstream net.Conn, upstreamBr *bufio.Reader, user, password, target string, rec *ConnInfo) error {
	req, err := http.NewRequest("CONNECT", "http://"+target, nil)
	if err != nil {
		return err
	}
	req.Host = target

	if user != "" {
		req.SetBasicAuth(user, password)
	}

	upstream.SetDeadline(time.Now().Add(handshakeTimeout))
	if rec != nil {
		if user != "" {
			rec.setAuth("ntlm")
			rec.setState(StateAuthenticating)
			rec.event("NTLM handshake started")
		} else {
			rec.event("no credentials, anonymous CONNECT")
		}
	}
	transp := ntlmssp.Negotiator{
		RoundTripper: MyRoundTripper{
			conn: upstream,
			br:   upstreamBr,
		},
	}
	resp, err := transp.RoundTrip(req)
	upstream.SetDeadline(time.Time{})
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("proxy returned status %d", resp.StatusCode)
	}
	if rec != nil {
		if user != "" {
			rec.setAuth("authenticated")
			rec.setState(StateAuthenticated)
			rec.event("NTLM handshake completed")
		}
	}
	return nil
}

func (mrt MyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if auth := req.Header.Get("Authorization"); auth != "" {
		req.Header.Set("Proxy-Authorization", auth)
		req.Header.Del("Authorization")
	}
	if err := req.Write(mrt.conn); err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(mrt.br, req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == 407 {
		// The NTLM negotiator defers draining the first 407 body until the
		// handshake completes, but this raw connection uses a single shared
		// reader: the body (real proxies send an HTML error page) must be
		// consumed right away, otherwise the next response read gets out of
		// sync. The final 200 (the tunnel itself) is never drained.
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		resp.StatusCode = 401
	}
	for _, v := range resp.Header.Values("Proxy-Authenticate") {
		resp.Header.Add("WWW-Authenticate", v)
	}
	return resp, nil
}

// proxyAuthRT wraps a standard http.RoundTripper used to talk to an upstream
// proxy: it moves the Authorization header (set by the NTLM negotiator) into
// Proxy-Authorization, and translates the 407 handshake responses so that the
// negotiator sees the 401/WWW-Authenticate flow it expects.
type proxyAuthRT struct {
	base http.RoundTripper
}

func (p *proxyAuthRT) RoundTrip(req *http.Request) (*http.Response, error) {
	rec, _ := req.Context().Value(connRecKey{}).(*ConnInfo)
	hadAuth := req.Header.Get("Authorization") != ""
	if rec != nil && hadAuth {
		rec.setState(StateAuthenticating)
	}
	if auth := req.Header.Get("Authorization"); auth != "" {
		req.Header.Set("Proxy-Authorization", auth)
		req.Header.Del("Authorization")
	}
	resp, err := p.base.RoundTrip(req)
	if err != nil {
		if rec != nil {
			rec.setError(err.Error())
			rec.setAuth("failed")
		}
		return nil, err
	}
	if resp.StatusCode == 407 {
		// Drain the challenge body immediately so that the underlying
		// connection is reusable for the next handshake step (keeps the
		// whole NTLM handshake on a single connection).
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		resp.StatusCode = 401
		if rec != nil {
			rec.event("407 received, handshake in progress")
			if hadAuth {
				rec.setAuth("failed")
				rec.event("credentials rejected")
			}
		}
	} else if rec != nil {
		if hadAuth {
			rec.setAuth("authenticated")
			rec.event("authenticated")
		}
	}
	for _, v := range resp.Header.Values("Proxy-Authenticate") {
		resp.Header.Add("WWW-Authenticate", v)
	}
	return resp, nil
}

// resolveHost resolves the hostname locally (so that the upstream proxy only
// sees the IP address); when the resolution fails, it returns an empty string
// and the caller lets the upstream proxy resolve the name itself.
// A name listed in the configuration's Hosts is never resolved: its address is the configured one.
func resolveHost(host string) string {
	if net.ParseIP(host) != nil {
		return host
	}
	if address, ok := configuration.Hosts[strings.ToLower(host)]; ok {
		return address
	}
	if v, ok := dnsCache.Get(host); ok {
		return v.(string)
	}
	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		dnsCache.AddWithTTL(host, "", 5*time.Minute)
		return ""
	}
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			dnsCache.AddWithTTL(host, ip.IP.String(), 30*time.Minute)
			return ip.IP.String()
		}
	}
	dnsCache.AddWithTTL(host, ips[0].IP.String(), 30*time.Minute)
	return ips[0].IP.String()
}

func connectError(c net.Conn, status int) {
	fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status, http.StatusText(status))
	c.Close()
}

type closeWriter interface {
	CloseWrite() error
}

func tunnel(client net.Conn, clientReader *bufio.Reader, upstream net.Conn, upstreamReader *bufio.Reader) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(upstream, clientReader)
		if cw, ok := upstream.(closeWriter); ok {
			cw.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		io.Copy(client, upstreamReader)
		if cw, ok := client.(closeWriter); ok {
			cw.CloseWrite()
		}
	}()

	wg.Wait()
	client.Close()
	upstream.Close()
}

func systrayReady() {
	if icon := trayIcon(); icon != nil {
		systray.SetIcon(icon)
	}
	systray.SetTitle("Proxy")
	systray.SetTooltip("Go Smart Proxy")

	allRoutes := getRoutes()
	options := make([]*systray.MenuItem, 0, len(allRoutes)+1)
	items := make([]*systray.MenuItem, len(allRoutes))

	for i, r := range allRoutes {
		mRoute := systray.AddMenuItemCheckbox(r.name, r.name, false)
		items[i] = mRoute
		options = append(options, mRoute)
	}

	mAuto := systray.AddMenuItemCheckbox("Auto", "Auto", true)
	options = append(options, mAuto)

	for i := range items {
		go func(m *systray.MenuItem, r *ProxyRoute) {
			for range m.ClickedCh {
				log.Printf("Forcing route %s", r.name)
				setForceRoute(r)
				for _, opt := range options {
					opt.Uncheck()
				}
				m.Check()
			}
		}(items[i], allRoutes[i])
	}

	go func() {
		for range mAuto.ClickedCh {
			log.Printf("Forcing route Auto")
			setForceRoute(nil)
			for _, opt := range options {
				opt.Uncheck()
			}
			mAuto.Check()
		}
	}()

	systray.AddSeparator()
	mOpen := systray.AddMenuItem("Open management page", "Open the web UI in the browser")
	go func() {
		for range mOpen.ClickedCh {
			if err := openBrowser(webUIURL()); err != nil {
				log.Printf("Cannot open the browser: %+v", err)
			}
		}
	}()
	mQuit := systray.AddMenuItem("Quit", "Quit proxy")

	go systrayReact(mQuit)
}

func systrayExit() {

}

func systrayReact(quit *systray.MenuItem) {
	select {
	case <-quit.ClickedCh:
		os.Exit(0)
	}
}
