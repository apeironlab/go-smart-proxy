package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"github.com/apeironlab/go-smart-proxy/relay"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// chainHop is one proxy of a route chain. The protocol spoken to it depends on
// the scheme of its ProxyUrl: http:// (CONNECT, NTLM/Basic) or socks5://.
// A chainHop with scheme "pac" is a PAC file instead of a proxy: it must be the
// only hop of its chain and is evaluated by the route, not dialed.
// A chainHop with scheme "dynamic" is a routing decision point: it must be the
// last hop and is replaced at dial time with the chain of the route selected by
// the destination rules.
type chainHop struct {
	scheme    string // "http", "socks5", "relay", "pac" or "dynamic"
	addr      string // host:port, or the contact e-mail for relay hops, or the PAC URL
	device    string // relay hops: contact device code (empty = any)
	relayName string // relay hops: which relay server (empty = the one that knows the contact)
	user      string
	password  string
	cred      string
	rulesOnly bool // chain stops before this hop unless a rule selected the route
}

func buildChain(cfg []ConfigHop) ([]*chainHop, error) {
	hops := make([]*chainHop, 0, len(cfg))
	relayHop := -1
	for i, h := range cfg {
		if h.Dynamic {
			if h.ProxyUrl != "" || h.PacUrl != "" {
				return nil, fmt.Errorf("hop %d: a dynamic hop cannot also be a proxy or a PAC", i+1)
			}
			if i != len(cfg)-1 {
				return nil, fmt.Errorf("hop %d: a dynamic hop must be the last hop of the chain", i+1)
			}
			if h.Credential != "" {
				return nil, fmt.Errorf("hop %d: a dynamic hop has no credentials", i+1)
			}
			hops = append(hops, &chainHop{scheme: "dynamic", rulesOnly: h.RulesOnly})
			continue
		}
		if h.PacUrl != "" {
			if h.ProxyUrl != "" {
				return nil, fmt.Errorf("hop %d: set either ProxyUrl or PacUrl, not both", i+1)
			}
			if len(cfg) != 1 {
				return nil, fmt.Errorf("hop %d: a PAC hop must be the only hop of the chain", i+1)
			}
			u, err := url.Parse(h.PacUrl)
			if err != nil || u.Host == "" {
				return nil, fmt.Errorf("hop %d: invalid PacUrl %q (use http:// or https://)", i+1, h.PacUrl)
			}
			if scheme := strings.ToLower(u.Scheme); scheme != "http" && scheme != "https" {
				return nil, fmt.Errorf("hop %d: invalid PacUrl %q (use http:// or https://)", i+1, h.PacUrl)
			}
			hop := &chainHop{scheme: "pac", addr: h.PacUrl, cred: h.Credential, rulesOnly: h.RulesOnly}
			if h.Credential != "" {
				c := GetCredential(h.Credential)
				if c == nil {
					return nil, fmt.Errorf("hop %d: unknown credential %q", i+1, h.Credential)
				}
				hop.user, hop.password = c.User, c.Password
			} else if u.User != nil {
				hop.user = u.User.Username()
				hop.password, _ = u.User.Password()
			}
			hops = append(hops, hop)
			continue
		}

		raw := h.ProxyUrl
		if raw == "" {
			return nil, fmt.Errorf("hop %d: ProxyUrl or PacUrl is required", i+1)
		}
		if !strings.Contains(raw, "://") {
			raw = "http://" + raw
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("hop %d: invalid ProxyUrl %q", i+1, h.ProxyUrl)
		}
		hop := &chainHop{scheme: strings.ToLower(u.Scheme), addr: u.Host, cred: h.Credential, rulesOnly: h.RulesOnly}
		switch hop.scheme {
		case "http":
		case "relay": // relay://alice@example.com[/device]: exit through the network of a contact
			if relayHop >= 0 {
				return nil, fmt.Errorf("hop %d: only one relay hop is allowed per chain", i+1)
			}
			email, ok := relay.NormalizeEmail(u.User.Username() + "@" + u.Hostname())
			if u.User == nil || !ok {
				return nil, fmt.Errorf("hop %d: use relay://name@domain with the contact's e-mail", i+1)
			}
			device, ok := relay.NormalizeDevice(strings.TrimPrefix(u.Path, "/"))
			if !ok {
				return nil, fmt.Errorf("hop %d: use relay://name@domain/device with a simple device code", i+1)
			}
			relayName := strings.ToLower(strings.TrimSpace(u.Query().Get("relay")))
			if relayName != "" && !validRelayName(relayName) {
				return nil, fmt.Errorf("hop %d: invalid relay name %q (lowercase letters, digits, - and _)", i+1, relayName)
			}
			relayHop = i
			hops = append(hops, &chainHop{scheme: "relay", addr: email, device: device, relayName: relayName, rulesOnly: h.RulesOnly})
			continue
		case "socks5", "socks5h":
			hop.scheme = "socks5"
		default:
			return nil, fmt.Errorf("hop %d: unsupported scheme %q (use http or socks5)", i+1, u.Scheme)
		}
		if u.Port() == "" {
			port := "8080"
			if hop.scheme == "socks5" {
				port = "1080"
			}
			hop.addr = net.JoinHostPort(u.Hostname(), port)
		}
		if h.Credential != "" {
			c := GetCredential(h.Credential)
			if c == nil {
				return nil, fmt.Errorf("hop %d: unknown credential %q", i+1, h.Credential)
			}
			hop.user, hop.password = c.User, c.Password
		} else if u.User != nil {
			hop.user = u.User.Username()
			hop.password, _ = u.User.Password()
		}
		hops = append(hops, hop)
	}
	return hops, nil
}

// configHopsLabel renders the configured upstream of a route for logs.
func configHopsLabel(cfg []ConfigHop) string {
	parts := make([]string, 0, len(cfg))
	for _, h := range cfg {
		if h.Dynamic {
			parts = append(parts, "dynamic")
			continue
		}
		if h.PacUrl != "" {
			parts = append(parts, "pac "+h.PacUrl)
			continue
		}
		parts = append(parts, h.ProxyUrl)
	}
	return strings.Join(parts, " -> ")
}

// maxDynamicDepth bounds the recursive expansion of dynamic hops in case
// configurations are changed while a request is being routed.
const maxDynamicDepth = 8

// expandDynamic replaces each dynamic hop with the chain of the route selected
// by the destination rules for this target. A dynamic hop is terminal: when no
// rule matches, when the selected route is not applicable, or when a loop is
// detected, nothing is appended and the connection continues directly from the
// hops already traversed.
func expandDynamic(chain []*chainHop, routeName, host, target string) []*chainHop {
	visited := map[string]bool{routeName: true}
	return expandDynamicHops(chain, host, target, visited, 0)
}

func expandDynamicHops(chain []*chainHop, host, target string, visited map[string]bool, depth int) []*chainHop {
	out := make([]*chainHop, 0, len(chain))
	for _, h := range chain {
		if h.scheme != "dynamic" {
			out = append(out, h)
			continue
		}
		if depth >= maxDynamicDepth {
			log.Printf("dynamic hop: maximum expansion depth reached for %s, connecting directly", host)
			continue
		}
		rt, rule := firstRuleRoute(host)
		if rt == nil {
			log.Printf("dynamic hop: no matching rule for %s, connecting directly", host)
			continue
		}
		if visited[rt.name] {
			log.Printf("dynamic hop: loop through route %q for %s, connecting directly", rt.name, host)
			continue
		}
		visited[rt.name] = true
		log.Printf("dynamic hop: rule %q selects route %q for %s", rule, rt.name, host)
		out = append(out, dynamicRouteHops(rt, host, target, visited, depth+1)...)
	}
	return out
}

// dynamicRouteHops turns the route selected at a dynamic hop into concrete
// hops. A route without upstreams (Direct) adds nothing.
func dynamicRouteHops(rt *ProxyRoute, host, target string, visited map[string]bool, depth int) []*chainHop {
	if len(rt.chain) > 0 {
		return expandDynamicHops(rt.chain, host, target, visited, depth)
	}
	if rt.pacUrl != "" {
		proxy := rt.FindProxy("https://" + target + "/")
		if proxy.Type == "DIRECT" || proxy.Address == "" {
			return nil
		}
		hop := &chainHop{scheme: "http", addr: proxy.Address, cred: rt.cred}
		hop.user, hop.password = rt.user, rt.password
		if proxy.Username != "" {
			hop.user, hop.password = proxy.Username, proxy.Password
		}
		return []*chainHop{hop}
	}
	if rt.proxyUrl != "" {
		return []*chainHop{{
			scheme: "http", addr: rt.proxyUrl, user: rt.user, password: rt.password, cred: rt.cred,
		}}
	}
	return nil
}

// firstChainAddr returns the first address usable in a connection log. A
// dynamic hop has no address of its own, so it is represented by the marker.
func firstChainAddr(chain []*chainHop) string {
	for _, h := range chain {
		if h.scheme != "dynamic" {
			return h.addr
		}
	}
	return "dynamic"
}

// automaticChain returns the part of the chain usable by the automatic
// selection: it stops before the first hop marked RulesOnly, because that hop
// and the ones after it are only traversed when a destination rule selects the
// route. The last value reports whether the chain was cut.
func automaticChain(chain []*chainHop, hops []ConfigHop) ([]*chainHop, []ConfigHop, bool) {
	for i, h := range chain {
		if !h.rulesOnly {
			continue
		}
		outChain := append([]*chainHop{}, chain[:i]...)
		var outHops []ConfigHop
		if i <= len(hops) {
			outHops = append([]ConfigHop{}, hops[:i]...)
		}
		return outChain, outHops, true
	}
	return nil, nil, false
}

func chainStrings(hops []*chainHop) []string {
	out := make([]string, len(hops))
	for i, h := range hops {
		if h.scheme == "dynamic" {
			out[i] = "dynamic"
			continue
		}
		if h.scheme == "pac" {
			out[i] = h.addr
			continue
		}
		out[i] = h.scheme + "://" + h.addr
		if h.scheme == "relay" && h.device != "" {
			out[i] += "/" + h.device
		}
	}
	return out
}

func chainLabel(hops []*chainHop) string {
	addrs := make([]string, len(hops))
	for i, h := range hops {
		if h.scheme == "dynamic" {
			addrs[i] = "dynamic"
			continue
		}
		addrs[i] = h.addr
		if h.scheme == "relay" {
			addrs[i] = relayDisplay(h)
		}
	}
	return strings.Join(addrs, " → ")
}

func relayDisplay(h *chainHop) string {
	s := h.addr
	if h.device != "" {
		s += "/" + h.device
	}
	if h.relayName != "" {
		s += " @" + h.relayName
	}
	return s
}

// dialChain opens a tunnel to target through every hop of the route, in order.
// A relay hop is the exit through a contact: the hops before it are the path
// used by the relay client to reach the relay server, so they are not dialed
// again here; the hops after it are reached through the relay tunnel.
// Dynamic hops are expanded first using the destination rules for host.
// The returned reader must be used for all further reads from the connection.
func dialChain(route *ProxyRoute, target, host string, rec *ConnInfo) (net.Conn, *bufio.Reader, error) {
	hops := expandDynamic(route.chain, route.name, host, target)
	if len(hops) == 0 {
		// A dynamic hop with no matching rule: connect to the target from the
		// point reached so far, which is the local machine.
		raw, err := net.DialTimeout("tcp", target, dialTimeout)
		if err != nil {
			return nil, nil, err
		}
		conn := &countingConn{Conn: raw, in: &rec.bytesUpIn, out: &rec.bytesUpOut}
		return conn, bufio.NewReader(conn), nil
	}
	if hops[0].scheme == "pac" {
		return nil, nil, errors.New("a PAC hop cannot be dialed as a proxy chain")
	}
	if hops[0].scheme == "relayapp" {
		// An application published by the relay: the relay takes the
		// connection to its gateway. The target says nothing here.
		rec.event(fmt.Sprintf("application %s on relay %s", hops[0].device, hops[0].relayName))
		raw, err := relayHub.DialApp(hops[0].relayName, hops[0].device)
		if err != nil {
			return nil, nil, fmt.Errorf("application: %w", err)
		}
		conn := &countingConn{Conn: raw, in: &rec.bytesUpIn, out: &rec.bytesUpOut}
		return conn, bufio.NewReader(conn), nil
	}
	relayIdx := -1
	for i, h := range hops {
		if h.scheme == "relay" {
			relayIdx = i
			break
		}
	}

	var conn net.Conn
	first := 0
	if relayIdx >= 0 {
		next := target
		if relayIdx+1 < len(hops) {
			next = hops[relayIdx+1].addr
		}
		rec.event(fmt.Sprintf("hop %d/%d relay via %s -> %s", relayIdx+1, len(hops), relayDisplay(hops[relayIdx]), next))
		raw, err := relayHub.Dial(hops[relayIdx].relayName, hops[relayIdx].addr, hops[relayIdx].device, next)
		if err != nil {
			return nil, nil, fmt.Errorf("hop %d (relay %s): %w", relayIdx+1, relayDisplay(hops[relayIdx]), err)
		}
		conn = &countingConn{Conn: raw, in: &rec.bytesUpIn, out: &rec.bytesUpOut}
		first = relayIdx + 1
	} else {
		raw, err := net.DialTimeout("tcp", hops[0].addr, dialTimeout)
		if err != nil {
			return nil, nil, fmt.Errorf("hop 1 (%s): %w", hops[0].addr, err)
		}
		conn = &countingConn{Conn: raw, in: &rec.bytesUpIn, out: &rec.bytesUpOut}
	}
	br := bufio.NewReader(conn)

	var err error
	for i := first; i < len(hops); i++ {
		hop := hops[i]
		next := target
		if i+1 < len(hops) {
			next = hops[i+1].addr
		}
		rec.event(fmt.Sprintf("hop %d/%d %s://%s -> %s", i+1, len(hops), hop.scheme, hop.addr, next))
		switch hop.scheme {
		case "socks5":
			err = socks5Connect(conn, br, hop.user, hop.password, next)
		case "relay":
			err = errors.New("a relay hop cannot be traversed through a proxy")
		case "pac":
			err = errors.New("a PAC hop cannot be traversed through a proxy")
		case "dynamic":
			err = errors.New("unresolved dynamic hop")
		default:
			err = httpConnect(conn, br, hop.user, hop.password, next, rec)
		}
		if err != nil {
			conn.Close()
			return nil, nil, fmt.Errorf("hop %d (%s): %w", i+1, hop.addr, err)
		}
	}
	return conn, br, nil
}

// bufConn makes reads go through the buffered reader that may hold bytes
// read ahead during the handshakes.
type bufConn struct {
	net.Conn
	br *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.br.Read(p) }

func (c *bufConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// hasRelayHop reports whether the route goes through a relay contact.
func (p *ProxyRoute) hasRelayHop() bool {
	for _, h := range p.chain {
		if h.scheme == "relay" {
			return true
		}
	}
	return false
}

// routeToRelay returns the route to use for the connection to the relay server
// itself: the chain is cut at the first relay hop, since the relay cannot be
// used to reach itself (it is not connected yet). The hops before the relay
// are used to reach the relay server; if the relay is the first hop, the
// connection becomes direct. Routes without a relay hop are returned as-is.
func (p *ProxyRoute) routeToRelay() *ProxyRoute {
	idx := -1
	for i, h := range p.chain {
		if h.scheme == "relay" {
			idx = i
			break
		}
	}
	if idx < 0 {
		return p
	}
	if idx == 0 {
		return &ProxyRoute{name: "Direct"}
	}
	out := &ProxyRoute{name: p.name, cred: p.cred}
	out.chain = append([]*chainHop{}, p.chain[:idx]...)
	if idx <= len(p.hops) {
		out.hops = append([]ConfigHop{}, p.hops[:idx]...)
	}
	return out
}

// newChainTransport returns a transport for plain HTTP requests: each new
// connection is a tunnel through the whole chain to the origin server, and
// requests are sent in origin form (no proxy involved from the transport's view).
// Callers must hold p.mu.
func (p *ProxyRoute) newChainTransport() *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			target := addr
			if ip := resolveHost(host); ip != "" {
				target = net.JoinHostPort(ip, port)
			}
			rec := connReg.newConn("transport", "", host, target, chainLabel(p.chain), p.name, p.cred, "", "")
			conn, br, err := dialChain(p, target, host, rec)
			if err != nil {
				rec.setError(err.Error())
				rec.finish(StateFailed)
				return nil, err
			}
			activeConns.add(conn)
			rec.setState(StateEstablished)
			tc := &trackedConn{
				Conn: &bufConn{Conn: conn, br: br},
				remove: func() {
					activeConns.remove(conn)
					rec.finish(StateClosed)
				},
			}
			rec.setCloseFn(func() { tc.Close() })
			return tc, nil
		},
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
	}
}

// socks5Connect asks a SOCKS5 server (RFC 1928, user/pass auth per RFC 1929)
// to connect to target over an already open connection.
func socks5Connect(conn net.Conn, br *bufio.Reader, user, password, target string) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return fmt.Errorf("invalid port %q", portStr)
	}

	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	defer conn.SetDeadline(time.Time{})

	methods := []byte{0x00}
	if user != "" {
		methods = []byte{0x00, 0x02}
	}
	if _, err := conn.Write(append([]byte{0x05, byte(len(methods))}, methods...)); err != nil {
		return err
	}
	var sel [2]byte
	if _, err := io.ReadFull(br, sel[:]); err != nil {
		return err
	}
	if sel[0] != 0x05 {
		return errors.New("not a SOCKS5 server")
	}
	switch sel[1] {
	case 0x00:
	case 0x02:
		if len(user) > 255 || len(password) > 255 {
			return errors.New("SOCKS5 credentials too long")
		}
		msg := append([]byte{0x01, byte(len(user))}, user...)
		msg = append(msg, byte(len(password)))
		msg = append(msg, password...)
		if _, err := conn.Write(msg); err != nil {
			return err
		}
		var st [2]byte
		if _, err := io.ReadFull(br, st[:]); err != nil {
			return err
		}
		if st[1] != 0x00 {
			return errors.New("SOCKS5 authentication failed")
		}
	default:
		return errors.New("SOCKS5 server accepts no supported authentication method")
	}

	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(append(req, 0x01), ip4...)
		} else {
			req = append(append(req, 0x04), ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return errors.New("hostname too long")
		}
		req = append(append(req, 0x03, byte(len(host))), host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return err
	}

	var head [4]byte
	if _, err := io.ReadFull(br, head[:]); err != nil {
		return err
	}
	if head[1] != 0x00 {
		return fmt.Errorf("SOCKS5 connect failed (code %d)", head[1])
	}
	var skip int
	switch head[3] {
	case 0x01:
		skip = 4 + 2
	case 0x04:
		skip = 16 + 2
	case 0x03:
		l, err := br.ReadByte()
		if err != nil {
			return err
		}
		skip = int(l) + 2
	default:
		return errors.New("SOCKS5: bad address type in reply")
	}
	_, err = io.CopyN(io.Discard, br, int64(skip))
	return err
}
