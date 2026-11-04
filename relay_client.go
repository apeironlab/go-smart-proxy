package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hashicorp/yamux"

	"proxy/relay"
)

const (
	relayStateFile     = "relay_state.json"
	relayApprovalWait  = 60 * time.Second
	relayDialReplyWait = 100 * time.Second
	relayNoticeTTL     = 15 * time.Second
	// A contact can open any number of streams: cap the approvals waiting for
	// an answer so they cannot flood the user with prompts or pile up
	// goroutines.
	relayMaxPending        = 20
	relayMaxPendingPerFrom = 5
)

// relayRule remembers a route (contact + device + destination) that was approved.
type relayRule struct {
	ID         int64  `json:"id"`
	From       string `json:"from"`
	FromDevice string `json:"fromDevice,omitempty"`
	Host       string `json:"host"`
	Port       int    `json:"port"` // 0 = any port
}

type relayDecision struct {
	Allow   bool `json:"allow"`
	Always  bool `json:"always"`
	AnyPort bool `json:"anyPort"`
}

// relayApproval is a route requested by a contact that waits for our answer.
type relayApproval struct {
	ID         int64     `json:"id"`
	From       string    `json:"from"`
	FromDevice string    `json:"fromDevice,omitempty"`
	Host       string    `json:"host"`
	Port       int       `json:"port"`
	Time       time.Time `json:"time"`
	ch         chan relayDecision
}

type relayPersisted struct {
	Rules  []relayRule `json:"rules"`
	NextID int64       `json:"nextId"`
	State  relay.State `json:"state"` // last known address book, shown while offline
}

// relayClient keeps the connection to the relay, the address book and the
// approvals for routes requested by contacts.
type relayClient struct {
	mu        sync.Mutex
	cfg       *RelayConfig
	sess      *yamux.Session
	ctrl      net.Conn
	connected bool
	started   bool
	lastErr   string
	route     string
	device    string
	email     string
	state     relay.State
	notice    string
	noticeAt  time.Time
	approvals map[int64]*relayApproval
	rules     []relayRule
	nextID    int64
	sendMu    sync.Mutex
	file      string // persisted state, relayStateFile by default
}

var relayMgr = &relayClient{approvals: map[int64]*relayApproval{}}

// Start connects to the relay in the background, if one is configured.
func (r *relayClient) Start() {
	r.start(configuration.Relay)
}

func (r *relayClient) start(cfg *RelayConfig) {
	if cfg == nil || cfg.Address == "" {
		return
	}
	r.mu.Lock()
	r.cfg = cfg
	r.device = cfg.Device
	started := r.started
	r.started = true
	sess := r.sess
	r.mu.Unlock()
	if sess != nil {
		sess.Close()
	}
	if !started {
		r.loadFile()
		go r.loop()
	}
}

func (r *relayClient) stateFile() string {
	if r.file != "" {
		return r.file
	}
	return relayStateFile
}

func (r *relayClient) loadFile() {
	b, err := os.ReadFile(r.stateFile())
	if err != nil {
		return
	}
	var p relayPersisted
	if json.Unmarshal(b, &p) != nil {
		return
	}
	r.mu.Lock()
	r.rules, r.nextID, r.state = p.Rules, p.NextID, p.State
	for i := range r.state.Contacts {
		r.state.Contacts[i].Online = false
		r.state.Contacts[i].Devices = nil
	}
	for i := range r.state.MyDevices {
		r.state.MyDevices[i].Online = false
	}
	for i := range r.rules {
		// Rules saved before per-device approvals apply to the legacy "default"
		// device used by older clients.
		if r.rules[i].FromDevice == "" {
			r.rules[i].FromDevice = "default"
		}
	}
	r.mu.Unlock()
}

func (r *relayClient) saveLocked() {
	b, _ := json.MarshalIndent(relayPersisted{Rules: r.rules, NextID: r.nextID, State: r.state}, "", "  ")
	relay.WriteFileAtomic(r.stateFile(), b, 0o600)
}

func (r *relayClient) loop() {
	backoff := 2 * time.Second
	for {
		started := time.Now()
		err := r.connectOnce()
		r.mu.Lock()
		r.connected, r.sess, r.ctrl = false, nil, nil
		if err != nil {
			r.lastErr = err.Error()
		}
		for id, a := range r.approvals {
			a.ch <- relayDecision{}
			delete(r.approvals, id)
		}
		r.mu.Unlock()
		if err != nil {
			log.Printf("relay: %v", err)
		}
		if time.Since(started) > 30*time.Second {
			backoff = 2 * time.Second
		}
		time.Sleep(backoff)
		if backoff < time.Minute {
			backoff *= 2
		}
	}
}

// relayRoute picks the route used to reach the relay: the one named in the
// configuration, or the first applicable one. Following its chain, the route is
// cut at the first relay hop: the relay must not be used to reach itself (it is
// not connected yet), so only the hops before it are used, and the connection
// is direct when the relay hop is the first one.
func (r *relayClient) relayRoute() (*ProxyRoute, error) {
	var route *ProxyRoute
	if r.cfg.Route != "" {
		for _, rt := range getRoutes() {
			if rt.name == r.cfg.Route {
				route = rt
				break
			}
		}
		if route == nil {
			return nil, fmt.Errorf("Relay.Route %q does not exist", r.cfg.Route)
		}
	} else {
		// Rules-only routes are not selected automatically, unless their chain
		// contains a relay hop: for the relay connection only the hops before
		// the relay are used, so they cannot carry generic traffic.
		route = getApplicableRoute(func(rt *ProxyRoute) bool {
			return rt.rulesOnly && !rt.hasRelayHop()
		})
	}
	if route == nil {
		return nil, errors.New("no route available")
	}
	// The relay connection is not selected by a destination rule: the chain
	// stops at the first RulesOnly hop, then at the relay hop.
	return route.autoRoute().routeToRelay(), nil
}

func (r *relayClient) connectOnce() error {
	r.mu.Lock()
	cfg := r.cfg
	r.mu.Unlock()
	if cfg == nil {
		return errors.New("relay not configured")
	}
	cert, err := relayCertificate(cfg)
	if err != nil {
		return fmt.Errorf("client certificate: %w", err)
	}
	if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
		if email, ok := relay.EmailFromCert(leaf); ok {
			r.mu.Lock()
			r.email = email
			r.mu.Unlock()
		}
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if cfg.CAPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(cfg.CAPEM)) {
			return errors.New("relay CA: no certificates found")
		}
		tlsCfg.RootCAs = pool
	} else if cfg.CA != "" {
		pool, err := relay.LoadPool(cfg.CA)
		if err != nil {
			return fmt.Errorf("relay CA: %w", err)
		}
		tlsCfg.RootCAs = pool
	}

	addr := cfg.Address
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		addr = net.JoinHostPort(addr, "8443")
	}
	tlsCfg.ServerName = host

	route, err := r.relayRoute()
	if err != nil {
		return err
	}
	rec := connReg.newConn("relay", "", host, addr, "", route.name, route.cred, "", "")
	rec.event("connecting to relay " + addr)
	raw, err := dialViaRoute(route, addr, rec)
	if err != nil {
		rec.setError(err.Error())
		rec.finish(StateFailed)
		return fmt.Errorf("connect to %s via route %q: %w", addr, route.name, err)
	}
	tc := tls.Client(raw, tlsCfg)
	raw.SetDeadline(time.Now().Add(30 * time.Second))
	if err := tc.Handshake(); err != nil {
		raw.Close()
		rec.setError(err.Error())
		rec.finish(StateFailed)
		return fmt.Errorf("TLS handshake with relay: %w", err)
	}
	raw.SetDeadline(time.Time{})

	ycfg := yamux.DefaultConfig()
	ycfg.LogOutput = discardWriter{}
	sess, err := yamux.Client(tc, ycfg)
	if err != nil {
		raw.Close()
		rec.finish(StateFailed)
		return err
	}
	defer func() {
		sess.Close()
		rec.finish(StateClosed)
	}()
	ctrl, err := sess.OpenStream()
	if err != nil {
		return err
	}
	r.mu.Lock()
	device := r.device
	r.mu.Unlock()
	if err := relay.WriteLine(ctrl, relay.DialReq{T: relay.TControl, Device: device}); err != nil {
		return err
	}

	rec.setState(StateEstablished)
	rec.event("relay session established")
	rec.setCloseFn(func() { sess.Close() })

	r.mu.Lock()
	r.sess, r.ctrl, r.connected, r.lastErr, r.route = sess, ctrl, true, "", route.name
	r.mu.Unlock()
	log.Printf("relay: connected to %s via route %q", addr, route.name)

	go r.readState(ctrl, sess)
	go func() { // reconnect when the network (and so the selected route) changes
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-sess.CloseChan():
				return
			case <-t.C:
				if cur, err := r.relayRoute(); err != nil || cur.name != route.name {
					log.Printf("relay: route changed, reconnecting")
					sess.Close()
					return
				}
			}
		}
	}()

	for {
		st, err := sess.AcceptStream()
		if err != nil {
			return err
		}
		go r.handleIncoming(st)
	}
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func (r *relayClient) readState(ctrl net.Conn, sess *yamux.Session) {
	br := relay.NewReader(ctrl)
	for {
		var st relay.State
		if err := relay.ReadLine(br, &st); err != nil {
			sess.Close()
			return
		}
		var freshIncoming []string
		r.mu.Lock()
		if st.Notice != "" {
			r.notice, r.noticeAt = st.Notice, time.Now()
		}
		for _, e := range st.Incoming {
			seen := false
			for _, old := range r.state.Incoming {
				if old == e {
					seen = true
					break
				}
			}
			if !seen {
				freshIncoming = append(freshIncoming, e)
			}
		}
		r.state = st
		r.dropRulesOfRemovedContactsLocked()
		r.saveLocked()
		r.mu.Unlock()

		if len(freshIncoming) > 0 {
			// Contact requests are shown in the web UI (banner and Relay page).
			// They do not raise a desktop notification: a stale request on a
			// relay would otherwise keep re-notifying on every reconnect.
			log.Printf("relay: contact request from %s (open the Relay page)", strings.Join(freshIncoming, ", "))
		}
	}
}

func (r *relayClient) dropRulesOfRemovedContactsLocked() {
	known := map[string]bool{}
	for _, c := range r.state.Contacts {
		known[c.Email] = true
	}
	kept := r.rules[:0]
	for _, rule := range r.rules {
		if known[rule.From] {
			kept = append(kept, rule)
		}
	}
	r.rules = kept
}

func (r *relayClient) send(m relay.ClientMsg) error {
	r.mu.Lock()
	ctrl := r.ctrl
	r.mu.Unlock()
	if ctrl == nil {
		return errors.New("not connected to the relay")
	}
	r.sendMu.Lock()
	defer r.sendMu.Unlock()
	ctrl.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return relay.WriteLine(ctrl, m)
}

// SetDevice changes the device code of this installation and reconnects so the
// relay registers the session under the new code.
func (r *relayClient) SetDevice(device string) {
	r.mu.Lock()
	r.device = device
	sess := r.sess
	r.mu.Unlock()
	if sess != nil {
		sess.Close()
	}
}

// Dial opens a connection to target through the network of contact email. An
// empty device means any online device of that contact.
func (r *relayClient) Dial(email, device, target string) (net.Conn, error) {
	r.mu.Lock()
	sess := r.sess
	r.mu.Unlock()
	if sess == nil {
		return nil, errors.New("not connected to the relay")
	}
	st, err := sess.OpenStream()
	if err != nil {
		return nil, err
	}
	if err := relay.WriteLine(st, relay.DialReq{T: relay.TDial, Via: email, ViaDevice: device, Target: target}); err != nil {
		st.Close()
		return nil, err
	}
	br := relay.NewReader(st)
	st.SetReadDeadline(time.Now().Add(relayDialReplyWait))
	var resp relay.DialResp
	if err := relay.ReadLine(br, &resp); err != nil {
		st.Close()
		return nil, err
	}
	st.SetReadDeadline(time.Time{})
	if !resp.OK {
		st.Close()
		if resp.Error == "" {
			resp.Error = "refused"
		}
		return nil, errors.New(resp.Error)
	}
	return &bufConn{Conn: st, br: br}, nil
}

// relayPingTimeout bounds how long a probe waits for the answer (a variable so
// tests can shorten it).
var relayPingTimeout = 8 * time.Second

// Ping measures the round trip to the relay (email empty) or, through the
// relay, to a device of a contact (or of the user). It crosses the same path a
// real connection would, but opens nothing on the other side.
func (r *relayClient) Ping(email, device string) (time.Duration, error) {
	r.mu.Lock()
	sess := r.sess
	r.mu.Unlock()
	if sess == nil {
		return 0, errors.New("not connected to the relay")
	}
	st, err := sess.OpenStream()
	if err != nil {
		return 0, err
	}
	defer st.Close()
	start := time.Now()
	if err := relay.WriteLine(st, relay.DialReq{T: relay.TPing, Via: email, ViaDevice: device}); err != nil {
		return 0, err
	}
	st.SetReadDeadline(time.Now().Add(relayPingTimeout))
	var resp relay.DialResp
	if err := relay.ReadLine(relay.NewReader(st), &resp); err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return 0, errors.New("no answer in time")
		}
		return 0, err
	}
	rtt := time.Since(start)
	if !resp.OK {
		if resp.Error == "" {
			resp.Error = "refused"
		}
		return 0, errors.New(resp.Error)
	}
	return rtt, nil
}

// handleIncoming serves a contact that asked us to open a connection for it.
func (r *relayClient) handleIncoming(st net.Conn) {
	defer st.Close()
	br := relay.NewReader(st)
	var req relay.DialReq
	if err := relay.ReadLine(br, &req); err != nil || (req.T != relay.TDial && req.T != relay.TPing) {
		return
	}
	deny := func(msg string) { relay.WriteLine(st, relay.DialResp{Error: msg}) }
	if req.T == relay.TPing {
		// A reachability probe: it carries no destination, opens nothing and
		// needs no approval. Only the user's own devices and contacts get an
		// answer.
		from, ok := relay.NormalizeEmail(req.From)
		r.mu.Lock()
		self := r.email
		r.mu.Unlock()
		if !ok || (from != self && !r.isContact(from)) {
			deny("not a contact")
			return
		}
		relay.WriteLine(st, relay.DialResp{OK: true})
		return
	}

	from, ok := relay.NormalizeEmail(req.From)
	if !ok {
		deny("invalid identity")
		return
	}
	r.mu.Lock()
	self := r.email
	r.mu.Unlock()
	if from != self && !r.isContact(from) {
		deny("not a contact")
		return
	}
	host, portStr, err := net.SplitHostPort(req.Target)
	port, perr := strconv.Atoi(portStr)
	if err != nil || perr != nil || port <= 0 || port > 65535 || host == "" {
		deny("invalid target")
		return
	}
	if !r.authorize(from, req.FromDevice, strings.ToLower(host), port) {
		log.Printf("relay: %s -> %s refused", from, req.Target)
		deny("route not approved")
		return
	}

	target := req.Target
	if ip := resolveHost(host); ip != "" {
		target = net.JoinHostPort(ip, portStr)
	}
	d := net.Dialer{Timeout: dialTimeout, Control: r.guard}
	conn, err := d.Dial("tcp", target)
	if err != nil {
		deny(err.Error())
		return
	}
	rec := connReg.newConn("relay-exit", from, host, target, "", "relay", "", "", "")
	rec.setState(StateEstablished)
	rec.event("opened for " + from)
	rec.setCloseFn(func() { conn.Close(); st.Close() })
	defer rec.finish(StateClosed)
	if err := relay.WriteLine(st, relay.DialResp{OK: true}); err != nil {
		conn.Close()
		return
	}
	cc := &countingConn{Conn: conn, in: &rec.bytesUpIn, out: &rec.bytesUpOut}
	log.Printf("relay: %s -> %s", from, target)
	relay.Pipe(st, br, cc, bufio.NewReader(cc))
}

// guard stops contacts from reaching services bound to this machine
// (including the proxy itself and its web UI) unless explicitly allowed.
func (r *relayClient) guard(network, address string, _ syscall.RawConn) error {
	if r.cfg != nil && r.cfg.AllowLocal {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return errors.New("destination not allowed")
	}
	return nil
}

func (r *relayClient) isContact(email string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.state.Contacts {
		if c.Email == email {
			return true
		}
	}
	return false
}

func deviceSuffix(device string) string {
	if device == "" {
		return ""
	}
	return "/" + device
}

// authorize returns true when the route is already approved, otherwise it
// asks the user (through the web UI) and waits for the answer.
func (r *relayClient) ruleAllowsLocked(from, fromDevice, host string, port int) bool {
	for _, rule := range r.rules {
		if rule.From == from && rule.FromDevice == fromDevice && rule.Host == host && (rule.Port == 0 || rule.Port == port) {
			return true
		}
	}
	return false
}

func (r *relayClient) authorize(from, fromDevice, host string, port int) bool {
	r.mu.Lock()
	if r.ruleAllowsLocked(from, fromDevice, host, port) {
		r.mu.Unlock()
		return true
	}
	pending, pendingFrom := len(r.approvals), 0
	for _, p := range r.approvals {
		if p.From == from {
			pendingFrom++
		}
	}
	if pending >= relayMaxPending || pendingFrom >= relayMaxPendingPerFrom {
		r.mu.Unlock()
		log.Printf("relay: too many pending approvals (%d total, %d from %s): refusing %s:%d", pending, pendingFrom, from, host, port)
		return false
	}
	r.nextID++
	a := &relayApproval{ID: r.nextID, From: from, FromDevice: fromDevice, Host: host, Port: port, Time: time.Now(), ch: make(chan relayDecision, 1)}
	r.approvals[a.ID] = a
	r.mu.Unlock()
	log.Printf("relay: waiting for approval of %s/%s -> %s:%d", from, fromDevice, host, port)
	notifyDesktop("Richiesta di rotta", fmt.Sprintf("%s%s vuole raggiungere %s:%d", from, deviceSuffix(fromDevice), host, port))

	var dec relayDecision
	select {
	case dec = <-a.ch:
	case <-time.After(relayApprovalWait):
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.approvals, a.ID)
	if dec.Allow && dec.Always {
		rule := relayRule{ID: a.ID, From: from, FromDevice: a.FromDevice, Host: host, Port: port}
		if dec.AnyPort {
			rule.Port = 0
		}
		r.rules = append(r.rules, rule)
		r.saveLocked()
	}
	return dec.Allow
}

// Decide answers a pending approval.
func (r *relayClient) Decide(id int64, dec relayDecision) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.approvals[id]
	if !ok {
		return false
	}
	select {
	case a.ch <- dec:
	default:
	}
	return true
}

func (r *relayClient) RemoveRule(id int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	kept := r.rules[:0]
	for _, rule := range r.rules {
		if rule.ID != id {
			kept = append(kept, rule)
		}
	}
	r.rules = kept
	r.saveLocked()
}

type relayStatusJSON struct {
	Enabled   bool               `json:"enabled"`
	Connected bool               `json:"connected"`
	Address   string             `json:"address"`
	Route     string             `json:"route"`
	Email     string             `json:"email"`
	Device    string             `json:"device"`
	EnrollURL string             `json:"enrollUrl,omitempty"`
	Error     string             `json:"error,omitempty"`
	Notice    string             `json:"notice,omitempty"`
	Contacts  []relay.Contact    `json:"contacts"`
	MyDevices []relay.DeviceInfo `json:"myDevices"`
	Incoming  []string           `json:"incoming"`
	Outgoing  []string           `json:"outgoing"`
	Approvals []*relayApproval   `json:"approvals"`
	Rules     []relayRule        `json:"rules"`
}

func (r *relayClient) Status() relayStatusJSON {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := relayStatusJSON{
		Enabled:   r.cfg != nil,
		Connected: r.connected,
		Route:     r.route,
		Email:     r.state.Email,
		Error:     r.lastErr,
		Contacts:  append([]relay.Contact{}, r.state.Contacts...),
		MyDevices: append([]relay.DeviceInfo{}, r.state.MyDevices...),
		Incoming:  append([]string{}, r.state.Incoming...),
		Outgoing:  append([]string{}, r.state.Outgoing...),
		Approvals: []*relayApproval{},
		Rules:     append([]relayRule{}, r.rules...),
	}
	if r.cfg != nil {
		st.Address = r.cfg.Address
		st.EnrollURL = r.cfg.EnrollURL
	}
	st.Device = r.device
	if time.Since(r.noticeAt) < relayNoticeTTL {
		st.Notice = r.notice
	}
	for _, a := range r.approvals {
		st.Approvals = append(st.Approvals, a)
	}
	return st
}

// dialViaRoute opens a TCP connection to addr using the given route: directly,
// through its proxy, or through its whole chain.
func dialViaRoute(route *ProxyRoute, addr string, rec *ConnInfo) (net.Conn, error) {
	proxy := route.FindProxy("https://" + addr + "/")
	if proxy.Type == "DIRECT" {
		c, err := net.DialTimeout("tcp", addr, dialTimeout)
		if err != nil {
			return nil, err
		}
		return &countingConn{Conn: c, in: &rec.bytesUpIn, out: &rec.bytesUpOut}, nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	conn, br, err := dialProxyAndConnect(route, proxy, addr, host, rec)
	if err != nil {
		return nil, err
	}
	return &bufConn{Conn: conn, br: br}, nil
}
