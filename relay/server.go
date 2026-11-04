package relay

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"
)

const (
	dialReplyTimeout = 90 * time.Second // the contact may have to approve the route
	firstLineTimeout = 15 * time.Second
)

// Server is the relay.
type Server struct {
	Store *Store
	Log   *log.Logger
	// Revoked, when set, is consulted after the TLS handshake: connections
	// whose client certificate it rejects are closed.
	Revoked *Revocations
	// Audit, when set, is told about connections and refusals (the admin
	// interface keeps them in its event log).
	Audit func(kind, actor, subject, detail string)
	// Catalog lists the applications users can open through gateways. nil
	// means the relay serves no applications.
	Catalog *Catalog
	// Renewer, when set, issues a new certificate for a connected device that
	// asks for one (see EnrollServer.RenewCertificate). nil refuses renewals.
	Renewer func(c RenewContext, csrPEM []byte) (certPEM string, err error)
	// Policy lists what the relay refuses to connect to and tells proxies to
	// block. nil means nothing is blocked.
	Policy *Policy

	mu       sync.Mutex
	sessions map[string]*session
	gateways map[string]*session // application gateways by id
	serving  atomic.Bool

	// Shared and peers are set when several relays share a database (SetShared).
	Shared   *Shared
	peers    *peerState
	onShared []func()
}

// Serving reports whether Serve is accepting connections.
func (s *Server) Serving() bool { return s.serving.Load() }

type session struct {
	email  string
	device string
	ys     *yamux.Session
	mu     sync.Mutex
	ctrl   net.Conn
	ctx    *NetContext   // what this device shares about its network, nil = nothing
	ready  chan struct{} // closed once the control stream has registered the device
	serial string        // serial number (hex) of the client certificate
	// certDevice is the device the certificate is bound to ("" if none);
	// notBefore and notAfter are its validity.
	certDevice          string
	notBefore, notAfter time.Time
	addr                string
	since               time.Time
}

// SetAudit sets Audit while the server may already be running.
func (s *Server) SetAudit(fn func(kind, actor, subject, detail string)) {
	s.mu.Lock()
	s.Audit = fn
	s.mu.Unlock()
}

func (s *Server) audit(kind, actor, subject, detail string) {
	emitEvent(kind, actor, subject, detail)
	s.mu.Lock()
	fn := s.Audit
	s.mu.Unlock()
	if fn != nil {
		fn(kind, actor, subject, detail)
	}
}

// OnlineDevice describes a connected device.
type OnlineDevice struct {
	Email   string      `json:"email"`
	Device  string      `json:"device"`
	Addr    string      `json:"addr"`
	Serial  string      `json:"serial"`
	Since   time.Time   `json:"since"`
	Context *NetContext `json:"context,omitempty"`
	// Replica is the relay the device is connected to (empty: this one).
	Replica string `json:"replica,omitempty"`
}

// Online lists the devices that are connected now, on every relay sharing the
// database.
func (s *Server) Online() []OnlineDevice {
	s.mu.Lock()
	all := make([]*session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		all = append(all, sess)
	}
	s.mu.Unlock()
	out := make([]OnlineDevice, 0, len(all))
	for _, sess := range all {
		sess.mu.Lock()
		out = append(out, OnlineDevice{Email: sess.email, Device: sess.device, Addr: sess.addr, Serial: sess.serial, Since: sess.since, Context: sess.ctx})
		sess.mu.Unlock()
	}
	for _, d := range s.remoteAll() {
		_, devAddr := splitRemoteAddr(d.Addr)
		out = append(out, OnlineDevice{Email: d.Email, Device: d.Device, Addr: devAddr, Serial: d.Serial, Since: d.Since, Context: d.Ctx, Replica: d.Replica})
	}
	return out
}

// Kick closes the connections of a user (all of them when serial is empty,
// else only those using that certificate) and returns how many it closed.
func (s *Server) Kick(email, serial string) int {
	s.mu.Lock()
	var hit []*session
	for _, sess := range s.sessions {
		if sess.email == email && (serial == "" || sess.serial == serial) {
			hit = append(hit, sess)
		}
	}
	s.mu.Unlock()
	for _, sess := range hit {
		sess.ys.Close()
	}
	if sh := s.sharedDB(); sh != nil { // the other relays close theirs
		sh.db.Exec(`INSERT INTO kicks(email, device, serial, before_ts, ts) VALUES(?,?,?,?,?)`, email, "", serial, 0, nowUnix())
	}
	return len(hit)
}

// NewServer returns a relay server that keeps its address book in store. Call
// Serve with a TLS listener to run it.
func NewServer(store *Store) *Server {
	return &Server{Store: store, Log: log.Default(), sessions: map[string]*session{}, gateways: map[string]*session{}}
}

// TLSConfig builds the server TLS configuration: clients must present a
// certificate signed by the CA.
func TLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	pool, err := LoadPool(caFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// Serve accepts connections on ln (already wrapped with TLS) until it fails.
func (s *Server) Serve(ln net.Listener) error {
	s.serving.Store(true)
	defer s.serving.Store(false)
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleConn(c)
	}
}

func (s *Server) handleConn(c net.Conn) {
	tc, ok := c.(*tls.Conn)
	if !ok {
		c.Close()
		return
	}
	c.SetDeadline(time.Now().Add(firstLineTimeout))
	if err := tc.Handshake(); err != nil {
		CounterInc("gsp_relay_connections_total", "result", "handshake_failed")
		s.Log.Printf("handshake from %s failed: %v", c.RemoteAddr(), err)
		c.Close()
		return
	}
	c.SetDeadline(time.Time{})
	peers := tc.ConnectionState().PeerCertificates
	if len(peers) == 0 {
		c.Close()
		return
	}
	if s.Revoked.Revoked(peers[0]) {
		CounterInc("gsp_relay_connections_total", "result", "revoked")
		s.Log.Printf("revoked certificate from %s refused", c.RemoteAddr())
		if e, ok := EmailFromCert(peers[0]); ok {
			s.audit("session.refused", e, "", "revoked certificate from "+c.RemoteAddr().String())
		}
		c.Close()
		return
	}
	if rid, isReplica := ReplicaFromCert(peers[0]); isReplica {
		if s.sharedDB() == nil {
			s.Log.Printf("a relay certificate (%s) from %s, but this relay is not shared: refused", rid, c.RemoteAddr())
			c.Close()
			return
		}
		s.handlePeerConn(c, rid)
		return
	}
	if gid, isGateway := GatewayFromCert(peers[0]); isGateway {
		s.handleGatewayConn(c, peers[0], gid)
		return
	}
	email, ok := EmailFromCert(peers[0])
	if !ok {
		s.Log.Printf("certificate from %s has no e-mail identity", c.RemoteAddr())
		c.Close()
		return
	}

	cfg := yamux.DefaultConfig()
	cfg.LogOutput = discard{}
	ys, err := yamux.Server(c, cfg)
	if err != nil {
		c.Close()
		return
	}
	sess := &session{email: email, ys: ys, ready: make(chan struct{}), addr: c.RemoteAddr().String(), since: time.Now()}
	if peers[0].SerialNumber != nil {
		sess.serial = strings.ToLower(peers[0].SerialNumber.Text(16))
	}
	sess.certDevice = DeviceFromCert(peers[0])
	sess.notBefore, sess.notAfter = peers[0].NotBefore, peers[0].NotAfter
	defer func() {
		ys.Close()
		s.unregister(sess)
	}()

	for {
		st, err := ys.AcceptStream()
		if err != nil {
			return
		}
		go s.handleStream(sess, st)
	}
}

// unregister removes the session from the registry (if it was registered) and
// notifies its contacts that the device went offline.
func (s *Server) unregister(sess *session) {
	s.mu.Lock()
	removed := false
	for key, cur := range s.sessions {
		if cur == sess {
			delete(s.sessions, key)
			removed = true
		}
	}
	s.mu.Unlock()
	if !removed {
		return
	}
	sess.mu.Lock()
	email, device := sess.email, sess.device
	sess.mu.Unlock()
	s.presenceDel(email, device)
	s.Log.Printf("%s/%s disconnected", email, device)
	s.audit("session.close", email, device, "")
	s.Store.Seen(email, time.Now())
	s.notifyPresence(email)
	s.pushState(email, "")
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func sessionKey(email, device string) string { return email + "\x00" + device }

// onlineDevices returns the sorted online device codes of a user.
func (s *Server) onlineDevices(email string) []string {
	s.mu.Lock()
	var out []string
	seen := map[string]bool{}
	for _, sess := range s.sessions {
		if sess.email == email && sess.device != "" {
			out = append(out, sess.device)
			seen[sess.device] = true
		}
	}
	s.mu.Unlock()
	for _, d := range s.remoteDevices(email) {
		if d.Device != "" && !seen[d.Device] {
			out = append(out, d.Device)
			seen[d.Device] = true
		}
	}
	sort.Strings(out)
	return out
}

// deviceContexts returns the network context shared by each online device of
// email, by device code. Devices that share nothing are left out.
func (s *Server) deviceContexts(email string) map[string]NetContext {
	var out map[string]NetContext
	for _, d := range s.remoteDevices(email) {
		if d.Device == "" || d.Ctx == nil {
			continue
		}
		if out == nil {
			out = map[string]NetContext{}
		}
		out[d.Device] = *d.Ctx
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sess := range s.sessions {
		if sess.email != email || sess.device == "" {
			continue
		}
		sess.mu.Lock()
		c := sess.ctx
		sess.mu.Unlock()
		if c == nil {
			continue
		}
		if out == nil {
			out = map[string]NetContext{}
		}
		out[sess.device] = *c
	}
	return out
}

// peer returns the online session of a contact. An empty device means "any":
// it works only when a single device is online, so a multi-device user is never
// routed by chance.
func (s *Server) peer(email, device string) (*session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if device != "" {
		if sess := s.sessions[sessionKey(email, device)]; sess != nil {
			return sess, nil
		}
		return nil, fmt.Errorf("%s/%s is offline", email, device)
	}
	var found []*session
	for _, sess := range s.sessions {
		if sess.email == email {
			found = append(found, sess)
		}
	}
	switch len(found) {
	case 0:
		return nil, fmt.Errorf("%s is offline", email)
	case 1:
		return found[0], nil
	default:
		return nil, fmt.Errorf("%s has multiple devices online: select one (relay://%s/device)", email, email)
	}
}

// pushState sends the current snapshot to every device of email.
func (s *Server) pushState(email, notice string) {
	s.pushStateDevice(email, "", notice)
}

// pushStateDevice sends the current snapshot to one device of email, or to all
// of them when device is empty.
func (s *Server) pushStateDevice(email, device, notice string) {
	s.mu.Lock()
	var targets []*session
	for _, sess := range s.sessions {
		if sess.email == email && (device == "" || sess.device == device) {
			targets = append(targets, sess)
		}
	}
	s.mu.Unlock()
	if len(targets) == 0 {
		return
	}

	contacts, in, out := s.Store.Snapshot(email)
	st := State{T: TState, Email: email, Incoming: in, Outgoing: out, Notice: notice, Apps: s.appsFor(email), Policy: s.Policy.Push()}
	for _, c := range contacts {
		devices := s.onlineDevices(c)
		ct := Contact{Email: c, Online: len(devices) > 0, Devices: devices, Context: s.deviceContexts(c)}
		if !ct.Online {
			ct.LastSeen = s.Store.LastSeen(c)
		}
		st.Contacts = append(st.Contacts, ct)
	}
	ownOnline := map[string]bool{}
	ownCtx := s.deviceContexts(email)
	for _, d := range s.onlineDevices(email) {
		ownOnline[d] = true
	}
	for _, id := range s.Store.Devices(email) {
		di := DeviceInfo{ID: id, Online: ownOnline[id]}
		if c, ok := ownCtx[id]; ok && ownOnline[id] {
			c := c
			di.Context = &c
		}
		st.MyDevices = append(st.MyDevices, di)
	}

	for _, sess := range targets {
		sess.mu.Lock()
		ctrl := sess.ctrl
		if ctrl != nil {
			ctrl.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := WriteLine(ctrl, st); err != nil {
				ctrl.Close()
			}
		}
		sess.mu.Unlock()
	}
}

// notifyPresence tells the contacts of email that its presence changed.
func (s *Server) notifyPresence(email string) {
	contacts, _, _ := s.Store.Snapshot(email)
	for _, c := range contacts {
		s.pushState(c, "")
	}
}

func (s *Server) handleStream(sess *session, st net.Conn) {
	br := NewReader(st)
	st.SetReadDeadline(time.Now().Add(firstLineTimeout))
	var head struct {
		T string `json:"t"`
	}
	line, err := br.ReadSlice('\n')
	if err != nil {
		st.Close()
		return
	}
	st.SetReadDeadline(time.Time{})
	if err := json.Unmarshal(line, &head); err != nil {
		st.Close()
		return
	}
	switch head.T {
	case TControl:
		var req DialReq
		if err := json.Unmarshal(line, &req); err != nil {
			st.Close()
			return
		}
		s.handleControl(sess, st, br, req)
	case TDial:
		var req DialReq
		if err := json.Unmarshal(line, &req); err != nil {
			st.Close()
			return
		}
		s.handleDial(sess, st, br, req)
	case TPing:
		var req DialReq
		if err := json.Unmarshal(line, &req); err != nil {
			st.Close()
			return
		}
		s.handlePing(sess, st, req)
	case TRenew:
		var req RenewReq
		if err := json.Unmarshal(line, &req); err != nil {
			st.Close()
			return
		}
		s.handleRenew(sess, st, req)
	default:
		st.Close()
	}
}

func (s *Server) handleControl(sess *session, st net.Conn, br *bufio.Reader, hello DialReq) {
	device, ok := NormalizeDevice(hello.Device)
	if !ok {
		st.Close()
		return
	}
	if sess.certDevice != "" {
		// The certificate was issued for this device: that is the device,
		// whatever the client claims.
		if device != "" && device != sess.certDevice {
			s.Log.Printf("%s claimed device %q but its certificate is for %q", sess.email, device, sess.certDevice)
		}
		device = sess.certDevice
	}
	if device == "" {
		device = "default" // clients that predate device identities
	}

	sess.mu.Lock()
	if sess.ctrl != nil {
		sess.mu.Unlock()
		st.Close()
		return
	}
	sess.ctrl = st
	sess.device = device
	sess.ctx = SanitizeContext(hello.Context)
	sess.mu.Unlock()

	key := sessionKey(sess.email, device)
	s.mu.Lock()
	old := s.sessions[key]
	s.sessions[key] = sess
	s.mu.Unlock()
	if old != nil && old != sess {
		old.ys.Close() // a newer connection of the same user+device replaces the old one
	}
	close(sess.ready)
	s.presenceSet(sess)
	s.Store.RememberDevice(sess.email, device)
	s.Log.Printf("%s/%s connected", sess.email, device)
	s.audit("session.open", sess.email, device, sess.addr)
	s.pushState(sess.email, "")
	s.notifyPresence(sess.email)

	defer st.Close()

	for {
		var m ClientMsg
		if err := ReadLine(br, &m); err != nil {
			return
		}
		if m.T == TContext {
			// The device changed networks (or what it wants to share): tell
			// it and its contacts.
			sess.mu.Lock()
			sess.ctx = SanitizeContext(m.Context)
			sess.mu.Unlock()
			s.presenceSet(sess)
			s.pushState(sess.email, "")
			s.notifyPresence(sess.email)
			continue
		}
		other, ok := NormalizeEmail(m.Email)
		if !ok {
			s.pushStateDevice(sess.email, sess.device, "invalid e-mail address")
			continue
		}
		var changed []string
		notice := ""
		switch m.T {
		case TContactRequest:
			changed, notice = s.Store.Request(sess.email, other)
		case TContactRespond:
			changed = s.Store.Respond(sess.email, other, m.Accept)
		case TContactRemove:
			changed = s.Store.Remove(sess.email, other)
		default:
			notice = "unknown command"
		}
		if notice != "" {
			s.pushStateDevice(sess.email, sess.device, notice)
		}
		for _, e := range changed {
			if notice != "" && e == sess.email {
				continue
			}
			s.pushState(e, "")
		}
	}
}

// pingTimeout bounds how long a probe waits for the contact's device.
const pingTimeout = 6 * time.Second

// handlePing answers a reachability probe. Without Via it only tests the link
// to the relay; with Via it also crosses to the contact's device and back, so
// the round trip measured by the caller is the one a real connection pays.
// A probe carries no destination and never needs the contact's approval.
func (s *Server) handlePing(sess *session, st net.Conn, req DialReq) {
	defer st.Close()
	reply := func(r DialResp) {
		st.SetWriteDeadline(time.Now().Add(5 * time.Second))
		WriteLine(st, r)
	}
	if strings.TrimSpace(req.Via) == "" {
		reply(DialResp{OK: true})
		return
	}
	select {
	case <-sess.ready:
	case <-time.After(5 * time.Second):
		reply(DialResp{Error: "control stream not ready"})
		return
	}
	sess.mu.Lock()
	fromDevice := sess.device
	sess.mu.Unlock()

	via, ok := NormalizeEmail(req.Via)
	viaDevice, dok := NormalizeDevice(req.ViaDevice)
	if !ok || !dok {
		reply(DialResp{Error: "invalid request"})
		return
	}
	if via != sess.email && !s.Store.IsContact(sess.email, via) {
		reply(DialResp{Error: via + " is not in your contacts"})
		return
	}
	loc, err := s.locate(via, viaDevice)
	if err != nil {
		reply(DialResp{Error: err.Error()})
		return
	}
	if loc.sess == sess {
		reply(DialResp{Error: "this is the device you are using"})
		return
	}
	inner := DialReq{T: TPing, From: sess.email, FromDevice: fromDevice}
	var ps net.Conn
	if loc.remote != nil { // on another relay
		if ps, err = s.openRemote(loc.remote, kindPing, inner); err != nil {
			reply(DialResp{Error: via + " is unreachable"})
			return
		}
		defer ps.Close()
	} else {
		if ps, err = loc.sess.ys.OpenStream(); err != nil {
			reply(DialResp{Error: via + " is unreachable"})
			return
		}
		defer ps.Close()
		if err := WriteLine(ps, inner); err != nil {
			reply(DialResp{Error: via + " is unreachable"})
			return
		}
	}
	ps.SetReadDeadline(time.Now().Add(pingTimeout))
	var resp DialResp
	if err := ReadLine(NewReader(ps), &resp); err != nil {
		// Older clients close the stream without understanding the probe: the
		// device is connected, it just cannot be timed.
		reply(DialResp{Error: "no answer (the contact may run an older version)"})
		return
	}
	reply(resp)
}

func validTarget(t string) bool {
	h, p, err := net.SplitHostPort(t)
	if err != nil || h == "" || len(t) > 300 || strings.ContainsAny(t, " \t\r\n") {
		return false
	}
	n, err := strconv.Atoi(p)
	return err == nil && n > 0 && n < 65536
}

func (s *Server) handleDial(sess *session, st net.Conn, br *bufio.Reader, req DialReq) {
	result := "failed"
	fail := func(msg string) {
		CounterInc("gsp_relay_dials_total", "kind", "contact", "result", result)
		WriteLine(st, DialResp{Error: msg})
		st.Close()
	}
	select {
	case <-sess.ready:
	case <-time.After(5 * time.Second):
		fail("control stream not ready")
		return
	}
	sess.mu.Lock()
	fromDevice := sess.device
	sess.mu.Unlock()

	if req.App != "" {
		s.handleAppDial(sess, st, br, req, fromDevice)
		return
	}
	via, ok := NormalizeEmail(req.Via)
	viaDevice, dok := NormalizeDevice(req.ViaDevice)
	if !ok || !dok || !validTarget(req.Target) {
		fail("invalid request")
		return
	}
	if via != sess.email && !s.Store.IsContact(sess.email, via) {
		fail(via + " is not in your contacts")
		return
	}
	if host, _, err := net.SplitHostPort(req.Target); err == nil {
		if hit, blocked := s.Policy.Check(host); blocked {
			if s.Policy.record(sess.email, host, hit.Source) {
				s.audit("policy.block", sess.email, host, hit.Source+" ("+hit.Rule+")")
			}
			result = "blocked"
			fail("blocked by the organization's policy")
			return
		}
	}
	loc, err := s.locate(via, viaDevice)
	if err != nil {
		fail(err.Error())
		return
	}
	if loc.sess == sess {
		fail("cannot use this device as the relay exit")
		return
	}
	inner := DialReq{T: TDial, From: sess.email, FromDevice: fromDevice, Target: req.Target}
	var ps net.Conn
	if loc.remote != nil { // on another relay
		if ps, err = s.openRemote(loc.remote, kindDial, inner); err != nil {
			fail(via + " is unreachable")
			return
		}
	} else {
		if ps, err = loc.sess.ys.OpenStream(); err != nil {
			fail(via + " is unreachable")
			return
		}
		if err := WriteLine(ps, inner); err != nil {
			ps.Close()
			fail(via + " is unreachable")
			return
		}
	}
	pbr := NewReader(ps)
	ps.SetReadDeadline(time.Now().Add(dialReplyTimeout))
	var resp DialResp
	if err := ReadLine(pbr, &resp); err != nil {
		ps.Close()
		if errors.Is(err, net.ErrClosed) {
			fail(via + " is unreachable")
		} else {
			fail("no answer from " + via)
		}
		return
	}
	ps.SetReadDeadline(time.Time{})
	if err := WriteLine(st, resp); err != nil || !resp.OK {
		ps.Close()
		st.Close()
		return
	}
	CounterInc("gsp_relay_dials_total", "kind", "contact", "result", "ok")
	s.Log.Printf("%s/%s -> %s/%s -> %s", sess.email, fromDevice, via, viaDevice, req.Target)
	Pipe(st, br, ps, pbr)
}
