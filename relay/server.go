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

	mu       sync.Mutex
	sessions map[string]*session
}

type session struct {
	email  string
	device string
	ys     *yamux.Session
	mu     sync.Mutex
	ctrl   net.Conn
	ready  chan struct{} // closed once the control stream has registered the device
}

func NewServer(store *Store) *Server {
	return &Server{Store: store, Log: log.Default(), sessions: map[string]*session{}}
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
		s.Log.Printf("revoked certificate from %s refused", c.RemoteAddr())
		c.Close()
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
	sess := &session{email: email, ys: ys, ready: make(chan struct{})}
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
	s.Log.Printf("%s/%s disconnected", email, device)
	s.notifyPresence(email)
	s.pushState(email, "")
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func sessionKey(email, device string) string { return email + "\x00" + device }

// onlineDevices returns the sorted online device codes of a user.
func (s *Server) onlineDevices(email string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, sess := range s.sessions {
		if sess.email == email && sess.device != "" {
			out = append(out, sess.device)
		}
	}
	sort.Strings(out)
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
	st := State{T: TState, Email: email, Incoming: in, Outgoing: out, Notice: notice}
	for _, c := range contacts {
		devices := s.onlineDevices(c)
		st.Contacts = append(st.Contacts, Contact{Email: c, Online: len(devices) > 0, Devices: devices})
	}
	ownOnline := map[string]bool{}
	s.mu.Lock()
	for _, sess := range s.sessions {
		if sess.email == email {
			ownOnline[sess.device] = true
		}
	}
	s.mu.Unlock()
	for _, id := range s.Store.Devices(email) {
		st.MyDevices = append(st.MyDevices, DeviceInfo{ID: id, Online: ownOnline[id]})
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
	s.Store.RememberDevice(sess.email, device)
	s.Log.Printf("%s/%s connected", sess.email, device)
	s.pushState(sess.email, "")
	s.notifyPresence(sess.email)

	defer st.Close()

	for {
		var m ClientMsg
		if err := ReadLine(br, &m); err != nil {
			return
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

func validTarget(t string) bool {
	h, p, err := net.SplitHostPort(t)
	if err != nil || h == "" || len(t) > 300 || strings.ContainsAny(t, " \t\r\n") {
		return false
	}
	n, err := strconv.Atoi(p)
	return err == nil && n > 0 && n < 65536
}

func (s *Server) handleDial(sess *session, st net.Conn, br *bufio.Reader, req DialReq) {
	fail := func(msg string) {
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
	peer, err := s.peer(via, viaDevice)
	if err != nil {
		fail(err.Error())
		return
	}
	if peer == sess {
		fail("cannot use this device as the relay exit")
		return
	}
	ps, err := peer.ys.OpenStream()
	if err != nil {
		fail(via + " is unreachable")
		return
	}
	if err := WriteLine(ps, DialReq{T: TDial, From: sess.email, FromDevice: fromDevice, Target: req.Target}); err != nil {
		ps.Close()
		fail(via + " is unreachable")
		return
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
	s.Log.Printf("%s/%s -> %s/%s -> %s", sess.email, fromDevice, via, viaDevice, req.Target)
	Pipe(st, br, ps, pbr)
}
