package relay

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log"
	"net"
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

	mu       sync.Mutex
	sessions map[string]*session
}

type session struct {
	email string
	ys    *yamux.Session
	mu    sync.Mutex
	ctrl  net.Conn
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
	sess := &session{email: email, ys: ys}
	s.mu.Lock()
	old := s.sessions[email]
	s.sessions[email] = sess
	s.mu.Unlock()
	if old != nil {
		old.ys.Close() // a newer connection of the same identity replaces the old one
	}
	s.Log.Printf("%s connected from %s", email, c.RemoteAddr())
	s.notifyPresence(email)

	defer func() {
		ys.Close()
		s.mu.Lock()
		if s.sessions[email] == sess {
			delete(s.sessions, email)
		}
		s.mu.Unlock()
		s.Log.Printf("%s disconnected", email)
		s.notifyPresence(email)
	}()

	for {
		st, err := ys.AcceptStream()
		if err != nil {
			return
		}
		go s.handleStream(sess, st)
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func (s *Server) online(email string) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[email]
}

// pushState sends the current snapshot to email, if connected.
func (s *Server) pushState(email, notice string) {
	sess := s.online(email)
	if sess == nil {
		return
	}
	sess.mu.Lock()
	ctrl := sess.ctrl
	sess.mu.Unlock()
	if ctrl == nil {
		return
	}
	contacts, in, out := s.Store.Snapshot(email)
	st := State{T: TState, Email: email, Incoming: in, Outgoing: out, Notice: notice}
	for _, c := range contacts {
		st.Contacts = append(st.Contacts, Contact{Email: c, Online: s.online(c) != nil})
	}
	sess.mu.Lock()
	ctrl.SetWriteDeadline(time.Now().Add(10 * time.Second))
	err := WriteLine(ctrl, st)
	sess.mu.Unlock()
	if err != nil {
		ctrl.Close()
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
		s.handleControl(sess, st, br)
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

func (s *Server) handleControl(sess *session, st net.Conn, br *bufio.Reader) {
	sess.mu.Lock()
	if sess.ctrl != nil {
		sess.mu.Unlock()
		st.Close()
		return
	}
	sess.ctrl = st
	sess.mu.Unlock()
	defer st.Close()

	s.pushState(sess.email, "")
	for {
		var m ClientMsg
		if err := ReadLine(br, &m); err != nil {
			return
		}
		other, ok := NormalizeEmail(m.Email)
		if !ok {
			s.pushState(sess.email, "invalid e-mail address")
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
			s.pushState(sess.email, notice)
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
	via, ok := NormalizeEmail(req.Via)
	if !ok || !validTarget(req.Target) {
		fail("invalid request")
		return
	}
	if !s.Store.IsContact(sess.email, via) {
		fail(via + " is not in your contacts")
		return
	}
	peer := s.online(via)
	if peer == nil {
		fail(via + " is offline")
		return
	}
	ps, err := peer.ys.OpenStream()
	if err != nil {
		fail(via + " is unreachable")
		return
	}
	if err := WriteLine(ps, DialReq{T: TDial, From: sess.email, Target: req.Target}); err != nil {
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
	s.Log.Printf("%s -> %s -> %s", sess.email, via, req.Target)
	Pipe(st, br, ps, pbr)
}
