package relay

import (
	"bufio"
	"crypto/x509"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/yamux"
)

// appDialTimeout bounds how long a gateway may take to reach a backend.
const appDialTimeout = 30 * time.Second

func (s *Server) gateway(id string) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gateways[id]
}

// appsFor lists the applications email may open, sorted by name. Applications
// the user may not open are not mentioned at all.
func (s *Server) appsFor(email string) []AppInfo {
	if s.Catalog == nil {
		return nil
	}
	groups := s.Store.Groups(email)
	var out []AppInfo
	for _, a := range s.Catalog.Apps() {
		if !a.Allows(email, groups) {
			continue
		}
		out = append(out, AppInfo{
			ID: a.ID, Name: a.Name, Description: a.Description, Host: a.Host, Kind: a.Kind,
			Online: s.gateway(a.Gateway) != nil,
		})
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

// AttachCatalog makes the server serve the catalog and keep users and
// gateways up to date when it changes.
func (s *Server) AttachCatalog(c *Catalog) {
	s.Catalog = c
	c.OnChange(s.pushCatalog)
}

// AttachPolicy makes the server enforce the policy and tell proxies about it.
func (s *Server) AttachPolicy(p *Policy) {
	s.Policy = p
	p.OnChange(s.pushCatalog)
}

// pushCatalog tells every connected user and gateway about the catalog (and
// the policy: both ride on the state each user receives).
func (s *Server) pushCatalog() {
	s.mu.Lock()
	people := map[string]bool{}
	for _, sess := range s.sessions {
		people[sess.email] = true
	}
	var gws []string
	for id := range s.gateways {
		gws = append(gws, id)
	}
	s.mu.Unlock()
	for e := range people {
		s.pushState(e, "")
	}
	for _, id := range gws {
		s.pushGateway(id)
	}
}

// pushGatewayState sends a gateway the applications it serves.
func (s *Server) pushGateway(id string) {
	gw := s.gateway(id)
	if gw == nil {
		return
	}
	apps := []GatewayApp{}
	if s.Catalog != nil {
		apps = s.Catalog.ForGateway(id)
	}
	gw.mu.Lock()
	defer gw.mu.Unlock()
	if gw.ctrl == nil {
		return
	}
	gw.ctrl.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := WriteLine(gw.ctrl, GatewayState{T: TGatewayState, Apps: apps}); err != nil {
		gw.ys.Close()
	}
}

// OnlineGateways lists the gateways that are connected.
func (s *Server) OnlineGateways() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.gateways))
	for id := range s.gateways {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// KickGateway closes the connection of a gateway.
func (s *Server) KickGateway(id string) bool {
	if gw := s.gateway(id); gw != nil {
		gw.ys.Close()
		return true
	}
	return false
}

// handleGatewayConn serves the connection of an application gateway after the
// TLS handshake and the revocation check.
func (s *Server) handleGatewayConn(c net.Conn, cert *x509.Certificate, id string) {
	cfg := yamux.DefaultConfig()
	cfg.LogOutput = discard{}
	ys, err := yamux.Server(c, cfg)
	if err != nil {
		c.Close()
		return
	}
	defer ys.Close()
	sess := &session{ys: ys, ready: make(chan struct{}), addr: c.RemoteAddr().String(), since: time.Now(), device: id}
	if cert.SerialNumber != nil {
		sess.serial = strings.ToLower(cert.SerialNumber.Text(16))
	}

	// The gateway's first stream is its control stream.
	st, err := ys.AcceptStream()
	if err != nil {
		return
	}
	defer st.Close()
	st.SetReadDeadline(time.Now().Add(firstLineTimeout))
	br := NewReader(st)
	var hello DialReq
	if err := ReadLine(br, &hello); err != nil || hello.T != TGateway {
		return
	}
	st.SetReadDeadline(time.Time{})
	sess.mu.Lock()
	sess.ctrl = st
	sess.mu.Unlock()

	s.mu.Lock()
	old := s.gateways[id]
	s.gateways[id] = sess
	s.mu.Unlock()
	if old != nil {
		old.ys.Close() // a newer connection of the same gateway replaces the old one
	}
	s.Log.Printf("gateway %s connected from %s", id, sess.addr)
	s.audit("gateway.open", id, "", sess.addr)
	s.pushGateway(id)
	s.pushCatalog()

	defer func() {
		s.mu.Lock()
		if s.gateways[id] == sess {
			delete(s.gateways, id)
		}
		s.mu.Unlock()
		s.Log.Printf("gateway %s disconnected", id)
		s.audit("gateway.close", id, "", "")
		s.pushCatalog()
	}()

	// Streams opened by a gateway are not served; we only watch the control
	// stream for the end of the connection.
	go func() {
		for {
			x, err := ys.AcceptStream()
			if err != nil {
				return
			}
			x.Close()
		}
	}()
	for {
		var ignore map[string]any
		if err := ReadLine(br, &ignore); err != nil {
			return
		}
	}
}

// handleAppDial opens an application for a user: the user must be allowed by
// the catalog, and the gateway that serves it must be connected. The user does
// not say where to connect; the gateway uses the catalog's target.
func (s *Server) handleAppDial(sess *session, st net.Conn, br *bufio.Reader, req DialReq, fromDevice string) {
	fail := func(msg string) {
		WriteLine(st, DialResp{Error: msg})
		st.Close()
	}
	if s.Catalog == nil {
		fail("unknown application")
		return
	}
	app, ok := s.Catalog.ByID(req.App)
	if !ok || !app.Allows(sess.email, s.Store.Groups(sess.email)) {
		// Same answer for "does not exist" and "not allowed": a user learns
		// nothing about applications they cannot open.
		if ok {
			s.audit("app.denied", sess.email, app.ID, "")
		}
		fail("unknown application")
		return
	}
	gw := s.gateway(app.Gateway)
	if gw == nil {
		fail(app.Name + " is not available right now")
		return
	}
	ps, err := gw.ys.OpenStream()
	if err != nil {
		fail(app.Name + " is not available right now")
		return
	}
	if err := WriteLine(ps, DialReq{T: TDial, App: app.ID, From: sess.email, FromDevice: fromDevice}); err != nil {
		ps.Close()
		fail(app.Name + " is not available right now")
		return
	}
	pbr := NewReader(ps)
	ps.SetReadDeadline(time.Now().Add(appDialTimeout))
	var resp DialResp
	if err := ReadLine(pbr, &resp); err != nil {
		ps.Close()
		fail("no answer from the gateway of " + app.Name)
		return
	}
	ps.SetReadDeadline(time.Time{})
	if !resp.OK {
		// What went wrong at the backend is the operator's business.
		s.Log.Printf("%s/%s -> app %s: gateway %s: %s", sess.email, fromDevice, app.ID, app.Gateway, resp.Error)
		ps.Close()
		fail(app.Name + " cannot be reached")
		return
	}
	if err := WriteLine(st, resp); err != nil {
		ps.Close()
		st.Close()
		return
	}
	s.Log.Printf("%s/%s -> app %s via gateway %s", sess.email, fromDevice, app.ID, app.Gateway)
	s.audit("app.open", sess.email, app.ID, fromDevice)
	Pipe(st, br, ps, pbr)
}
