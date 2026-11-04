package relay

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

// Several relays can share one database and be put behind a load balancer.
// The database holds what must be common (the address book, revocations,
// enrollments, certificates, settings); each relay holds the connections it
// serves. What remains is to know who is connected where, and to connect two
// people whose devices are on different relays:
//
//   - every relay records its sessions in the presence table and keeps them
//     fresh with a heartbeat; a relay that dies leaves rows that stop counting
//     after presenceFresh;
//   - when a stream must reach a device on another relay, the relay opens (once,
//     and keeps) a link to it: an mTLS connection to its ordinary listener with
//     a relay certificate that only relays have, and asks it to open the stream
//     to its own session. The authorization (contacts, catalog, policy) is done
//     before, by the relay that received the request;
//   - a change anybody makes bumps a counter in the database; every relay
//     watches it and pushes fresh states to its users.

const (
	presenceFresh   = 20 * time.Second
	heartbeatEvery  = 5 * time.Second
	watchEvery      = time.Second
	purgeEvery      = 30 * time.Second
	replicaCertLife = 30 * 24 * time.Hour
)

// ReplicaConfig says how this relay is reached by the others.
type ReplicaConfig struct {
	// Addr is where the other relays reach this one's mTLS listener
	// (host:port), for instance the pod address.
	Addr string
	// CADir holds the CA the relay certificate is made with (the same directory
	// enrollment uses).
	CADir string
	// ServerName is the name in the server certificate of the relays (they are
	// reached by address, but verified by this name).
	ServerName string
	// CAFile verifies the peers' server certificates.
	CAFile string
}

type peerState struct {
	cfg  ReplicaConfig
	cert tls.Certificate
	tls  *tls.Config
	mu   sync.Mutex
	link map[string]*yamux.Session // by replica id
}

// SetShared makes the server one of several: it records its sessions in the
// shared database and reaches the others through peer links.
func (s *Server) SetShared(sh *Shared, rc ReplicaConfig) error {
	if rc.Addr == "" {
		// A relay on its own, with a database: it records who is connected, and
		// is not reachable by other relays.
		s.mu.Lock()
		s.Shared = sh
		s.mu.Unlock()
		return nil
	}
	cert, err := newReplicaCertificate(rc.CADir, sh.ReplicaID, replicaCertLife)
	if err != nil {
		return fmt.Errorf("replica certificate: %w", err)
	}
	pool, err := LoadPool(rc.CAFile)
	if err != nil {
		return fmt.Errorf("relay CA: %w", err)
	}
	ps := &peerState{cfg: rc, cert: cert, link: map[string]*yamux.Session{}}
	ps.tls = &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: rc.ServerName, MinVersion: tls.VersionTLS12}
	s.mu.Lock()
	s.Shared, s.peers = sh, ps
	s.mu.Unlock()
	return nil
}

func (s *Server) sharedDB() *Shared {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Shared
}

// ---- presence ---------------------------------------------------------

type remoteDevice struct {
	Email, Device, Replica, Addr, Serial string
	Since                                time.Time
	Ctx                                  *NetContext
}

func (s *Server) presenceSet(sess *session) {
	sh := s.sharedDB()
	if sh == nil {
		return
	}
	sess.mu.Lock()
	device, ctx := sess.device, sess.ctx
	sess.mu.Unlock()
	ctxJSON := ""
	if ctx != nil {
		b, _ := json.Marshal(ctx)
		ctxJSON = string(b)
	}
	// A device that reconnects to another relay: the old session is closed
	// there (it is the older one, by `since`).
	var oldReplica string
	if err := sh.db.QueryRow(`SELECT replica FROM presence WHERE email = ? AND device = ?`, sess.email, device).Scan(&oldReplica); err == nil && oldReplica != sh.ReplicaID {
		sh.db.Exec(`INSERT INTO kicks(email, device, serial, before_ts, ts) VALUES(?,?,?,?,?)`, sess.email, device, "", sess.since.UnixMilli(), nowUnix())
	}
	sh.db.Exec(`DELETE FROM presence WHERE email = ? AND device = ?`, sess.email, device)
	_, err := sh.db.Exec(`INSERT INTO presence(email, device, replica, addr, serial, since, ctx, beat) VALUES(?,?,?,?,?,?,?,?)`,
		sess.email, device, sh.ReplicaID, sess.addr, sess.serial, sess.since.Unix(), ctxJSON, nowUnix())
	if err != nil {
		s.Log.Printf("presence: %v", err)
	}
	sh.bump()
}

func (s *Server) presenceDel(email, device string) {
	sh := s.sharedDB()
	if sh == nil {
		return
	}
	sh.db.Exec(`DELETE FROM presence WHERE email = ? AND device = ? AND replica = ?`, email, device, sh.ReplicaID)
	sh.bump()
}

func (s *Server) queryRemote(where string, args ...any) []remoteDevice {
	sh := s.sharedDB()
	if sh == nil {
		return nil
	}
	args = append(args, sh.ReplicaID, nowUnix()-int64(presenceFresh/time.Second))
	rows, err := sh.db.Query(`SELECT p.email, p.device, p.replica, p.addr, p.serial, p.since, p.ctx, r.addr FROM presence p JOIN replicas r ON r.id = p.replica WHERE `+where+` AND p.replica <> ? AND p.beat > ?`, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []remoteDevice
	for rows.Next() {
		var d remoteDevice
		var since int64
		var ctx, raddr string
		if rows.Scan(&d.Email, &d.Device, &d.Replica, &d.Addr, &d.Serial, &since, &ctx, &raddr) != nil {
			continue
		}
		d.Since = time.Unix(since, 0)
		if ctx != "" {
			var c NetContext
			if json.Unmarshal([]byte(ctx), &c) == nil {
				d.Ctx = &c
			}
		}
		d.Addr = raddr + "|" + d.Addr // where to reach the relay it is on | the device's own address
		out = append(out, d)
	}
	return out
}

// remoteDevices lists the devices of email that are on other relays.
func (s *Server) remoteDevices(email string) []remoteDevice {
	return s.queryRemote(`p.email = ?`, email)
}

func (s *Server) remoteAll() []remoteDevice { return s.queryRemote(`1 = 1`) }

func splitRemoteAddr(a string) (relayAddr, deviceAddr string) {
	relayAddr, deviceAddr, _ = strings.Cut(a, "|")
	return
}

// ---- locating a peer anywhere -----------------------------------------

// located is where a device is: here (sess) or on another relay (remote).
type located struct {
	sess   *session
	remote *remoteDevice
}

// locate finds the device of a user, with the same rules as peer: an empty
// device means "any", which works only when exactly one is online.
func (s *Server) locate(email, device string) (located, error) {
	if sess, err := s.peer(email, device); err == nil && s.sharedDB() == nil {
		return located{sess: sess}, nil
	}
	if s.sharedDB() == nil {
		_, err := s.peer(email, device)
		return located{}, err
	}
	s.mu.Lock()
	var local []*session
	for _, sess := range s.sessions {
		if sess.email == email && (device == "" || sess.device == device) {
			local = append(local, sess)
		}
	}
	s.mu.Unlock()
	var remote []remoteDevice
	for _, d := range s.remoteDevices(email) {
		if device == "" || d.Device == device {
			remote = append(remote, d)
		}
	}
	switch n := len(local) + len(remote); {
	case n == 0 && device != "":
		return located{}, fmt.Errorf("%s/%s is offline", email, device)
	case n == 0:
		return located{}, fmt.Errorf("%s is offline", email)
	case n > 1:
		if device != "" { // the same device on two relays: the newest connection
			sort.Slice(remote, func(i, j int) bool { return remote[i].Since.After(remote[j].Since) })
			if len(local) > 0 {
				return located{sess: local[0]}, nil
			}
			return located{remote: &remote[0]}, nil
		}
		return located{}, fmt.Errorf("%s has multiple devices online: select one (relay://%s/device)", email, email)
	}
	if len(local) == 1 {
		return located{sess: local[0]}, nil
	}
	return located{remote: &remote[0]}, nil
}

// ---- links between relays ---------------------------------------------

// PeerReq is what a relay asks of another: open this to your own session.
type PeerReq struct {
	T      string  `json:"t"` // TPeer
	Kind   string  `json:"kind"`
	Email  string  `json:"email,omitempty"`
	Device string  `json:"device,omitempty"`
	Inner  DialReq `json:"inner"`
}

const (
	TPeer     = "peer"
	kindDial  = "dial"
	kindPing  = "ping"
	kindApp   = "app"
	peerDial  = 10 * time.Second
	peerReply = 100 * time.Second
)

func (s *Server) peerSession(replica, addr string) (*yamux.Session, error) {
	s.mu.Lock()
	ps := s.peers
	s.mu.Unlock()
	if ps == nil {
		return nil, errors.New("not a shared relay")
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if ys := ps.link[replica]; ys != nil && !ys.IsClosed() {
		return ys, nil
	}
	d := &net.Dialer{Timeout: peerDial}
	raw, err := (&tls.Dialer{NetDialer: d, Config: ps.tls}).DialContext(context.Background(), "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("relay %s is unreachable: %w", replica, err)
	}
	cfg := yamux.DefaultConfig()
	cfg.LogOutput = discard{}
	ys, err := yamux.Client(raw, cfg)
	if err != nil {
		raw.Close()
		return nil, err
	}
	ps.link[replica] = ys
	return ys, nil
}

// openRemote asks the relay the device is on to open a stream to it, and
// returns the stream: the answer (a DialResp or a ping answer) is the first
// line on it, as with a device on this relay.
func (s *Server) openRemote(rd *remoteDevice, kind string, inner DialReq) (net.Conn, error) {
	relayAddr, _ := splitRemoteAddr(rd.Addr)
	ys, err := s.peerSession(rd.Replica, relayAddr)
	if err != nil {
		return nil, err
	}
	st, err := ys.OpenStream()
	if err != nil {
		return nil, err
	}
	if err := WriteLine(st, PeerReq{T: TPeer, Kind: kind, Email: rd.Email, Device: rd.Device, Inner: inner}); err != nil {
		st.Close()
		return nil, err
	}
	return st, nil
}

// handlePeerConn serves another relay's link.
func (s *Server) handlePeerConn(c net.Conn, id string) {
	cfg := yamux.DefaultConfig()
	cfg.LogOutput = discard{}
	ys, err := yamux.Server(c, cfg)
	if err != nil {
		c.Close()
		return
	}
	defer ys.Close()
	for {
		st, err := ys.AcceptStream()
		if err != nil {
			return
		}
		go s.handlePeerStream(st)
	}
}

func (s *Server) handlePeerStream(st net.Conn) {
	br := NewReader(st)
	st.SetReadDeadline(time.Now().Add(firstLineTimeout))
	var req PeerReq
	if err := ReadLine(br, &req); err != nil || req.T != TPeer {
		st.Close()
		return
	}
	st.SetReadDeadline(time.Time{})
	fail := func(msg string) {
		if req.Kind == kindPing {
			WriteLine(st, DialResp{Error: msg})
		} else {
			WriteLine(st, DialResp{Error: msg})
		}
		st.Close()
	}
	var ps net.Conn
	var err error
	switch req.Kind {
	case kindDial, kindPing:
		sess := s.localSession(req.Email, req.Device)
		if sess == nil {
			fail(req.Email + " is offline")
			return
		}
		if ps, err = sess.ys.OpenStream(); err != nil {
			fail(req.Email + " is unreachable")
			return
		}
	case kindApp:
		gw := s.gateway(req.Inner.Via) // the gateway id travels in Via
		if gw == nil {
			fail("the application is not available right now")
			return
		}
		if ps, err = gw.ys.OpenStream(); err != nil {
			fail("the application is not available right now")
			return
		}
	default:
		st.Close()
		return
	}
	if err := WriteLine(ps, req.Inner); err != nil {
		ps.Close()
		fail("unreachable")
		return
	}
	pbr := NewReader(ps)
	timeout := peerReply
	if req.Kind == kindPing {
		timeout = pingTimeout
	}
	ps.SetReadDeadline(time.Now().Add(timeout))
	var resp DialResp
	if err := ReadLine(pbr, &resp); err != nil {
		ps.Close()
		fail("no answer")
		return
	}
	ps.SetReadDeadline(time.Time{})
	if err := WriteLine(st, resp); err != nil || !resp.OK || req.Kind == kindPing {
		ps.Close()
		st.Close()
		return
	}
	Pipe(st, br, ps, pbr)
}

func (s *Server) localSession(email, device string) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	if device != "" {
		return s.sessions[sessionKey(email, device)]
	}
	for _, sess := range s.sessions {
		if sess.email == email {
			return sess
		}
	}
	return nil
}

// ---- gateways on other relays -----------------------------------------

func (s *Server) gatewayPresenceSet(id string, sess *session) {
	sh := s.sharedDB()
	if sh == nil {
		return
	}
	sh.db.Exec(`DELETE FROM gw_presence WHERE id = ?`, id)
	sh.db.Exec(`INSERT INTO gw_presence(id, replica, addr, serial, since, beat) VALUES(?,?,?,?,?,?)`, id, sh.ReplicaID, sess.addr, sess.serial, sess.since.Unix(), nowUnix())
	sh.bump()
}

func (s *Server) gatewayPresenceDel(id string) {
	if sh := s.sharedDB(); sh != nil {
		sh.db.Exec(`DELETE FROM gw_presence WHERE id = ? AND replica = ?`, id, sh.ReplicaID)
		sh.bump()
	}
}

// remoteGateway finds a gateway connected to another relay.
func (s *Server) remoteGateway(id string) *remoteDevice {
	sh := s.sharedDB()
	if sh == nil {
		return nil
	}
	var rid, raddr string
	err := sh.db.QueryRow(`SELECT g.replica, r.addr FROM gw_presence g JOIN replicas r ON r.id = g.replica WHERE g.id = ? AND g.replica <> ? AND g.beat > ?`,
		id, sh.ReplicaID, nowUnix()-int64(presenceFresh/time.Second)).Scan(&rid, &raddr)
	if err != nil {
		return nil
	}
	return &remoteDevice{Replica: rid, Addr: raddr + "|", Device: id}
}

func (s *Server) remoteGatewayIDs() []string {
	sh := s.sharedDB()
	if sh == nil {
		return nil
	}
	rows, err := sh.db.Query(`SELECT id FROM gw_presence WHERE replica <> ? AND beat > ?`, sh.ReplicaID, nowUnix()-int64(presenceFresh/time.Second))
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			out = append(out, id)
		}
	}
	return out
}

// ---- the watcher ------------------------------------------------------

// OnSharedChange registers a function called when somebody changed what is
// shared (settings, contacts, who is online...).
func (s *Server) OnSharedChange(fn func()) {
	s.mu.Lock()
	s.onShared = append(s.onShared, fn)
	s.mu.Unlock()
}

// RunShared keeps this relay in step with the others until ctx ends.
func (s *Server) RunShared(ctx context.Context) {
	sh := s.sharedDB()
	if sh == nil {
		return
	}
	s.heartbeat(sh)
	last := sh.version()
	var lastKick int64
	sh.db.QueryRow(`SELECT COALESCE(MAX(id), 0) FROM kicks`).Scan(&lastKick)
	tick := time.NewTicker(watchEvery)
	defer tick.Stop()
	var beat, purge time.Time
	for {
		select {
		case <-ctx.Done():
			s.leave(sh)
			return
		case <-tick.C:
		}
		now := time.Now()
		if now.Sub(beat) >= heartbeatEvery {
			beat = now
			s.heartbeat(sh)
		}
		if now.Sub(purge) >= purgeEvery {
			purge = now
			stale := now.Add(-3 * presenceFresh).Unix()
			sh.db.Exec(`DELETE FROM presence WHERE beat < ?`, stale)
			sh.db.Exec(`DELETE FROM gw_presence WHERE beat < ?`, stale)
			sh.db.Exec(`DELETE FROM replicas WHERE beat < ?`, stale)
			sh.db.Exec(`DELETE FROM kicks WHERE ts < ?`, now.Add(-time.Hour).Unix())
		}
		lastKick = s.applyKicks(sh, lastKick)
		s.enforceRevocations()
		if v := sh.version(); v != last {
			last = v
			s.mu.Lock()
			fns := append([]func(){}, s.onShared...)
			s.mu.Unlock()
			for _, fn := range fns {
				fn()
			}
			s.pushCatalog() // every user of this relay gets the new state
		}
	}
}

func (s *Server) heartbeat(sh *Shared) {
	s.mu.Lock()
	ps := s.peers
	s.mu.Unlock()
	addr := ""
	if ps != nil {
		addr = ps.cfg.Addr
	}
	if err := sh.db.upsert("replicas", "id", []string{"id", "addr", "beat"}, []string{"addr", "beat"}, sh.ReplicaID, addr, nowUnix()); err != nil {
		s.Log.Printf("heartbeat: %v", err)
	}
	sh.db.Exec(`UPDATE presence SET beat = ? WHERE replica = ?`, nowUnix(), sh.ReplicaID)
	sh.db.Exec(`UPDATE gw_presence SET beat = ? WHERE replica = ?`, nowUnix(), sh.ReplicaID)
}

// leave takes this relay's rows out when it stops.
func (s *Server) leave(sh *Shared) {
	sh.db.Exec(`DELETE FROM presence WHERE replica = ?`, sh.ReplicaID)
	sh.db.Exec(`DELETE FROM gw_presence WHERE replica = ?`, sh.ReplicaID)
	sh.db.Exec(`DELETE FROM replicas WHERE id = ?`, sh.ReplicaID)
	sh.bump()
}

// applyKicks closes the sessions other relays asked to close.
func (s *Server) applyKicks(sh *Shared, after int64) int64 {
	rows, err := sh.db.Query(`SELECT id, email, device, serial, before_ts FROM kicks WHERE id > ? ORDER BY id`, after)
	if err != nil {
		return after
	}
	type kick struct {
		email, device, serial string
		before                int64
	}
	var ks []kick
	max := after
	for rows.Next() {
		var id int64
		var k kick
		if rows.Scan(&id, &k.email, &k.device, &k.serial, &k.before) == nil {
			ks = append(ks, k)
			if id > max {
				max = id
			}
		}
	}
	rows.Close()
	for _, k := range ks {
		s.kickLocal(k.email, k.device, k.serial, k.before)
	}
	return max
}

// kickLocal closes the local sessions that match: of the user (all of them
// when device and serial are empty), the device, the certificate. before, in
// milliseconds, spares sessions that started after it.
func (s *Server) kickLocal(email, device, serial string, before int64) int {
	s.mu.Lock()
	var hit []*session
	for _, sess := range s.sessions {
		if sess.email != email || (serial != "" && sess.serial != serial) {
			continue
		}
		sess.mu.Lock()
		dev := sess.device
		sess.mu.Unlock()
		if device != "" && dev != device {
			continue
		}
		if before > 0 && sess.since.UnixMilli() >= before {
			continue
		}
		hit = append(hit, sess)
	}
	s.mu.Unlock()
	for _, sess := range hit {
		sess.ys.Close()
	}
	return len(hit)
}

// enforceRevocations closes connections whose certificate was revoked since
// they were made (by an administrator, a user, or another relay).
func (s *Server) enforceRevocations() {
	if !s.Revoked.Enabled() {
		return
	}
	s.mu.Lock()
	var sessions []*session
	for _, sess := range s.sessions {
		sessions = append(sessions, sess)
	}
	for _, g := range s.gateways {
		sessions = append(sessions, g)
	}
	s.mu.Unlock()
	for _, sess := range sessions {
		if s.Revoked.IsRevoked(sess.email, sess.serial) {
			s.Log.Printf("closing the connection of %s: its certificate was revoked", orDash(sess.email+sess.device))
			sess.ys.Close()
		}
	}
}
