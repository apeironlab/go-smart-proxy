package relay

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A cluster is several relays sharing one database and one CA, as they would
// behind a load balancer.
type cluster struct {
	t     *testing.T
	dir   string
	ca    string
	addr  string // the database
	rev   string
	first *Shared
}

type replica struct {
	id  string
	srv *Server
	sh  *Shared
	ln  net.Listener
	cl  *cluster
}

func newCluster(t *testing.T) *cluster {
	t.Helper()
	dir := t.TempDir()
	c := &cluster{t: t, dir: dir, ca: filepath.Join(dir, "ca"), addr: testDBAddr(t, dir)}
	if err := InitCA(c.ca); err != nil {
		t.Fatal(err)
	}
	if err := IssueServer(c.ca, filepath.Join(dir, "srv"), []string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	return c
}

func (c *cluster) replica(id string) *replica {
	t := c.t
	var sh *Shared
	if c.first != nil && c.first.db.dia == dialSQLite {
		// A SQLite file is for one process: the relays of the test share the
		// one connection, each with its own identity.
		sh = &Shared{db: c.first.db, ReplicaID: id}
		sh.admin = &adminDB{db: c.first.db, changed: sh.bump}
	} else {
		var err error
		if sh, err = OpenShared(c.addr, id); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { sh.Close() })
	}
	if c.first == nil {
		c.first = sh
	}
	cfg, err := TLSConfig(filepath.Join(c.dir, "srv", "server.pem"), filepath.Join(c.dir, "srv", "server-key.pem"), filepath.Join(c.ca, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	srv := NewServer(NewSharedStore(sh))
	srv.Revoked = NewSharedRevocations(sh)
	srv.Log = quietLogger()
	if err := srv.SetShared(sh, ReplicaConfig{Addr: ln.Addr().String(), CADir: c.ca, ServerName: "127.0.0.1", CAFile: filepath.Join(c.ca, "ca.pem")}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Serve(ln)
	go srv.RunShared(ctx)
	return &replica{id: id, srv: srv, sh: sh, ln: ln, cl: c}
}

// connect is a user's proxy connecting to this relay.
func (r *replica) connect(email, device string) *testClient {
	t := r.cl.t
	out := filepath.Join(r.cl.dir, email)
	if _, err := tls.LoadX509KeyPair(filepath.Join(out, "client.pem"), filepath.Join(out, "client-key.pem")); err != nil {
		if err := IssueClient(r.cl.ca, out, email); err != nil {
			t.Fatal(err)
		}
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(out, "client.pem"), filepath.Join(out, "client-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pool, _ := LoadPool(filepath.Join(r.cl.ca, "ca.pem"))
	return connectTestClient(t, r.ln.Addr().String(), pool, cert, email, device)
}

func echoOn(c *testClient) {
	go func() {
		for {
			s, err := c.ys.AcceptStream()
			if err != nil {
				return
			}
			go func() {
				br := NewReader(s)
				var req DialReq
				if ReadLine(br, &req) != nil {
					s.Close()
					return
				}
				if req.T == TPing {
					WriteLine(s, DialResp{OK: true})
					s.Close()
					return
				}
				WriteLine(s, DialResp{OK: true})
				io.Copy(s, br)
				s.Close()
			}()
		}
	}()
}

func within(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 120; i++ {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

func TestContactsAndTrafficAcrossRelays(t *testing.T) {
	c := newCluster(t)
	a, b := c.replica("ra"), c.replica("rb")
	alice, bob := a.connect("alice@example.com", "laptop"), b.connect("bob@example.com", "pc")
	echoOn(bob)
	alice.waitState(t, func(s State) bool { return s.Email == "alice@example.com" })

	// a request made on one relay reaches the user connected to the other
	WriteLine(alice.ctrl, ClientMsg{T: TContactRequest, Email: "bob@example.com"})
	bob.waitState(t, func(s State) bool { return len(s.Incoming) == 1 && s.Incoming[0] == "alice@example.com" })
	WriteLine(bob.ctrl, ClientMsg{T: TContactRespond, Email: "alice@example.com", Accept: true})
	st := alice.waitState(t, func(s State) bool { return len(s.Contacts) == 1 && s.Contacts[0].Online })
	if st.Contacts[0].Email != "bob@example.com" || len(st.Contacts[0].Devices) != 1 || st.Contacts[0].Devices[0] != "pc" {
		t.Fatalf("alice sees: %+v", st.Contacts)
	}
	bob.waitState(t, func(s State) bool { return len(s.Contacts) == 1 && s.Contacts[0].Online })

	// a connection through bob crosses from the relay alice is on to bob's
	st1, _ := alice.ys.OpenStream()
	WriteLine(st1, DialReq{T: TDial, Via: "bob@example.com", Target: "10.1.2.3:80"})
	br := NewReader(st1)
	var resp DialResp
	if err := ReadLine(br, &resp); err != nil || !resp.OK {
		t.Fatalf("dial across relays: %+v %v", resp, err)
	}
	io.WriteString(st1, "ping")
	buf := make([]byte, 4)
	if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo across relays: %q %v", buf, err)
	}
	st1.Close()

	// and so does a latency probe
	ps, _ := alice.ys.OpenStream()
	WriteLine(ps, DialReq{T: TPing, Via: "bob@example.com"})
	ps.SetReadDeadline(time.Now().Add(5 * time.Second))
	var pr DialResp
	if err := ReadLine(NewReader(ps), &pr); err != nil || !pr.OK {
		t.Fatalf("ping across relays: %+v %v", pr, err)
	}

	// a user who is not a contact is not reachable, wherever they are
	eve := b.connect("eve@example.com", "x")
	echoOn(eve)
	waitFor(t, func() bool { return len(a.srv.Online()) == 3 })
	es, _ := alice.ys.OpenStream()
	WriteLine(es, DialReq{T: TDial, Via: "eve@example.com", Target: "10.1.2.3:80"})
	var er DialResp
	ReadLine(NewReader(es), &er)
	if er.OK || !strings.Contains(er.Error, "not in your contacts") {
		t.Fatalf("a stranger on another relay: %+v", er)
	}

	// both relays report everybody
	for _, r := range []*replica{a, b} {
		if n := len(r.srv.Online()); n != 3 {
			t.Fatalf("%s sees %d devices", r.id, n)
		}
	}
	// going offline is seen across relays
	bob.ys.Close()
	alice.waitState(t, func(s State) bool { return len(s.Contacts) == 1 && !s.Contacts[0].Online })
}

func TestApplicationsThroughAGatewayOnAnotherRelay(t *testing.T) {
	c := newCluster(t)
	a, b := c.replica("ra"), c.replica("rb")
	backend := echoBackend(t)
	cat := NewCatalog()
	cat2 := NewCatalog()
	a.srv.AttachCatalog(cat)
	b.srv.AttachCatalog(cat2)
	apps := []App{{ID: "echo", Name: "Echo", Host: "echo.apps", Gateway: "g1", Target: backend, Everyone: true}}
	cat.Set(apps)
	cat2.Set(apps)

	out := filepath.Join(c.dir, "gw")
	IssueGateway(c.ca, out, "g1")
	g, err := NewGateway(GatewayConfig{Address: b.ln.Addr().String(), CertFile: filepath.Join(out, "gateway.pem"), KeyFile: filepath.Join(out, "gateway-key.pem"), CAFile: filepath.Join(out, "ca.pem")})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go g.Run(ctx)
	within(t, "the gateway on relay b", func() bool { return len(b.srv.OnlineGateways()) == 1 })

	// the user is on relay a, the gateway on relay b
	alice := a.connect("alice@example.com", "laptop")
	st := alice.waitState(t, func(s State) bool { return len(s.Apps) == 1 && s.Apps[0].Online })
	if st.Apps[0].ID != "echo" {
		t.Fatalf("apps: %+v", st.Apps)
	}
	conn, br, resp := dialApp(t, alice, "echo")
	if !resp.OK {
		t.Fatalf("open: %+v", resp)
	}
	io.WriteString(conn, "hello")
	buf := make([]byte, 5)
	if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("echo: %q %v", buf, err)
	}
	conn.Close()
	if got := a.srv.OnlineGateways(); len(got) != 1 || got[0] != "g1" {
		t.Fatalf("gateways seen from relay a: %v", got)
	}
}

func TestRevocationReachesConnectionsOnOtherRelays(t *testing.T) {
	c := newCluster(t)
	a, b := c.replica("ra"), c.replica("rb")
	alice := b.connect("alice@example.com", "laptop")
	waitFor(t, func() bool { return len(a.srv.Online()) == 1 })

	// revoked on relay a: relay b closes alice's connection
	if err := a.srv.Revoked.Add("alice@example.com"); err != nil {
		t.Fatal(err)
	}
	within(t, "relay b to close the revoked connection", func() bool { return len(b.srv.Online()) == 0 })
	_ = alice
	// and she cannot come back, on either relay
	cert, _ := tls.LoadX509KeyPair(filepath.Join(c.dir, "alice@example.com", "client.pem"), filepath.Join(c.dir, "alice@example.com", "client-key.pem"))
	pool, _ := LoadPool(filepath.Join(c.ca, "ca.pem"))
	for _, r := range []*replica{a, b} {
		cn, err := tls.Dial("tcp", r.ln.Addr().String(), &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool})
		if err != nil {
			continue
		}
		cn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := cn.Read(make([]byte, 1)); err == nil {
			t.Fatalf("a revoked connection was served by %s", r.id)
		}
		cn.Close()
	}
	if err := a.srv.Revoked.Remove("alice@example.com"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(sharedFreshness + 200*time.Millisecond) // the other relay's copy of the list is up to a second old
	b.connect("alice@example.com", "laptop")
	within(t, "alice back", func() bool { return len(a.srv.Online()) == 1 })
}

func TestADeviceThatReconnectsToAnotherRelayReplacesItsOldSession(t *testing.T) {
	c := newCluster(t)
	a, b := c.replica("ra"), c.replica("rb")
	first := a.connect("alice@example.com", "laptop")
	within(t, "first session", func() bool { return len(a.srv.Online()) == 1 })
	time.Sleep(20 * time.Millisecond)
	b.connect("alice@example.com", "laptop")
	// relay a closes the older one; one device remains, on relay b
	within(t, "one session", func() bool {
		on := a.srv.Online()
		return len(on) == 1 && on[0].Replica == "rb"
	})
	first.ys.Close()
}

func TestADeadRelaysSessionsStopCounting(t *testing.T) {
	c := newCluster(t)
	a, b := c.replica("ra"), c.replica("rb")
	b.connect("bob@example.com", "pc")
	within(t, "bob seen by a", func() bool { return len(a.srv.Online()) == 1 })
	// relay b "dies": its heartbeat is old
	b.sh.db.Exec(`UPDATE presence SET beat = ? WHERE replica = ?`, nowUnix()-int64(2*presenceFresh/time.Second), "rb")
	if n := len(a.srv.Online()); n != 0 {
		t.Fatalf("a dead relay's devices still count: %d", n)
	}
}

func TestSettingsSavedOnOneRelayReachTheOther(t *testing.T) {
	c := newCluster(t)
	a, b := c.replica("ra"), c.replica("rb")
	mk := func(r *replica) *Admin {
		adm, err := NewAdmin(AdminConfig{Shared: r.sh, Groups: []string{"admin"}, Revoked: r.srv.Revoked})
		if err != nil {
			t.Fatal(err)
		}
		adm.SetServer(r.srv)
		cat := NewCatalog()
		if err := adm.SetCatalog(cat); err != nil {
			t.Fatal(err)
		}
		r.srv.AttachCatalog(cat)
		return adm
	}
	admA, admB := mk(a), mk(b)
	_ = admA
	alice := b.connect("alice@example.com", "laptop")
	alice.waitState(t, func(s State) bool { return s.Email == "alice@example.com" })

	// the catalog is changed on relay a ...
	if err := a.srv.Catalog.Set([]App{{ID: "crm", Name: "CRM", Host: "crm.apps", Gateway: "g", Target: "10.0.0.1:80", Everyone: true}}); err != nil {
		t.Fatal(err)
	}
	// ... and alice, on relay b, is told
	st := alice.waitState(t, func(s State) bool { return len(s.Apps) == 1 })
	if st.Apps[0].ID != "crm" {
		t.Fatalf("apps: %+v", st.Apps)
	}
	if got := b.srv.Catalog.Apps(); len(got) != 1 {
		t.Fatalf("catalog on b: %+v", got)
	}
	_ = admB
}

func quietLogger() *log.Logger { return log.New(io.Discard, "", 0) }
