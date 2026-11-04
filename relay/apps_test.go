package relay

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type appEnv struct {
	dir     string
	ca      string
	addr    string
	srv     *Server
	store   *Store
	catalog *Catalog
}

func newAppRelay(t *testing.T) (*appEnv, func(email string) *testClient, func(id string) *Gateway) {
	t.Helper()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca")
	if err := InitCA(ca); err != nil {
		t.Fatal(err)
	}
	IssueServer(ca, filepath.Join(dir, "srv"), []string{"127.0.0.1"})
	cfg, err := TLSConfig(filepath.Join(dir, "srv", "server.pem"), filepath.Join(dir, "srv", "server-key.pem"), filepath.Join(ca, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	store, _ := NewStore("") // no file: sessions end after the test and would write into a removed directory
	srv := NewServer(store)
	cat := NewCatalog()
	srv.AttachCatalog(cat)
	go srv.Serve(ln)
	pool, _ := LoadPool(filepath.Join(ca, "ca.pem"))
	env := &appEnv{dir: dir, ca: ca, addr: ln.Addr().String(), srv: srv, store: store, catalog: cat}

	client := func(email string) *testClient {
		out := filepath.Join(dir, email)
		if err := IssueClient(ca, out, email); err != nil {
			t.Fatal(err)
		}
		cert, err := tls.LoadX509KeyPair(filepath.Join(out, "client.pem"), filepath.Join(out, "client-key.pem"))
		if err != nil {
			t.Fatal(err)
		}
		return connectTestClient(t, env.addr, pool, cert, email, "laptop")
	}
	gateway := func(id string) *Gateway {
		out := filepath.Join(dir, "gw-"+id)
		if err := IssueGateway(ca, out, id); err != nil {
			t.Fatal(err)
		}
		g, err := NewGateway(GatewayConfig{
			Address: env.addr, CertFile: filepath.Join(out, "gateway.pem"), KeyFile: filepath.Join(out, "gateway-key.pem"),
			CAFile: filepath.Join(out, "ca.pem"), Logger: nil,
		})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		go g.Run(ctx)
		return g
	}
	return env, client, gateway
}

func echoBackend(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return ln.Addr().String()
}

func dialApp(t *testing.T, c *testClient, app string) (net.Conn, *bufio.Reader, DialResp) {
	t.Helper()
	st, err := c.ys.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	WriteLine(st, DialReq{T: TDial, App: app})
	br := NewReader(st)
	var resp DialResp
	st.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err := ReadLine(br, &resp); err != nil {
		t.Fatalf("dial %s: %v", app, err)
	}
	st.SetReadDeadline(time.Time{})
	return st, br, resp
}

func TestApplicationsEndToEnd(t *testing.T) {
	env, client, gateway := newAppRelay(t)
	backend := echoBackend(t)
	httpBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "sid=1; Domain=backend.internal; Path=/")
		if r.URL.Path == "/redir" {
			http.Redirect(w, r, "http://"+r.Host+"/landing", http.StatusFound)
			return
		}
		io.WriteString(w, "host="+r.Host+" hdr="+r.Header.Get("X-Remote-User")+" origin="+r.Header.Get("Origin"))
	}))
	defer httpBackend.Close()

	if err := env.catalog.Set([]App{
		{ID: "echo", Name: "Echo", Host: "echo.apps", Kind: "tcp", Gateway: "g1", Target: backend, Emails: []string{"alice@example.com"}},
		{ID: "crm", Name: "CRM", Description: "Customers", Host: "crm.apps", Kind: "http", Gateway: "g1", Target: httpBackend.URL,
			Groups: []string{"sales"}, SetHeaders: map[string]string{"X-Remote-User": "gateway"}},
		{ID: "hr", Name: "HR", Host: "hr.apps", Kind: "tcp", Gateway: "g2", Target: backend, Everyone: true},
		{ID: "closed", Name: "Nobody", Host: "closed.apps", Kind: "tcp", Gateway: "g1", Target: backend},
	}); err != nil {
		t.Fatal(err)
	}
	env.store.SetGroups("bob@example.com", []string{"Sales"})

	alice, bob := client("alice@example.com"), client("bob@example.com")

	// each user is told only about what they may open; nothing about targets
	st := alice.waitState(t, func(s State) bool { return len(s.Apps) == 2 })
	if st.Apps[0].ID != "echo" || st.Apps[1].ID != "hr" || st.Apps[0].Online || st.Apps[1].Online {
		t.Fatalf("alice apps: %+v", st.Apps)
	}
	st = bob.waitState(t, func(s State) bool { return len(s.Apps) == 2 })
	if st.Apps[0].ID != "crm" || st.Apps[0].Description != "Customers" || st.Apps[0].Host != "crm.apps" || st.Apps[1].ID != "hr" {
		t.Fatalf("bob apps: %+v", st.Apps)
	}
	rawB, _ := json.Marshal(st)
	raw := string(rawB)
	if strings.Contains(raw, backend) || strings.Contains(raw, httpBackend.URL) || strings.Contains(raw, "gateway") && strings.Contains(raw, "g1") {
		t.Fatalf("the state leaks where applications are: %s", raw)
	}

	// no gateway yet: the application is unavailable, with a clear message
	_, _, resp := dialApp(t, alice, "echo")
	if resp.OK || !strings.Contains(resp.Error, "not available") {
		t.Fatalf("offline gateway: %+v", resp)
	}

	g1 := gateway("g1")
	waitFor(t, func() bool { return len(g1.Apps()) == 3 })
	// users see that it is online now
	alice.waitState(t, func(s State) bool { return len(s.Apps) == 2 && s.Apps[0].Online && !s.Apps[1].Online })

	// tcp application: bytes reach the backend the catalog names
	conn, br, resp := dialApp(t, alice, "echo")
	if !resp.OK {
		t.Fatalf("open echo: %+v", resp)
	}
	io.WriteString(conn, "hello")
	buf := make([]byte, 5)
	if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("echo: %q %v", buf, err)
	}
	conn.Close()

	// an application the user may not open looks exactly like one that does not exist
	_, _, denied := dialApp(t, alice, "crm")
	_, _, missing := dialApp(t, alice, "nothing")
	_, _, closed := dialApp(t, alice, "closed")
	if denied.OK || denied.Error != missing.Error || closed.Error != missing.Error {
		t.Fatalf("denied=%+v missing=%+v closed=%+v", denied, missing, closed)
	}
	// the group comes from the identity, case-insensitively
	conn, br, resp = dialApp(t, bob, "crm")
	if !resp.OK {
		t.Fatalf("open crm: %+v", resp)
	}
	io.WriteString(conn, "GET /x HTTP/1.1\r\nHost: crm.apps\r\nOrigin: http://crm.apps\r\nConnection: close\r\n\r\n")
	body, _ := io.ReadAll(br)
	text := string(body)
	if !strings.Contains(text, "host="+strings.TrimPrefix(httpBackend.URL, "http://")) || !strings.Contains(text, "hdr=gateway") ||
		!strings.Contains(text, "origin="+httpBackend.URL) {
		t.Fatalf("reverse proxy: %s", text)
	}
	if strings.Contains(strings.ToLower(text), "domain=") {
		t.Fatalf("cookie domain was not stripped: %s", text)
	}
	conn.Close()
	// redirects stay on the name the user knows
	conn, br, _ = dialApp(t, bob, "crm")
	io.WriteString(conn, "GET /redir HTTP/1.1\r\nHost: crm.apps\r\nConnection: close\r\n\r\n")
	body, _ = io.ReadAll(br)
	if !strings.Contains(string(body), "Location: http://crm.apps/landing") {
		t.Fatalf("redirect: %s", body)
	}
	conn.Close()

	// removing a user from the list closes the door at once, and the user's
	// catalog follows
	apps := env.catalog.Apps()
	for i := range apps {
		if apps[i].ID == "echo" {
			apps[i].Emails = []string{"carol@example.com"}
		}
	}
	if err := env.catalog.Set(apps); err != nil {
		t.Fatal(err)
	}
	alice.waitState(t, func(s State) bool { return len(s.Apps) == 1 && s.Apps[0].ID == "hr" })
	if _, _, r := dialApp(t, alice, "echo"); r.OK {
		t.Fatal("alice still opens echo")
	}

	// a backend that is down is reported without saying where it is
	if err := env.catalog.Set(append(env.catalog.Apps(), App{ID: "dead", Name: "Dead", Host: "dead.apps", Gateway: "g1", Target: "127.0.0.1:1", Everyone: true})); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(g1.Apps()) == 3 })
	_, _, r := dialApp(t, alice, "dead")
	if r.OK || strings.Contains(r.Error, "127.0.0.1") || !strings.Contains(r.Error, "cannot be reached") {
		t.Fatalf("dead backend: %+v", r)
	}

	// the second gateway comes and goes
	g2 := gateway("g2")
	waitFor(t, func() bool { return len(g2.Apps()) == 1 })
	conn, br, resp = dialApp(t, alice, "hr")
	if !resp.OK {
		t.Fatalf("hr: %+v", resp)
	}
	conn.Close()
	_ = br
	if !env.srv.KickGateway("g2") {
		t.Fatal("kick gateway")
	}
	waitFor(t, func() bool { return len(env.srv.OnlineGateways()) == 1 })
}

func TestGatewayCertificatesCannotBeUsedAsUsersAndViceVersa(t *testing.T) {
	env, client, gateway := newAppRelay(t)
	gateway("g1")
	waitFor(t, func() bool { return len(env.srv.OnlineGateways()) == 1 })

	// a gateway cannot ask for applications or contacts: it is not a user
	out := filepath.Join(env.dir, "gw-g1")
	cert, _ := tls.LoadX509KeyPair(filepath.Join(out, "gateway.pem"), filepath.Join(out, "gateway-key.pem"))
	pool, _ := LoadPool(filepath.Join(out, "ca.pem"))
	if c := connectTestClient(t, env.addr, pool, cert, "x@example.com", "dev"); c != nil {
		st, _ := c.ys.OpenStream()
		WriteLine(st, DialReq{T: TDial, App: "anything"})
		var resp DialResp
		st.SetReadDeadline(time.Now().Add(2 * time.Second))
		if err := ReadLine(NewReader(st), &resp); err == nil && resp.OK {
			t.Fatal("a gateway opened an application")
		}
	}
	// a user certificate is not a gateway, whatever it claims
	alice := client("alice@example.com")
	alice.waitState(t, func(s State) bool { return s.Email == "alice@example.com" })
	if len(env.srv.OnlineGateways()) != 1 {
		t.Fatalf("gateways: %v", env.srv.OnlineGateways())
	}
	// enrollment never puts a gateway identity in a certificate
	if _, ok := GatewayFromCert(parseCert(t, string(mustSign(t, env.ca, "alice@example.com")))); ok {
		t.Fatal("a user certificate carries a gateway identity")
	}
	if _, err := NewGatewayCredentials(env.ca, "Bad Id", time.Hour); err == nil {
		t.Fatal("invalid gateway id")
	}
}

func mustSign(t *testing.T, caDir, email string) []byte {
	t.Helper()
	csr, _ := testCSR(t, email)
	b, err := SignCSR(caDir, csr, email, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRevokedGatewayIsRefused(t *testing.T) {
	env, _, _ := newAppRelay(t)
	creds, err := NewGatewayCredentials(env.ca, "g9", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rev := NewRevocations(filepath.Join(env.dir, "rev.txt"))
	env.srv.Revoked = rev
	if err := rev.Add("serial:" + creds.Serial); err != nil {
		t.Fatal(err)
	}
	cert, _ := tls.X509KeyPair(creds.CertPEM, creds.KeyPEM)
	pool, _ := LoadPool(filepath.Join(env.ca, "ca.pem"))
	c, err := tls.Dial("tcp", env.addr, &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool})
	if err == nil {
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Fatal("a revoked gateway was served")
		}
		c.Close()
	}
	if len(env.srv.OnlineGateways()) != 0 {
		t.Fatal("revoked gateway registered")
	}
}

func TestCatalogValidation(t *testing.T) {
	ok := App{ID: "a", Name: "A", Host: "a.apps", Gateway: "g", Target: "10.0.0.1:80", Everyone: true}
	cases := map[string]func(a *App){
		"bad id":          func(a *App) { a.ID = "A B" },
		"no name":         func(a *App) { a.Name = " " },
		"ip as host":      func(a *App) { a.Host = "10.0.0.1" },
		"host with path":  func(a *App) { a.Host = "a.apps/x" },
		"bad kind":        func(a *App) { a.Kind = "ftp" },
		"bad gateway":     func(a *App) { a.Gateway = "G W" },
		"tcp no port":     func(a *App) { a.Target = "10.0.0.1" },
		"http bad scheme": func(a *App) { a.Kind, a.Target = "http", "ftp://x" },
		"http creds":      func(a *App) { a.Kind, a.Target = "http", "http://u:p@x" },
		"bad email":       func(a *App) { a.Emails = []string{"nope"} },
		"header injection": func(a *App) {
			a.Kind, a.Target, a.SetHeaders = "http", "http://x", map[string]string{"X": "a\r\nSet-Cookie: b"}
		},
		"host header":    func(a *App) { a.Kind, a.Target, a.SetHeaders = "http", "http://x", map[string]string{"Host": "evil"} },
		"headers on tcp": func(a *App) { a.SetHeaders = map[string]string{"X": "y"} },
	}
	for name, mod := range cases {
		a := ok
		mod(&a)
		if err := a.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	dup := ok
	dup.ID = "b"
	if err := ValidateApps([]App{ok, dup}); err == nil {
		t.Fatal("two applications on one host")
	}
	dup.Host = "b.apps"
	dup.ID = "a"
	if err := ValidateApps([]App{ok, dup}); err == nil {
		t.Fatal("duplicate id")
	}
	// nobody by default
	none := ok
	none.Everyone = false
	if none.Allows("x@example.com", []string{"any"}) {
		t.Fatal("an application with no access rule is open")
	}
	off := ok
	off.Disabled = true
	if off.Allows("x@example.com", nil) {
		t.Fatal("disabled application is open")
	}
}

func TestCatalogFileIsWatched(t *testing.T) {
	path := filepath.Join(t.TempDir(), "apps.yaml")
	write := func(s string) {
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("apps:\n  - id: a\n    name: A\n    host: a.apps\n    gateway: g\n    target: 10.0.0.1:80\n    everyone: true\n")
	c, err := LoadCatalogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if len(c.Apps()) != 1 || !c.ReadOnly() {
		t.Fatalf("apps: %+v", c.Apps())
	}
	if err := c.Set(nil); err == nil {
		t.Fatal("a file catalog must not be edited through Set")
	}
	changed := make(chan struct{}, 1)
	c.OnChange(func() { changed <- struct{}{} })
	// a broken file keeps what was there
	write("apps:\n  - id: a\n    nme: oops\n")
	c.reload()
	if len(c.Apps()) != 1 {
		t.Fatal("a broken file replaced the catalog")
	}
	time.Sleep(10 * time.Millisecond)
	write("apps:\n  - id: a\n    name: A\n    host: a.apps\n    gateway: g\n    target: 10.0.0.1:80\n    everyone: true\n  - id: b\n    name: B\n    host: b.apps\n    gateway: g\n    target: 10.0.0.2:80\n    everyone: true\n")
	if changed2, err := c.reload(); err != nil || !changed2 {
		t.Fatalf("reload: %v %v", changed2, err)
	}
	select {
	case <-changed:
	case <-time.After(time.Second):
		t.Fatal("no change notification")
	}
	if len(c.Apps()) != 2 {
		t.Fatalf("apps: %+v", c.Apps())
	}
	if _, err := LoadCatalogFile(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("missing file")
	}
}

func TestGroupsAreRememberedFromSignIn(t *testing.T) {
	st := mustStore(t)
	st.SetGroups("a@example.com", []string{"b", "a"})
	if g := st.Groups("a@example.com"); len(g) != 2 || g[0] != "a" {
		t.Fatalf("groups: %v", g)
	}
	// persisted
	path := filepath.Join(t.TempDir(), "s.json")
	s1, _ := NewStore(path)
	s1.SetGroups("a@example.com", []string{"x"})
	s2, _ := NewStore(path)
	if g := s2.Groups("a@example.com"); len(g) != 1 || g[0] != "x" {
		t.Fatalf("after reload: %v", g)
	}
}
