package main

import (
	"crypto/tls"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"proxy/relay"
)

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func TestRelayRouteEndToEnd(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca")
	if err := relay.InitCA(ca); err != nil {
		t.Fatal(err)
	}
	if err := relay.IssueServer(ca, filepath.Join(dir, "srv"), []string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	for _, e := range []string{"alice@example.com", "bob@example.com"} {
		if err := relay.IssueClient(ca, filepath.Join(dir, e), e); err != nil {
			t.Fatal(err)
		}
	}
	tlsCfg, err := relay.TLSConfig(filepath.Join(dir, "srv", "server.pem"), filepath.Join(dir, "srv", "server-key.pem"), filepath.Join(ca, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	store, _ := relay.NewStore("")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go relay.NewServer(store).Serve(ln)

	// the site bob will reach
	echo, _ := net.Listen("tcp", "127.0.0.1:0")
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()

	loadRoutes() // only the "Direct" route
	mk := func(email string, allowLocal bool) *relayClient {
		c := &relayClient{approvals: map[int64]*relayApproval{}, file: filepath.Join(dir, email+".json")}
		c.start(&RelayConfig{
			Address:    ln.Addr().String(),
			Cert:       filepath.Join(dir, email, "client.pem"),
			Key:        filepath.Join(dir, email, "client-key.pem"),
			CA:         filepath.Join(ca, "ca.pem"),
			AllowLocal: allowLocal,
		})
		return c
	}
	alice, bob := mk("alice@example.com", false), mk("bob@example.com", true)
	waitFor(t, "clients connected", func() bool { return alice.Status().Connected && bob.Status().Connected })

	// contact request and approval
	if err := alice.send(relay.ClientMsg{T: relay.TContactRequest, Email: "bob@example.com"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "incoming request", func() bool { return len(bob.Status().Incoming) == 1 })
	bob.send(relay.ClientMsg{T: relay.TContactRespond, Email: "alice@example.com", Accept: true})
	waitFor(t, "contacts", func() bool { return len(alice.Status().Contacts) == 1 && len(bob.Status().Contacts) == 1 })

	// a route through bob: first request needs bob's approval
	relayMgr = alice
	chain, err := buildChain([]ConfigHop{{ProxyUrl: "relay://bob@example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	route := &ProxyRoute{name: "via bob", chain: chain}
	target := echo.Addr().String()

	go func() {
		waitFor(t, "pending approval", func() bool { return len(bob.Status().Approvals) == 1 })
		a := bob.Status().Approvals[0]
		bob.Decide(a.ID, relayDecision{Allow: true, Always: true})
	}()
	rec := connReg.newConn("tunnel", "", "", target, "", "t", "", "", "")
	conn, br, err := dialChain(route, target, rec)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(conn, "hello")
	buf := make([]byte, 5)
	if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("got %q err=%v", buf, err)
	}
	conn.Close()

	// the approval was remembered: no prompt this time
	conn, _, err = dialChain(route, target, connReg.newConn("tunnel", "", "", target, "", "t", "", "", ""))
	if err != nil {
		t.Fatalf("approved route should not ask again: %v", err)
	}
	conn.Close()
	if len(bob.Status().Rules) != 1 {
		t.Fatalf("expected one remembered rule, got %+v", bob.Status().Rules)
	}

	// another destination is a new route: denied
	go func() {
		waitFor(t, "pending approval", func() bool { return len(bob.Status().Approvals) == 1 })
		bob.Decide(bob.Status().Approvals[0].ID, relayDecision{Allow: false})
	}()
	if _, _, err := dialChain(route, "10.9.9.9:80", connReg.newConn("tunnel", "", "", "10.9.9.9:80", "", "t", "", "", "")); err == nil {
		t.Fatal("a denied route must fail")
	}
}
