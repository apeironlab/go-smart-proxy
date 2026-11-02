package main

import (
	"crypto/tls"
	"io"
	"net"
	"os"
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

func TestRelayRouteStopsAtRelayHop(t *testing.T) {
	resetEnv(t, nil, []ConfigRoute{
		{Name: "via bob", Chain: []ConfigHop{{ProxyUrl: "relay://bob@example.com"}}},
		{Name: "corp only", ProxyUrl: "http://127.0.0.1:1", RulesOnly: true},
	})
	t.Cleanup(func() { setForceRoute(nil) })

	r := &relayClient{cfg: &RelayConfig{}}

	// Auto (no forced route): the relay route is selected, but its chain stops
	// at the relay hop. Nothing comes before it, so the connection is direct.
	route, err := r.relayRoute()
	if err != nil {
		t.Fatal(err)
	}
	if route.name != "Direct" || len(route.chain) != 0 {
		t.Fatalf("auto route = %q (%v), want direct", route.name, chainStrings(route.chain))
	}

	// Same when the relay route is explicitly forced (e.g. from the tray menu).
	setForceRoute(getRoutes()[0])
	route, err = r.relayRoute()
	if err != nil {
		t.Fatal(err)
	}
	if route.name != "Direct" || len(route.chain) != 0 {
		t.Fatalf("forced route = %q (%v), want direct", route.name, chainStrings(route.chain))
	}

	// Naming a relay route in Relay.Route must not prevent the connection: the
	// relay hop is where the chain stops.
	r.cfg.Route = "via bob"
	route, err = r.relayRoute()
	if err != nil {
		t.Fatal(err)
	}
	if route.name != "Direct" || len(route.chain) != 0 {
		t.Fatalf("Relay.Route = %q (%v), want direct", route.name, chainStrings(route.chain))
	}
}

func TestRelayRouteUsesHopsBeforeRelay(t *testing.T) {
	resetEnv(t, nil, []ConfigRoute{
		{Name: "proxy then relay", Chain: []ConfigHop{
			{ProxyUrl: "http://127.0.0.1:1"},
			{ProxyUrl: "relay://bob@example.com"},
		}},
	})
	t.Cleanup(func() { setForceRoute(nil) })

	r := &relayClient{cfg: &RelayConfig{Route: "proxy then relay"}}
	route, err := r.relayRoute()
	if err != nil {
		t.Fatal(err)
	}
	if got := chainStrings(route.chain); len(got) != 1 || got[0] != "http://127.0.0.1:1" {
		t.Fatalf("route chain = %v, want only the proxy before the relay", got)
	}

	// More than one relay hop in a chain is meaningless.
	if _, err := buildChain([]ConfigHop{
		{ProxyUrl: "relay://bob@example.com"},
		{ProxyUrl: "relay://alice@example.com"},
	}); err == nil {
		t.Fatal("a chain with two relay hops must be rejected")
	}
}

func TestRelayRouteStopsAtRulesOnlyHop(t *testing.T) {
	resetEnv(t, nil, []ConfigRoute{
		{Name: "only rules proxy", Chain: []ConfigHop{
			{ProxyUrl: "http://127.0.0.1:1"},
			{ProxyUrl: "http://127.0.0.1:2", RulesOnly: true},
			{ProxyUrl: "relay://bob@example.com"},
		}},
	})

	r := &relayClient{cfg: &RelayConfig{Route: "only rules proxy"}}
	route, err := r.relayRoute()
	if err != nil {
		t.Fatal(err)
	}
	// The relay connection is not selected by a rule, so the chain stops
	// before the RulesOnly hop.
	if got := chainStrings(route.chain); len(got) != 1 || got[0] != "http://127.0.0.1:1" {
		t.Fatalf("relay route chain = %v, want only the proxy before the RulesOnly hop", got)
	}
}

func TestRelayApprovalIsPerDevice(t *testing.T) {
	r := &relayClient{rules: []relayRule{{
		ID: 1, From: "alice@example.com", FromDevice: "laptop", Host: "10.0.0.1", Port: 443,
	}}}
	if !r.ruleAllowsLocked("alice@example.com", "laptop", "10.0.0.1", 443) {
		t.Fatal("the approved device must reuse the rule")
	}
	if r.ruleAllowsLocked("alice@example.com", "desktop", "10.0.0.1", 443) {
		t.Fatal("another device of the same user must require a new approval")
	}
	if r.ruleAllowsLocked("alice@example.com", "laptop", "10.0.0.1", 80) {
		t.Fatal("a different port must require a new approval")
	}
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

	resetEnv(t, nil, nil) // only the "Direct" route
	caPEM, err := os.ReadFile(filepath.Join(ca, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	mk := func(email string, allowLocal bool) *relayClient {
		certPEM, err := os.ReadFile(filepath.Join(dir, email, "client.pem"))
		if err != nil {
			t.Fatal(err)
		}
		keyPEM, err := os.ReadFile(filepath.Join(dir, email, "client-key.pem"))
		if err != nil {
			t.Fatal(err)
		}
		c := &relayClient{approvals: map[int64]*relayApproval{}, file: filepath.Join(dir, email+".json")}
		c.start(&RelayConfig{
			Address:    ln.Addr().String(),
			CertPEM:    string(certPEM),
			KeyPEM:     string(keyPEM),
			CAPEM:      string(caPEM),
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
