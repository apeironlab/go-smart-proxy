package relay

import (
	"crypto/tls"
	"path/filepath"
	"testing"
	"time"
)

// TestAdminSeesAndDisconnectsLiveSessions uses a real mTLS relay.
func TestAdminSeesAndDisconnectsLiveSessions(t *testing.T) {
	f := newAdminFixture(t, adminOpts{})
	b := f.loggedIn(t)

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
	store, _ := NewStore("")
	srv := NewServer(store)
	srv.Revoked = NewRevocations(f.rev)
	f.admin.SetServer(srv)
	go srv.Serve(ln)
	pool, _ := LoadPool(filepath.Join(ca, "ca.pem"))

	connect := func(email string) *testClient {
		out := filepath.Join(dir, email)
		if err := IssueClient(ca, out, email); err != nil {
			t.Fatal(err)
		}
		cert, err := tls.LoadX509KeyPair(filepath.Join(out, "client.pem"), filepath.Join(out, "client-key.pem"))
		if err != nil {
			t.Fatal(err)
		}
		return connectTestClient(t, ln.Addr().String(), pool, cert, email, "laptop")
	}
	alice := connect("alice@example.com")
	connect("bob@example.com")
	alice.state(t)

	var ov struct {
		Counts map[string]int `json:"counts"`
		Online []OnlineDevice `json:"online"`
	}
	waitFor(t, func() bool { b.get("/admin/api/overview", &ov, 200); return len(ov.Online) == 2 })
	if ov.Counts["devices"] != 2 || ov.Counts["users"] != 2 || ov.Online[0].Email != "alice@example.com" || ov.Online[0].Device != "laptop" || ov.Online[0].Addr == "" {
		t.Fatalf("overview: %+v", ov)
	}
	var users []UserInfo
	b.get("/admin/api/users", &users, 200)
	seen := map[string]int{}
	for _, u := range users {
		seen[u.Email] = u.Devices
	}
	if seen["alice@example.com"] != 1 || seen["bob@example.com"] != 1 {
		t.Fatalf("users: %+v", users)
	}

	// disconnect one user
	b.send("POST", "/admin/api/kick", map[string]string{"email": "alice@example.com"}, nil, 200)
	waitFor(t, func() bool { b.get("/admin/api/overview", &ov, 200); return len(ov.Online) == 1 })
	if ov.Online[0].Email != "bob@example.com" {
		t.Fatalf("online after kick: %+v", ov.Online)
	}

	// revoking an identity cuts the live connection, and a new one is refused
	var out struct {
		Disconnected int `json:"disconnected"`
	}
	b.send("POST", "/admin/api/revoke", map[string]string{"email": "bob@example.com"}, &out, 200)
	if out.Disconnected != 1 {
		t.Fatalf("disconnected %d", out.Disconnected)
	}
	waitFor(t, func() bool { b.get("/admin/api/overview", &ov, 200); return len(ov.Online) == 0 })

	var events []Event
	waitFor(t, func() bool {
		b.get("/admin/api/events?kind=session.&limit=50", &events, 200)
		kinds := map[string]bool{}
		for _, e := range events {
			kinds[e.Kind] = true
		}
		return kinds["session.open"] && kinds["session.close"]
	})
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("condition never met")
}
