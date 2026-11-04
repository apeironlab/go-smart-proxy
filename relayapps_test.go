package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/apeironlab/go-smart-proxy/relay"
)

// startAppRelay is a relay server with a catalog and one connected gateway.
func startAppRelay(t *testing.T, apps []relay.App, users ...string) (*testRelayServer, *relay.Store, *relay.Catalog) {
	t.Helper()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca")
	if err := relay.InitCA(ca); err != nil {
		t.Fatal(err)
	}
	relay.IssueServer(ca, filepath.Join(dir, "srv"), []string{"127.0.0.1"})
	for _, e := range users {
		if err := relay.IssueClient(ca, filepath.Join(dir, e), e); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := relay.TLSConfig(filepath.Join(dir, "srv", "server.pem"), filepath.Join(dir, "srv", "server-key.pem"), filepath.Join(ca, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	store, _ := relay.NewStore("")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	srv := relay.NewServer(store)
	cat := relay.NewCatalog()
	srv.AttachCatalog(cat)
	if err := cat.Set(apps); err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	caPEM, _ := os.ReadFile(filepath.Join(ca, "ca.pem"))

	gw := filepath.Join(dir, "gw")
	if err := relay.IssueGateway(ca, gw, "g1"); err != nil {
		t.Fatal(err)
	}
	g, err := relay.NewGateway(relay.GatewayConfig{
		Address: ln.Addr().String(), CertFile: filepath.Join(gw, "gateway.pem"), KeyFile: filepath.Join(gw, "gateway-key.pem"), CAFile: filepath.Join(gw, "ca.pem"),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go g.Run(ctx)
	waitFor(t, "gateway", func() bool { return len(g.Apps()) > 0 })
	return &testRelayServer{addr: ln.Addr().String(), dir: dir, caPEM: string(caPEM)}, store, cat
}

func TestApplicationsAreRoutedAutomatically(t *testing.T) {
	echo := echoServer(t)
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "crm says hi to "+r.Host) }))
	defer web.Close()
	srv, _, _ := startAppRelay(t, []relay.App{
		{ID: "echo", Name: "Echo", Host: "echo.apps", Gateway: "g1", Target: echo, Everyone: true},
		{ID: "crm", Name: "CRM", Description: "Customers", Host: "crm.apps", Kind: "http", Gateway: "g1", Target: web.URL, Everyone: true},
		{ID: "hidden", Name: "Hidden", Host: "hidden.apps", Gateway: "g1", Target: echo, Emails: []string{"nobody@example.com"}},
	}, "alice@example.com")

	resetEnv(t, nil, nil)
	alice := srv.client(t, "main", "alice@example.com", false)
	relayHub.reset()
	relayHub.put("main", alice)
	t.Cleanup(relayHub.reset)
	waitFor(t, "catalog", func() bool { return len(alice.appInfos()) == 2 })

	// the catalog reaches the UI API, with nothing about where anything is
	rr := httptest.NewRecorder()
	appsHandler(rr, httptest.NewRequest("GET", "/api/apps", nil))
	var list []appJSON
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil || len(list) != 2 {
		t.Fatalf("apps api: %v %s", err, rr.Body.String())
	}
	if list[1].Name != "Echo" && list[0].Name != "Echo" {
		t.Fatalf("list: %+v", list)
	}
	for _, a := range list {
		if a.Name == "CRM" && (a.URL != "http://crm.apps/" || a.Description != "Customers" || a.Relay != "main") {
			t.Fatalf("crm entry: %+v", a)
		}
		if a.Name == "Echo" && a.URL != "" {
			t.Fatalf("tcp application with a URL: %+v", a)
		}
	}
	if strings.Contains(rr.Body.String(), echo) || strings.Contains(rr.Body.String(), web.URL) || strings.Contains(rr.Body.String(), "hidden") {
		t.Fatalf("the API reveals what it should not: %s", rr.Body.String())
	}

	// a connection to the application's host goes there with no route or rule set up,
	// even when another route is forced
	rt, name := routeFor("echo.apps")
	if rt == nil || !strings.HasPrefix(name, "application") {
		t.Fatalf("route for an application: %v %q", rt, name)
	}
	if other, _ := routeFor("example.org"); other == rt {
		t.Fatal("other hosts must not use the application route")
	}
	if r2, _ := routeFor("ECHO.apps."); r2 != rt {
		t.Fatal("host names compare case-insensitively and ignore the final dot")
	}
	conn, br, rec, err := dialTarget("tunnel", "127.0.0.1:1", "echo.apps", "3389", "CONNECT", "")
	if err != nil {
		t.Fatalf("dial application: %v", err)
	}
	io.WriteString(conn, "ping")
	buf := make([]byte, 4)
	if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo through the application: %q %v", buf, err)
	}
	conn.Close()
	_ = rec

	// an application the user cannot open is just another unknown host
	if rt, _ := routeFor("hidden.apps"); rt != nil && strings.HasPrefix(rt.name, "App:") {
		t.Fatal("a route exists for an application the user may not open")
	}

	// plain HTTP through the proxy handler reaches the reverse proxy
	req := httptest.NewRequest("GET", "http://crm.apps/page", nil)
	req.Host = "crm.apps"
	w := httptest.NewRecorder()
	proxyHandler(w, req)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "crm says hi to ") {
		t.Fatalf("http application: %d %s", w.Code, w.Body.String())
	}
}
