package relay

import (
	"bufio"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// metric reads one sample from the text a handler serves ("" labels: none).
func metric(t *testing.T, h http.Handler, name, labels string) float64 {
	t.Helper()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	want := name
	if labels != "" {
		want += "{" + labels + "}"
	}
	sc := bufio.NewScanner(rr.Body)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, want+" ") {
			v, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimPrefix(line, want)), 64)
			if err != nil {
				t.Fatalf("%q: %v", line, err)
			}
			return v
		}
	}
	return 0
}

func TestMetricsFormatAndAuth(t *testing.T) {
	env, _, _ := newAppRelay(t)
	o := &Observer{Server: env.srv, Token: "s3cret", Version: "test"}
	h := o.Handler()

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	if rr.Code != 401 || rr.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("no token: %d", rr.Code)
	}
	req := httptest.NewRequest("GET", "/metrics", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 401 {
		t.Fatalf("wrong token: %d", rr.Code)
	}
	req.Header.Set("Authorization", "Bearer s3cret")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	body := rr.Body.String()
	if rr.Code != 200 || !strings.HasPrefix(rr.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("with token: %d %s", rr.Code, rr.Header())
	}
	for _, want := range []string{
		"# TYPE gsp_relay_devices_online gauge", "gsp_relay_devices_online 0", "gsp_relay_users_online 0", "gsp_relay_gateways_online 0",
		`gsp_relay_build_info{version="test",go="go`, "gsp_relay_ready 1", "gsp_relay_applications 0", "go_goroutines ",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in:\n%s", want, body)
		}
	}
	// no private data in the metrics: no e-mail addresses
	if strings.Contains(body, "@") {
		t.Fatalf("an address in the metrics:\n%s", body)
	}
}

func TestHealthAndReadiness(t *testing.T) {
	srv := NewServer(mustStore(t))
	o := &Observer{Server: srv}
	h := o.Handler()
	get := func(path string) (int, string) {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("GET", path, nil))
		b, _ := io.ReadAll(rr.Body)
		return rr.Code, string(b)
	}
	if code, _ := get("/healthz"); code != 200 {
		t.Fatalf("healthz: %d", code)
	}
	// alive, but not listening yet: not ready
	if code, body := get("/readyz"); code != 503 || !strings.Contains(body, "not ready") {
		t.Fatalf("readyz before serving: %d %s", code, body)
	}
	if metric(t, h, "gsp_relay_ready", "") != 0 {
		t.Fatal("the ready gauge says ready")
	}
	env, _, _ := newAppRelay(t)
	o2 := &Observer{Server: env.srv}
	rr := httptest.NewRecorder()
	waitFor(t, func() bool { return env.srv.Serving() })
	o2.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/readyz", nil))
	if rr.Code != 200 {
		t.Fatalf("readyz while serving: %d %s", rr.Code, rr.Body.String())
	}
	// a database that is gone makes it unready
	f := newAdminFixture(t, adminOpts{})
	o3 := &Observer{Server: env.srv, Admin: f.admin}
	if err := o3.Ready(); err != nil {
		t.Fatal(err)
	}
	f.admin.Close()
	if err := o3.Ready(); err == nil {
		t.Fatal("ready with a closed database")
	}
}

func TestEventsAreCountedAndLogged(t *testing.T) {
	var mu sync.Mutex
	var got []string
	SetEventLogger(func(kind, actor, subject, detail string) {
		mu.Lock()
		got = append(got, kind+"|"+actor+"|"+subject+"|"+detail)
		mu.Unlock()
	})
	t.Cleanup(func() { SetEventLogger(nil) })

	f := newAdminFixture(t, adminOpts{})
	o := &Observer{Enroll: f.es, Admin: f.admin}
	h := o.Handler()
	before := metric(t, h, "gsp_relay_events_total", `kind="admin.login"`)
	issuedBefore := metric(t, h, "gsp_relay_events_total", `kind="enroll.issued"`)
	b := f.loggedIn(t)
	b.send("POST", "/admin/api/local-users", map[string]any{"username": "bob", "password": "bobs long password", "email": "bob@example.com"}, nil, 200)
	enrollAs(t, f, "bob", "bobs long password", "bob@example.com")

	if d := metric(t, h, "gsp_relay_events_total", `kind="admin.login"`) - before; d != 1 {
		t.Fatalf("admin.login counted %v times", d)
	}
	if d := metric(t, h, "gsp_relay_events_total", `kind="enroll.issued"`) - issuedBefore; d != 1 {
		t.Fatalf("enroll.issued counted %v times", d)
	}
	if metric(t, h, "gsp_relay_certificates_active", "") != 1 {
		t.Fatal("active certificates")
	}
	mu.Lock()
	defer mu.Unlock()
	n := 0
	for _, e := range got {
		if strings.HasPrefix(e, "admin.login|root@example.com|local") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("the event logger saw the sign-in %d times: %v", n, got)
	}
}

func TestDialsAndConnectionsAreCounted(t *testing.T) {
	env, client, gateway := newAppRelay(t)
	h := (&Observer{Server: env.srv}).Handler()
	backend := echoBackend(t)
	env.catalog.Set([]App{{ID: "echo", Name: "Echo", Host: "echo.apps", Gateway: "g1", Target: backend, Everyone: true}})
	gateway("g1")
	waitFor(t, func() bool { return len(env.srv.OnlineGateways()) == 1 })
	alice := client("alice@example.com")
	alice.waitState(t, func(s State) bool { return len(s.Apps) == 1 })

	okBefore := metric(t, h, "gsp_relay_dials_total", `kind="app",result="ok"`)
	deniedBefore := metric(t, h, "gsp_relay_dials_total", `kind="app",result="denied"`)
	failedBefore := metric(t, h, "gsp_relay_dials_total", `kind="app",result="failed"`)
	conn, _, resp := dialApp(t, alice, "echo")
	if !resp.OK {
		t.Fatal(resp)
	}
	conn.Close()
	if d := metric(t, h, "gsp_relay_dials_total", `kind="app",result="ok"`) - okBefore; d != 1 {
		t.Fatalf("ok dials: %v", d)
	}
	env.catalog.Set([]App{{ID: "echo", Name: "Echo", Host: "echo.apps", Gateway: "g1", Target: backend, Emails: []string{"nobody@example.com"}}})
	dialApp(t, alice, "echo")
	if d := metric(t, h, "gsp_relay_dials_total", `kind="app",result="denied"`) - deniedBefore; d != 1 {
		t.Fatalf("denied dials: %v", d)
	}
	// unknown and forbidden look alike, to the user and in the numbers
	dialApp(t, alice, "nonexistent")
	if d := metric(t, h, "gsp_relay_dials_total", `kind="app",result="denied"`) - deniedBefore; d != 2 {
		t.Fatalf("denied dials: %v", d)
	}
	if v := metric(t, h, "gsp_relay_gateways_online", ""); v != 1 {
		t.Fatalf("gateways online: %v", v)
	}
	// a gateway that is away is a failure
	env.srv.KickGateway("g1")
	waitFor(t, func() bool { return len(env.srv.OnlineGateways()) == 0 })
	env.catalog.Set([]App{{ID: "echo", Name: "Echo", Host: "echo.apps", Gateway: "g1", Target: backend, Everyone: true}})
	dialApp(t, alice, "echo")
	if d := metric(t, h, "gsp_relay_dials_total", `kind="app",result="failed"`) - failedBefore; d != 1 {
		t.Fatalf("failed dials: %v", d)
	}
	if v := metric(t, h, "gsp_relay_devices_online", ""); v != 1 {
		t.Fatalf("devices online: %v", v)
	}
	if v := metric(t, h, "gsp_relay_users_online", ""); v != 1 {
		t.Fatalf("users online: %v", v)
	}
}

func TestLabelEscaping(t *testing.T) {
	CounterInc("gsp_test_total", "x", "a\"b\\c\nd")
	rr := httptest.NewRecorder()
	writeCounters(rr)
	if !strings.Contains(rr.Body.String(), `gsp_test_total{x="a\"b\\c\nd"} 1`) {
		t.Fatalf("labels not escaped:\n%s", rr.Body.String())
	}
}
