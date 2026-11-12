package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func waitPAC(t *testing.T, p *ProxyRoute, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatal("the PAC state did not settle")
}

func TestPACRouteLifecycle(t *testing.T) {
	t.Chdir(t.TempDir()) // the cache directory is relative
	var hits atomic.Int32
	mode := atomic.Value{}
	mode.Store("ok")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch mode.Load().(string) {
		case "ok":
			w.Write([]byte(`function FindProxyForURL(url, host) { if (shExpMatch(host, "*.corp.example")) return "PROXY proxy.corp.example:8080"; if (host == "none.example") return ""; return "DIRECT"; }`))
		case "broken":
			w.Write([]byte(`this is not javascript {{{`))
		default:
			http.Error(w, "gone", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	r, err := newProxyRoute(&ConfigRoute{Name: "pac", Chain: []ConfigHop{{PacUrl: srv.URL + "/proxy.pac"}}})
	if err != nil {
		t.Fatal(err)
	}
	if r.Check() == nil {
		t.Fatal("a PAC that was never fetched is usable")
	}
	waitPAC(t, r, func() bool { r.mu.Lock(); defer r.mu.Unlock(); return r.pac != nil })
	if err := r.Check(); err != nil {
		t.Errorf("Check after the fetch: %v", err)
	}
	if p := r.FindProxy("https://git.corp.example:443/"); p.Type != "PROXY" || p.Address != "proxy.corp.example:8080" {
		t.Errorf("corp host: %+v", p)
	}
	if p := r.FindProxy("https://example.org/"); p.Type != "DIRECT" {
		t.Errorf("other host: %+v", p)
	}
	if p := r.FindProxy("https://none.example/"); p.Type != "DIRECT" {
		t.Errorf("a PAC with no answer: %+v", p)
	}
	info := r.info(getNetState())
	if info.PacStatus != "loaded" || !info.Applicable {
		t.Errorf("info: %+v", info)
	}
	if _, err := os.Stat(r.pacCacheFile()); err != nil {
		t.Errorf("the PAC was not cached: %v", err)
	}

	// a PAC that disappears or breaks: the loaded version stays and the error is shown
	mode.Store("gone")
	r.forceRefreshPAC()
	waitPAC(t, r, func() bool { r.mu.Lock(); defer r.mu.Unlock(); return r.pacError != "" })
	if r.FindProxy("https://git.corp.example/").Type != "PROXY" {
		t.Error("the last good PAC was dropped")
	}
	mode.Store("broken")
	r.mu.Lock()
	r.pacError = ""
	r.mu.Unlock()
	r.forceRefreshPAC()
	waitPAC(t, r, func() bool { r.mu.Lock(); defer r.mu.Unlock(); return r.pacError != "" })
	r.mu.Lock()
	msg := r.pacError
	r.mu.Unlock()
	if strings.Contains(msg, "404") {
		t.Errorf("the second error is still the first: %s", msg)
	}

	// a new route object starts from the cache without waiting for the network
	mode.Store("gone")
	r2, _ := newProxyRoute(&ConfigRoute{Name: "pac", Chain: []ConfigHop{{PacUrl: srv.URL + "/proxy.pac"}}})
	if err := r2.Check(); err != nil {
		t.Errorf("the cache was not used: %v", err)
	}
	// invalidation and refresh are throttled and never block
	r2.invalidatePAC()
	r2.refreshPAC()
	r2.refreshPAC()
	(&ProxyRoute{}).invalidatePAC()
	(&ProxyRoute{}).forceRefreshPAC()

	// a route that never got a PAC reports an error state
	bad, _ := newProxyRoute(&ConfigRoute{Name: "bad", Chain: []ConfigHop{{PacUrl: "http://127.0.0.1:1/p.pac"}}})
	st := bad.info(getNetState())
	if st.Applicable || st.WhyNot == "" {
		t.Errorf("an unavailable PAC is applicable: %+v", st)
	}
	waitPAC(t, bad, func() bool { bad.mu.Lock(); defer bad.mu.Unlock(); return !bad.refreshing && bad.pacError != "" })
	if st := bad.info(getNetState()); (st.PacStatus != "error" && st.PacStatus != "loading") || st.PacError == "" {
		t.Errorf("error state: %+v", st)
	}
}

func TestDirectRouteAndProxyURLs(t *testing.T) {
	d := &ProxyRoute{name: "Direct"}
	if p := d.FindProxy("https://example.org/"); p.Type != "DIRECT" {
		t.Errorf("direct: %+v", p)
	}
	if !d.IsApplicable() {
		t.Error("Direct is always applicable")
	}
	p := &ProxyRoute{name: "legacy", proxyUrl: "http://proxy.example:3128"}
	if got := p.FindProxy("https://example.org/"); got.Address != "proxy.example:3128" {
		t.Errorf("proxyUrl: %+v", got)
	}
	p = &ProxyRoute{name: "bare", proxyUrl: "proxy.example:3128"}
	if got := p.FindProxy("https://example.org/"); got.Address != "proxy.example:3128" {
		t.Errorf("bare proxyUrl: %+v", got)
	}
	if vpnLabel(netAnalysis{}) != "none" || vpnLabel(netAnalysis{VPN: []string{"utun3", "tun0"}}) != "utun3, tun0" {
		t.Error("vpnLabel")
	}
}
