package blocklist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func parse(t *testing.T, f Format, s string) ([]string, []netip.Prefix) {
	t.Helper()
	d, n, err := Parse(strings.NewReader(s), f)
	if err != nil {
		t.Fatal(err)
	}
	return d, n
}

func TestParseHostsFile(t *testing.T) {
	d, n := parse(t, Hosts, `# comment
127.0.0.1 localhost
::1 localhost ip6-localhost
0.0.0.0 0.0.0.0
0.0.0.0 ads.example.com tracker.example.net # trailing comment
0.0.0.0 ADS.Example.com.
0.0.0.0 bad_host!.com
not-an-address foo.com
0.0.0.0
`)
	if len(n) != 0 {
		t.Fatalf("nets: %v", n)
	}
	want := []string{"ads.example.com", "tracker.example.net", "ads.example.com"}
	if strings.Join(d, ",") != strings.Join(want, ",") {
		t.Fatalf("domains: %v", d)
	}
}

func TestParseDomainsAndNetworks(t *testing.T) {
	d, n := parse(t, Domains, "example.com\n*.wild.example.org\n.dot.example.org\nEXAMPLE.net # c\n10.1.2.3\n192.0.2.0/24\n2001:db8::/32\nbad domain.com\n-bad.com\nbad-.com\n..x\n")
	if strings.Join(d, ",") != "example.com,wild.example.org,dot.example.org,example.net" {
		t.Fatalf("domains: %v", d)
	}
	if len(n) != 3 || n[0].String() != "10.1.2.3/32" || n[1].String() != "192.0.2.0/24" || n[2].String() != "2001:db8::/32" {
		t.Fatalf("nets: %v", n)
	}
}

func TestParseAdblockKeepsOnlyHostRules(t *testing.T) {
	d, _ := parse(t, ABP, `[Adblock Plus 2.0]
! comment
||ads.example.com^
||tracker.example.net^$third-party
||example.org/banner^
||*.wild.example.com^
@@||allowed.example.com^
example.com##.ad
||cosmetic.example.com^##.x
|http://x.example.com
||ok.example.io^$important
`)
	if strings.Join(d, ",") != "ads.example.com,tracker.example.net,ok.example.io" {
		t.Fatalf("domains: %v", d)
	}
}

func TestAutoDetectsEachLine(t *testing.T) {
	d, n := parse(t, Auto, "||a.example.com^\n0.0.0.0 b.example.com\nc.example.com\n198.51.100.7\n")
	if strings.Join(d, ",") != "a.example.com,b.example.com,c.example.com" || len(n) != 1 {
		t.Fatalf("%v %v", d, n)
	}
}

func TestParseRefusesHugeListsAndUnknownFormat(t *testing.T) {
	if _, _, err := Parse(strings.NewReader("a.com"), Format("nope")); err == nil {
		t.Fatal("unknown format")
	}
	old := strings.Repeat("a.example.com\n", 10)
	if _, _, err := Parse(strings.NewReader(old), ""); err != nil {
		t.Fatal(err)
	}
}

func build(src string, domains []string, nets ...string) *Matcher {
	b := NewBuilder()
	var ps []netip.Prefix
	for _, n := range nets {
		ps = append(ps, netip.MustParsePrefix(n))
	}
	b.Add(src, domains, ps)
	return b.Build()
}

func TestMatcherBlocksSubdomainsNotSiblings(t *testing.T) {
	m := build("ads", []string{"example.com", "tracker.net"}, "10.0.0.0/8", "2001:db8::/32")
	blocked := []string{"example.com", "EXAMPLE.com.", "www.example.com", "a.b.example.com:443", "tracker.net", "10.1.2.3", "[2001:db8::1]:443", "::ffff:10.1.2.3"}
	for _, h := range blocked {
		if hit, ok := m.Match(h); !ok || hit.Source != "ads" {
			t.Errorf("%q should be blocked", h)
		}
	}
	for _, h := range []string{"notexample.com", "example.org", "com", "11.0.0.1", "example.com.evil.org", "", "2001:db9::1"} {
		if _, ok := m.Match(h); ok {
			t.Errorf("%q should not be blocked", h)
		}
	}
	if hit, _ := m.Match("x.example.com"); hit.Rule != "example.com" {
		t.Fatalf("hit: %+v", hit)
	}
	var nilm *Matcher
	if _, ok := nilm.Match("example.com"); ok || nilm.Len() != 0 {
		t.Fatal("nil matcher")
	}
}

func TestDecidePrecedence(t *testing.T) {
	mand := build("org", []string{"corp-blocked.com"})
	opt := build("ads", []string{"ads.com", "corp-blocked.com", "both.com"})
	allow := build("me", []string{"ads.com", "corp-blocked.com"})

	// the user's allow list beats an optional list ...
	if d := Decide("ads.com", []*Matcher{mand}, allow, []*Matcher{opt}); d.Blocked {
		t.Fatalf("allowed host blocked: %+v", d)
	}
	// ... but not a mandatory rule
	if d := Decide("corp-blocked.com", []*Matcher{mand}, allow, []*Matcher{opt}); !d.Blocked || !d.Mandatory || d.Hit.Source != "org" {
		t.Fatalf("mandatory rule: %+v", d)
	}
	if d := Decide("both.com", []*Matcher{mand}, allow, []*Matcher{opt}); !d.Blocked || d.Mandatory || d.Hit.Source != "ads" {
		t.Fatalf("optional list: %+v", d)
	}
	if d := Decide("fine.com", []*Matcher{mand}, allow, []*Matcher{opt}); d.Blocked {
		t.Fatalf("unlisted: %+v", d)
	}
	if d := Decide("ads.com", nil, nil, nil); d.Blocked {
		t.Fatal("no layers")
	}
}

func TestFetcherUpdatesCachesAndKeepsGoodCopy(t *testing.T) {
	var hits, notModified atomic.Int32
	body := "0.0.0.0 ads.example.com\n0.0.0.0 evil.example.net\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/list":
			if r.Header.Get("If-None-Match") == `"v1"` {
				notModified.Add(1)
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"v1"`)
			w.Write([]byte(body))
		case "/empty":
			w.Write([]byte("# nothing\n"))
		case "/redirect":
			http.Redirect(w, r, "file:///etc/passwd", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	f := &Fetcher{Dir: t.TempDir()}
	s := Source{ID: "a", Name: "ads", URL: srv.URL + "/list", Format: Hosts}

	if changed, err := f.Update(context.Background(), s); err != nil || !changed {
		t.Fatalf("first update: %v %v", changed, err)
	}
	d, _, fetched, err := f.Load(s)
	if err != nil || len(d) != 2 || fetched.IsZero() {
		t.Fatalf("load: %v %v %v", d, fetched, err)
	}
	// the second time the server says nothing changed
	if changed, err := f.Update(context.Background(), s); err != nil || changed || notModified.Load() != 1 {
		t.Fatalf("second update: %v %v %d", changed, err, notModified.Load())
	}
	// a broken answer keeps the copy
	bad := s
	bad.URL = srv.URL + "/missing"
	if _, err := f.Update(context.Background(), bad); err == nil {
		t.Fatal("404 accepted")
	}
	empty := Source{URL: srv.URL + "/empty", Format: Hosts}
	if _, err := f.Update(context.Background(), empty); err == nil {
		t.Fatal("a list with nothing usable replaced a cache")
	}
	if _, _, _, err := f.Load(empty); err == nil {
		t.Fatal("an empty list was cached")
	}
	if _, err := f.Update(context.Background(), Source{URL: srv.URL + "/redirect"}); err == nil {
		t.Fatal("redirect to a file followed")
	}
	if d, _, _, err := f.Load(s); err != nil || len(d) != 2 {
		t.Fatalf("the good copy was lost: %v %v", d, err)
	}
	f.Remove(s)
	if _, _, _, err := f.Load(s); err == nil {
		t.Fatal("not removed")
	}
}

func TestFetcherRefusesBadAddresses(t *testing.T) {
	for _, u := range []string{"file:///etc/passwd", "ftp://x/y", "http://user:pw@example.com/l", "//example.com", "", "http://"} {
		if CheckURL(u) == nil {
			t.Errorf("%q accepted", u)
		}
	}
	if CheckURL("https://example.com/list.txt") != nil {
		t.Fatal("valid URL refused")
	}
}

func TestFetcherDenyPrivate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("a.example.com\n")) }))
	defer srv.Close() // listens on 127.0.0.1
	s := Source{URL: srv.URL, Format: Domains}
	if _, err := (&Fetcher{Dir: t.TempDir(), DenyPrivate: true}).Update(context.Background(), s); err == nil {
		t.Fatal("a private address was fetched")
	}
	if _, err := (&Fetcher{Dir: t.TempDir()}).Update(context.Background(), s); err != nil {
		t.Fatalf("local fetch without the restriction: %v", err)
	}
}

func TestFetcherSizeLimit(t *testing.T) {
	old := int64(MaxListBytes)
	_ = old
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		line := strings.Repeat("a", 60) + ".example.com\n"
		for i := 0; i < 5; i++ {
			w.Write([]byte(line))
		}
	}))
	defer srv.Close()
	if _, err := (&Fetcher{Dir: t.TempDir()}).Update(context.Background(), Source{URL: srv.URL, Format: Domains}); err != nil {
		t.Fatal(err)
	}
}

func TestFetcherThroughAnEnvironmentProxyOnAPrivateAddress(t *testing.T) {
	// the proxy listens on 127.0.0.1, as a corporate proxy may on a private
	// address: it must stay usable, while the destination is still checked
	var asked atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		w.Write([]byte("a.example.com\n"))
	}))
	defer proxy.Close()
	pu, _ := url.Parse(proxy.URL)
	f := &Fetcher{Dir: t.TempDir(), DenyPrivate: true, Proxy: func(*http.Request) (*url.URL, error) { return pu, nil }}
	if _, err := f.Update(context.Background(), Source{URL: "http://lists.example.org/l", Format: Domains}); err != nil {
		t.Fatalf("through the proxy: %v", err)
	}
	if asked.Load() == 0 {
		t.Fatal("the proxy was not used")
	}
	// a destination that is a private address is refused even through a proxy
	if _, err := f.Update(context.Background(), Source{URL: "http://10.1.2.3/l", Format: Domains}); err == nil {
		t.Fatal("a private destination was requested through the proxy")
	}
}
