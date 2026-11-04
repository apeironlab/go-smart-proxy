package relay

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// both runs a scenario on the file store and on the store in the database.
func bothStores(t *testing.T, fn func(t *testing.T, s *Store)) {
	t.Run("file", func(t *testing.T) {
		s, err := NewStore(filepath.Join(t.TempDir(), "s.json"))
		if err != nil {
			t.Fatal(err)
		}
		fn(t, s)
	})
	t.Run("database", func(t *testing.T) {
		sh, err := OpenShared(testDBAddr(t, t.TempDir()), "ra")
		if err != nil {
			t.Fatal(err)
		}
		defer sh.Close()
		fn(t, NewSharedStore(sh))
	})
}

func TestStoreInTheDatabaseBehavesLikeTheFileStore(t *testing.T) {
	bothStores(t, func(t *testing.T, s *Store) {
		a, b, c := "a@example.com", "b@example.com", "c@example.com"
		if ch, n := s.Request(a, a); ch != nil || !strings.Contains(n, "yourself") {
			t.Fatalf("self request: %v %q", ch, n)
		}
		if ch, n := s.Request(a, b); len(ch) != 2 || n != "" {
			t.Fatalf("request: %v %q", ch, n)
		}
		if ch, n := s.Request(a, b); len(ch) != 1 || !strings.Contains(n, "already sent") {
			t.Fatalf("repeated request: %v %q", ch, n)
		}
		contacts, in, out := s.Snapshot(b)
		if len(contacts) != 0 || len(in) != 1 || in[0] != a || len(out) != 0 {
			t.Fatalf("snapshot of b: %v %v %v", contacts, in, out)
		}
		if _, _, out := s.Snapshot(a); len(out) != 1 || out[0] != b {
			t.Fatalf("snapshot of a: %v", out)
		}
		if s.IsContact(a, b) {
			t.Fatal("contact before approval")
		}
		if ch := s.Respond(b, c, true); ch != nil {
			t.Fatalf("answer to a request nobody made: %v", ch)
		}
		if ch := s.Respond(b, a, true); len(ch) != 2 {
			t.Fatalf("respond: %v", ch)
		}
		if !s.IsContact(a, b) || !s.IsContact(b, a) {
			t.Fatal("contacts are symmetric")
		}
		if _, n := s.Request(a, b); !strings.Contains(n, "already a contact") {
			t.Fatalf("request to a contact: %q", n)
		}
		// mutual intent accepts
		s.Request(a, c)
		if ch, _ := s.Request(c, a); len(ch) != 2 || !s.IsContact(a, c) || !s.IsContact(c, a) {
			t.Fatalf("mutual request: %v", ch)
		}
		// refusing leaves no contact
		s.Request(b, c)
		s.Respond(c, b, false)
		if s.IsContact(b, c) {
			t.Fatal("a refused request became a contact")
		}
		if ch := s.Remove(a, b); len(ch) != 2 || s.IsContact(a, b) || s.IsContact(b, a) {
			t.Fatalf("remove: %v", ch)
		}
		if ch := s.Remove(a, b); ch != nil {
			t.Fatalf("removing nothing: %v", ch)
		}

		// devices, last seen, groups
		if !s.RememberDevice(a, "laptop") || s.RememberDevice(a, "laptop") {
			t.Fatal("remembering a device twice")
		}
		s.RememberDevice(a, "phone")
		if d := s.Devices(a); strings.Join(d, ",") != "laptop,phone" {
			t.Fatalf("devices: %v", d)
		}
		s.ForgetDevice(a, "phone")
		if d := s.Devices(a); len(d) != 1 {
			t.Fatalf("after forgetting: %v", d)
		}
		if s.LastSeen(a) != 0 {
			t.Fatal("never seen")
		}
		now := time.Now()
		s.Seen(a, now)
		s.Seen(a, now.Add(time.Minute))
		if got := s.LastSeen(a); got != now.Add(time.Minute).Unix() {
			t.Fatalf("last seen: %d", got)
		}
		dn := "CN=VPN-Users,OU=Groups,DC=example,DC=com" // a distinguished name has commas
		s.SetGroups(a, []string{"staff", dn})
		g := s.Groups(a)
		if len(g) != 2 || g[0] != dn && g[1] != dn {
			t.Fatalf("groups: %v", g)
		}
		if got := s.Groups("nobody@example.com"); len(got) != 0 {
			t.Fatalf("groups of nobody: %v", got)
		}
	})
}

// A load balancer that sends each request to the next relay.
func balancer(t *testing.T, handlers ...http.Handler) *httptest.Server {
	var n atomic.Uint32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlers[int(n.Add(1))%len(handlers)].ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	return ts
}

// twoEnrollers are two enrollment servers on one database and one CA, behind a balancer.
func twoEnrollers(t *testing.T, mutate func(c *EnrollConfig, lbURL string)) (lb *httptest.Server, a, b *EnrollServer, box *mailbox, sh1 *Shared) {
	t.Helper()
	dir := t.TempDir()
	if err := InitCA(filepath.Join(dir, "ca")); err != nil {
		t.Fatal(err)
	}
	addr := testDBAddr(t, dir)
	box = &mailbox{}
	var cur http.Handler
	var current atomic.Pointer[http.Handler]
	lb = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { (*current.Load()).ServeHTTP(w, r) }))
	t.Cleanup(lb.Close)
	var servers [2]*EnrollServer
	for i, id := range []string{"ra", "rb"} {
		var sh *Shared
		if i == 1 && sh1.db.dia == dialSQLite {
			sh = &Shared{db: sh1.db, ReplicaID: id}
			sh.admin = &adminDB{db: sh1.db, changed: sh.bump}
		} else {
			var err error
			if sh, err = OpenShared(addr, id); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { sh.Close() })
		}
		if i == 0 {
			sh1 = sh
		}
		cfg := EnrollConfig{
			CADir: filepath.Join(dir, "ca"), PublicRelay: "relay.example.com:8443", PublicURL: lb.URL,
			SendMail: box.send, Shared: sh, Revoked: NewSharedRevocations(sh), AllowedDomains: []string{"example.com"},
		}
		if mutate != nil {
			mutate(&cfg, lb.URL)
		}
		es, err := NewEnrollServer(cfg)
		if err != nil {
			t.Fatal(err)
		}
		servers[i] = es
	}
	h := balancer(t, servers[0].Handler(), servers[1].Handler())
	hh := http.Handler(h.Config.Handler)
	cur = hh
	current.Store(&cur)
	return lb, servers[0], servers[1], box, sh1
}

func TestEmailCodeEnrollmentAcrossRelays(t *testing.T) {
	lb, a, b, box, _ := twoEnrollers(t, nil)
	csr, _ := testCSR(t, "carol@example.com")
	var start struct {
		ID        string `json:"id"`
		PollToken string `json:"pollToken"`
	}
	postJSONTest(t, lb.URL+"/enroll", "", map[string]string{"email": "carol@example.com", "csr": string(csr), "device": "tablet"}, &start, 200)
	code := regexpCode(t, box.wait(t, 1)[0].body)
	// every step goes to the other relay than the one before
	var st struct{ Status string }
	postJSONTest(t, lb.URL+"/enroll/"+start.ID+"/confirm", start.PollToken, map[string]string{"code": "AAAA-AAAA"}, nil, 403) // wrong code counts
	postJSONTest(t, lb.URL+"/enroll/"+start.ID+"/confirm", start.PollToken, map[string]string{"code": code}, nil, 200)
	getJSON(t, lb.URL+"/enroll/"+start.ID, start.PollToken, &st)
	if st.Status != "approved" {
		t.Fatalf("status: %+v", st)
	}
	// the certificate is in the one ledger both relays read
	for _, es := range []*EnrollServer{a, b} {
		certs := es.activeCerts("carol@example.com")
		if len(certs) != 1 || certs[0].Device != "tablet" {
			t.Fatalf("ledger: %+v", certs)
		}
	}
	// the owner was told once
	time.Sleep(100 * time.Millisecond)
	if n := box.count(); n != 2 { // the code and the notice
		t.Fatalf("%d mails", n)
	}
	// a second device is "known" on either relay
	postJSONTest(t, lb.URL+"/enroll", "", map[string]string{"email": "carol@example.com", "csr": string(csr), "device": "phone"}, &start, 200)
	if body := box.wait(t, 3)[2].body; !strings.Contains(body, "nuova configurazione") {
		t.Fatalf("the user is not known to the other relay: %s", body)
	}
}

func TestSelfRevocationLinkWorksOnTheOtherRelay(t *testing.T) {
	lb, a, _, box, _ := twoEnrollers(t, nil)
	rev := a.cfg.Revoked
	_ = rev
	csr, _ := testCSR(t, "carol@example.com")
	cert, err := a.sign(csr, "carol@example.com", "tablet", "password", "203.0.113.1")
	if err != nil {
		t.Fatal(err)
	}
	box.wait(t, 1)
	// asked of one relay, opened and confirmed on the next ones
	for i := 0; i < 2; i++ { // two requests: the balancer alternates
		postForm(t, lb.URL+"/revoke", url.Values(urlValues("carol@example.com")))
	}
	mails := box.wait(t, 3)
	link := revokeLinkFrom(t, mails[1])
	token := link[strings.Index(link, "token=")+6:]
	r, _ := http.Get(link)
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("the link: %d", r.StatusCode)
	}
	serial := serialHex(parseCert(t, cert))
	if code, _ := postForm(t, lb.URL+"/revoke/confirm", url.Values(urlValues2("token", token, "serial", serial))); code != 200 {
		t.Fatalf("confirm: %d", code)
	}
	if !a.cfg.Revoked.Revoked(parseCert(t, cert)) {
		t.Fatal("not revoked")
	}
	if code, _ := postForm(t, lb.URL+"/revoke/confirm", url.Values(urlValues2("token", token, "serial", serial))); code != 403 {
		t.Fatalf("the link worked twice: %d", code)
	}
}

func regexpCode(t *testing.T, body string) string {
	t.Helper()
	for _, w := range strings.Fields(body) {
		if len(w) == 9 && w[4] == '-' && strings.Trim(w, "ABCDEFGHJKLMNPQRSTUVWXYZ23456789-") == "" {
			return w
		}
	}
	t.Fatalf("no code in %q", body)
	return ""
}

func getJSON(t *testing.T, url, bearer string, out any) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	jsonDecode(resp.Body, out)
}

func urlValues(email string) map[string][]string { return map[string][]string{"email": {email}} }

func urlValues2(k1, v1, k2, v2 string) map[string][]string {
	return map[string][]string{k1: {v1}, k2: {v2}}
}

func TestBrowserSignInAcrossRelays(t *testing.T) {
	idp := newFakeIdP(t)
	lb, a, b, _, _ := twoEnrollers(t, func(c *EnrollConfig, _ string) {
		c.Auth = &AuthConfig{Methods: []AuthMethod{{ID: "idp", Type: "oidc", Label: "Company", OIDC: &OIDCConfig{Issuer: idp.srv.URL, ClientID: "relay", ClientSecret: "s3cret"}}}}
	})
	// start, the browser's return and the device code each reach another relay
	for i := 0; i < 3; i++ {
		res := browserSignIn(t, lb, "idp", "alice@example.com")
		if res.status != 200 || !res.approved {
			t.Fatalf("sign-in %d: %+v", i, res)
		}
		if got := certEmail(t, res.cert); got != "alice@example.com" {
			t.Fatalf("certificate for %q", got)
		}
	}
	if n := len(a.activeCerts("alice@example.com")); n != 3 {
		t.Fatalf("certificates in the ledger: %d", n)
	}
	_ = b
}

func TestAdministratorSessionsAreSharedByRelays(t *testing.T) {
	var admins []*Admin
	lb, a, b, _, sh := twoEnrollers(t, func(c *EnrollConfig, _ string) {
		c.Auth = &AuthConfig{Methods: []AuthMethod{{ID: "local", Type: "password", Label: "Local", Password: &PasswordConfig{Database: true}}}}
		adm, err := NewAdmin(AdminConfig{Shared: c.Shared, Groups: []string{"admin"}, Revoked: c.Revoked})
		if err != nil {
			t.Fatal(err)
		}
		c.Admin = adm
		admins = append(admins, adm)
	})
	if err := admins[0].AddLocalUser("root", "correct horse battery", "root@example.com", "admin"); err != nil {
		t.Fatal(err)
	}
	f := &adminFixture{ts: lb, es: a, admin: admins[0], rev: "", dir: ""}
	br := f.browser(t)
	br.signIn("local", "root", "correct horse battery", 200) // on one relay ...
	for i := 0; i < 4; i++ {                                 // ... every following request is on another
		br.get("/admin/api/overview", nil, 200)
	}
	// a change made through one relay is seen by the other
	br.send("PUT", "/admin/api/rules", map[string]any{
		"allowedDomains": []string{"example.com", "other.org"}, "certTtlHours": 48,
		"methods": []map[string]any{{"id": "email"}, {"id": "local"}},
		"smtp":    map[string]any{"addr": "smtp.example.com:587", "from": "relay@example.com", "tls": "starttls", "auth": "auto"},
	}, nil, 200)
	a.applyStoredRules()
	b.applyStoredRules()
	for _, es := range []*EnrollServer{a, b} {
		if r := es.Rules(); r.CertTTLHours != 48 || len(r.AllowedDomains) != 2 {
			t.Fatalf("rules on a relay: %+v", r)
		}
	}
	br.send("POST", "/admin/api/logout", nil, nil, 200)
	br.get("/admin/api/overview", nil, 401)
	_ = sh
}
