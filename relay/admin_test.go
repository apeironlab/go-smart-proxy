package relay

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// adminFixture is a relay with the management interface on.
type adminFixture struct {
	ts    *httptest.Server
	es    *EnrollServer
	admin *Admin
	rev   string // revocations file
	dir   string
}

type adminOpts struct {
	dir     string
	methods []AuthMethod
	mutate  func(*EnrollConfig)
}

func newAdminFixture(t *testing.T, o adminOpts) *adminFixture {
	t.Helper()
	dir := o.dir
	if dir == "" {
		dir = t.TempDir()
	}
	rev := filepath.Join(dir, "revoked.txt")
	admin, err := NewAdmin(AdminConfig{DBPath: testDBAddr(t, dir), Groups: []string{"admin"}, Revoked: NewRevocations(rev)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close() })
	if o.methods == nil {
		o.methods = []AuthMethod{{ID: "local", Type: "password", Label: "Local users", Password: &PasswordConfig{Database: true}}}
	}
	ts, es := authServer(t, func(c *EnrollConfig, _ string) {
		c.Auth = &AuthConfig{Methods: o.methods}
		c.Admin = admin
		c.AllowedDomains = []string{"example.com"}
		if o.mutate != nil {
			o.mutate(c)
		}
	})
	return &adminFixture{ts: ts, es: es, admin: admin, rev: rev, dir: dir}
}

// browser is an admin's browser: it keeps cookies and sends the CSRF token.
type browser struct {
	t    *testing.T
	base string
	c    *http.Client
	csrf string
}

func (f *adminFixture) browser(t *testing.T) *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{t: t, base: f.ts.URL, c: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (b *browser) do(method, path string, in any, headers map[string]string) (int, []byte) {
	b.t.Helper()
	var body *bytes.Reader
	if in != nil {
		raw, _ := json.Marshal(in)
		body = bytes.NewReader(raw)
	} else {
		body = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, b.base+path, body)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet && b.csrf != "" {
		req.Header.Set("X-CSRF-Token", b.csrf)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := b.c.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.Bytes()
}

func (b *browser) get(path string, out any, want int) {
	b.t.Helper()
	code, raw := b.do("GET", path, nil, nil)
	if code != want {
		b.t.Fatalf("GET %s: %d %s (want %d)", path, code, raw, want)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			b.t.Fatalf("GET %s: %v: %s", path, err, raw)
		}
	}
}

func (b *browser) send(method, path string, in, out any, want int) {
	b.t.Helper()
	code, raw := b.do(method, path, in, nil)
	if code != want {
		b.t.Fatalf("%s %s: %d %s (want %d)", method, path, code, raw, want)
	}
	if out != nil {
		json.Unmarshal(raw, out)
	}
}

// refreshCSRF reads the session and remembers its token.
func (b *browser) refreshCSRF() map[string]any {
	b.t.Helper()
	var s map[string]any
	b.get("/admin/api/session", &s, 200)
	b.csrf, _ = s["csrf"].(string)
	return s
}

func (b *browser) signIn(method, user, pass string, want int) {
	b.t.Helper()
	b.send("POST", "/admin/api/login/"+method, map[string]string{"username": user, "password": pass}, nil, want)
	b.refreshCSRF()
}

func (f *adminFixture) loggedIn(t *testing.T) *browser {
	t.Helper()
	if err := f.admin.AddLocalUser("root", "correct horse battery", "root@example.com", "admin"); err != nil {
		t.Fatal(err)
	}
	b := f.browser(t)
	b.signIn("local", "root", "correct horse battery", 200)
	return b
}

func TestWithoutAdminNothingIsMounted(t *testing.T) {
	ts, _ := authServer(t, nil)
	for _, p := range []string{"/admin/", "/admin/api/session"} {
		resp, err := http.Get(ts.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Fatalf("%s without the admin feature: %d", p, resp.StatusCode)
		}
	}
}

func TestAdminConfigIsChecked(t *testing.T) {
	dir := t.TempDir()
	rev := NewRevocations(filepath.Join(dir, "r.txt"))
	if _, err := NewAdmin(AdminConfig{DBPath: filepath.Join(dir, "a.db"), Revoked: rev}); err == nil {
		t.Fatal("an interface nobody can sign in to must be refused")
	}
	if _, err := NewAdmin(AdminConfig{DBPath: filepath.Join(dir, "a.db"), Groups: []string{"admin"}}); err == nil {
		t.Fatal("the interface needs the revocation file")
	}
	if _, err := NewAdmin(AdminConfig{DBPath: filepath.Join(dir, "a.db"), Emails: []string{"not an address"}, Revoked: rev}); err == nil {
		t.Fatal("bad administrator address")
	}
	// database users need the interface
	if _, err := NewEnrollServer(EnrollConfig{
		CADir: func() string { d := t.TempDir(); InitCA(d + "/ca"); return d + "/ca" }(), PublicRelay: "r:1", SendMail: func(string, string, string) error { return nil },
		Auth: &AuthConfig{Methods: []AuthMethod{{ID: "p", Type: "password", Password: &PasswordConfig{Database: true}}}},
	}); err == nil {
		t.Fatal("database users without the admin interface must be refused")
	}
	if err := (&PasswordConfig{UsersFile: "x", Database: true}).validate(); err == nil {
		t.Fatal("file and database together")
	}
	// a file next to the db
	st, err := os.Stat(filepath.Join(dir, "a.db"))
	if err == nil && st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("database mode %v", st.Mode())
	}
}

func TestAdminSignIn(t *testing.T) {
	f := newAdminFixture(t, adminOpts{})
	f.admin.AddLocalUser("staff", "another good password", "staff@example.com", "staff")
	f.admin.AddLocalUser("root", "correct horse battery", "root@example.com", "admin")

	b := f.browser(t)
	if s := b.refreshCSRF(); s["authenticated"] != false {
		t.Fatalf("session before sign-in: %v", s)
	}
	var s struct {
		Methods []methodInfo `json:"methods"`
	}
	b.get("/admin/api/session", &s, 200)
	if len(s.Methods) != 1 || s.Methods[0].ID != "local" {
		t.Fatalf("login methods: %+v (the e-mail code must not be one)", s.Methods)
	}
	b.get("/admin/api/overview", nil, 401)

	b.signIn("local", "root", "wrong password!!", 401)
	b.signIn("local", "staff", "another good password", 403) // right password, not an administrator
	b.get("/admin/api/overview", nil, 401)
	b.signIn("local", "root", "correct horse battery", 200)
	sess := b.refreshCSRF()
	if sess["authenticated"] != true || sess["email"] != "root@example.com" {
		t.Fatalf("session: %v", sess)
	}
	b.get("/admin/api/overview", nil, 200)

	// the cookie is HttpOnly and scoped to the interface
	resp, _ := http.Post(f.ts.URL+"/admin/api/login/local", "application/json", strings.NewReader(`{"username":"root","password":"correct horse battery"}`))
	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == adminCookie {
			cookie = c
		}
	}
	resp.Body.Close()
	if cookie == nil || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/admin" {
		t.Fatalf("session cookie: %+v", cookie)
	}

	// logout ends it
	b.send("POST", "/admin/api/logout", nil, nil, 200)
	b.get("/admin/api/overview", nil, 401)
}

func TestAdminWritesNeedTheCSRFTokenAndSameOrigin(t *testing.T) {
	f := newAdminFixture(t, adminOpts{})
	b := f.loggedIn(t)
	body := map[string]string{"email": "bob@example.com"}

	saved := b.csrf
	b.csrf = ""
	if code, _ := b.do("POST", "/admin/api/revoke", body, nil); code != 403 {
		t.Fatalf("no CSRF token: %d", code)
	}
	b.csrf = "wrong"
	if code, _ := b.do("POST", "/admin/api/revoke", body, nil); code != 403 {
		t.Fatalf("wrong CSRF token: %d", code)
	}
	b.csrf = saved
	if code, _ := b.do("POST", "/admin/api/revoke", body, map[string]string{"Sec-Fetch-Site": "cross-site"}); code != 403 {
		t.Fatalf("cross-site request: %d", code)
	}
	if code, _ := b.do("POST", "/admin/api/revoke", body, map[string]string{"Origin": "https://evil.example"}); code != 403 {
		t.Fatalf("foreign origin: %d", code)
	}
	req, _ := http.NewRequest("POST", f.ts.URL+"/admin/api/revoke", strings.NewReader("email=bob@example.com"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", b.csrf)
	resp, _ := b.c.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("form post: %d", resp.StatusCode)
	}
	if code, _ := b.do("POST", "/admin/api/revoke", body, nil); code != 200 {
		t.Fatalf("a proper request must work: %d", code)
	}
	if code, _ := b.do("GET", "/admin/api/overview", nil, map[string]string{"Sec-Fetch-Site": "cross-site"}); code != 403 {
		t.Fatalf("cross-site read: %d", code)
	}
}

func TestAdminLoginIsRateLimited(t *testing.T) {
	f := newAdminFixture(t, adminOpts{})
	f.admin.AddLocalUser("root", "correct horse battery", "root@example.com", "admin")
	b := f.browser(t)
	last := 0
	for i := 0; i < 12; i++ {
		last, _ = b.do("POST", "/admin/api/login/local", map[string]string{"username": "root", "password": "guess-" + strings.Repeat("x", i+1)}, nil)
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("after many wrong passwords: %d", last)
	}
	// even the right password is refused for a while
	if code, _ := b.do("POST", "/admin/api/login/local", map[string]string{"username": "root", "password": "correct horse battery"}, nil); code != http.StatusTooManyRequests {
		t.Fatalf("right password while limited: %d", code)
	}
}

type certsOut []CertRecord

func enrollAs(t *testing.T, f *adminFixture, user, pass, email string) (cert string, status int) {
	t.Helper()
	csr, _ := testCSR(t, email)
	body, _ := json.Marshal(map[string]string{"email": email, "csr": string(csr), "username": user, "password": pass, "device": "laptop"})
	resp, err := http.Post(f.ts.URL+"/enroll-auth/local", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		CertPEM string `json:"certPem"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	return out.CertPEM, resp.StatusCode
}

func TestLocalUsersInTheDatabaseCanEnrollAndAreManagedFromTheInterface(t *testing.T) {
	f := newAdminFixture(t, adminOpts{})
	b := f.loggedIn(t)

	var lu struct {
		Enabled bool        `json:"enabled"`
		Users   []LocalUser `json:"users"`
	}
	b.get("/admin/api/local-users", &lu, 200)
	if !lu.Enabled || len(lu.Users) != 1 {
		t.Fatalf("local users: %+v", lu)
	}

	b.send("POST", "/admin/api/local-users", map[string]any{"username": "Bob", "password": "bobs long password", "email": "bob@example.com", "groups": []string{"staff"}}, nil, 200)
	b.send("POST", "/admin/api/local-users", map[string]any{"username": "bob", "password": "bobs long password", "email": "bob@example.com"}, nil, 409)
	b.send("POST", "/admin/api/local-users", map[string]any{"username": "short", "password": "1234", "email": "s@example.com"}, nil, 400)
	b.send("POST", "/admin/api/local-users", map[string]any{"username": "bad name", "password": "bobs long password"}, nil, 400)
	b.send("POST", "/admin/api/local-users", map[string]any{"username": "carol", "password": "carols long password", "email": "not an address"}, nil, 400)

	// the new user can get a certificate with it
	cert, code := enrollAs(t, f, "bob", "bobs long password", "bob@example.com")
	if code != 200 || certEmail(t, cert) != "bob@example.com" {
		t.Fatalf("enrollment of a database user: %d", code)
	}
	if _, code := enrollAs(t, f, "bob", "wrong wrong wrong", "bob@example.com"); code != 401 {
		t.Fatalf("wrong password: %d", code)
	}

	// change the password: the old one stops working at once
	b.send("PUT", "/admin/api/local-users/bob", map[string]any{"password": "a brand new password", "email": "bob@example.com", "groups": []string{"staff"}}, nil, 200)
	if _, code := enrollAs(t, f, "bob", "bobs long password", "bob@example.com"); code != 401 {
		t.Fatalf("old password after reset: %d", code)
	}
	if _, code := enrollAs(t, f, "bob", "a brand new password", "bob@example.com"); code != 200 {
		t.Fatalf("new password: %d", code)
	}
	// an edit without a password keeps the current one
	b.send("PUT", "/admin/api/local-users/bob", map[string]any{"email": "bob@example.com", "groups": []string{"staff", "vpn"}}, nil, 200)
	if _, code := enrollAs(t, f, "bob", "a brand new password", "bob@example.com"); code != 200 {
		t.Fatalf("password after an edit without one: %d", code)
	}
	b.send("PUT", "/admin/api/local-users/nobody", map[string]any{"email": "n@example.com"}, nil, 404)

	b.send("DELETE", "/admin/api/local-users/bob", nil, nil, 200)
	b.send("DELETE", "/admin/api/local-users/bob", nil, nil, 404)
	if _, code := enrollAs(t, f, "bob", "a brand new password", "bob@example.com"); code != 401 {
		t.Fatalf("deleted user: %d", code)
	}
}

func TestRevokingCertificatesAndIdentities(t *testing.T) {
	f := newAdminFixture(t, adminOpts{})
	b := f.loggedIn(t)
	b.send("POST", "/admin/api/local-users", map[string]any{"username": "bob", "password": "bobs long password", "email": "bob@example.com"}, nil, 200)
	cert1, _ := enrollAs(t, f, "bob", "bobs long password", "bob@example.com")
	cert2, _ := enrollAs(t, f, "bob", "bobs long password", "bob@example.com")

	var certs certsOut
	b.get("/admin/api/certs?email=bob@example.com", &certs, 200)
	if len(certs) != 2 || certs[0].Revoked || certs[0].Method != "local" || certs[0].Device != "laptop" {
		t.Fatalf("certificates: %+v", certs)
	}

	// revoke one certificate: only that one is refused
	target := certs[1].Serial
	b.send("POST", "/admin/api/revoke", map[string]string{"serial": target}, nil, 200)
	rev := NewRevocations(f.rev)
	c1, c2 := parseCert(t, cert1), parseCert(t, cert2)
	if rev.Revoked(c1) == rev.Revoked(c2) {
		t.Fatal("exactly one of the two certificates must be revoked")
	}
	if !(rev.Revoked(c1) && serialHex(c1) == target) && !(rev.Revoked(c2) && serialHex(c2) == target) {
		t.Fatal("the wrong certificate was revoked")
	}
	b.get("/admin/api/certs?email=bob@example.com", &certs, 200)
	n := 0
	for _, c := range certs {
		if c.Revoked {
			n++
			if c.Serial != target || c.RevokedBy != "root@example.com" {
				t.Fatalf("revoked cert record: %+v", c)
			}
		}
	}
	if n != 1 {
		t.Fatalf("%d revoked records", n)
	}
	b.send("POST", "/admin/api/revoke", map[string]string{"serial": "deadbeef"}, nil, 400)
	b.send("POST", "/admin/api/revoke", map[string]string{"serial": "zz"}, nil, 400)

	// lift it
	b.send("POST", "/admin/api/unrevoke", map[string]string{"serial": target}, nil, 200)
	if rev.Revoked(c1) || rev.Revoked(c2) {
		t.Fatal("nothing should be revoked now")
	}

	// revoke the whole identity
	b.send("POST", "/admin/api/revoke", map[string]string{"email": "Bob@Example.com"}, nil, 200)
	if !rev.Revoked(c1) || !rev.Revoked(c2) {
		t.Fatal("every certificate of the identity must be refused")
	}
	var users []UserInfo
	b.get("/admin/api/users", &users, 200)
	var bob *UserInfo
	for i := range users {
		if users[i].Email == "bob@example.com" {
			bob = &users[i]
		}
	}
	if bob == nil || !bob.Revoked || bob.Local != "bob" {
		t.Fatalf("users: %+v", users)
	}
	b.send("POST", "/admin/api/unrevoke", map[string]string{"email": "bob@example.com"}, nil, 200)
	if rev.Revoked(c1) {
		t.Fatal("identity still revoked")
	}

	// an administrator cannot lock themselves out
	b.send("POST", "/admin/api/revoke", map[string]string{"email": "root@example.com"}, nil, 400)
	b.send("POST", "/admin/api/revoke", map[string]string{}, nil, 400)
	b.send("POST", "/admin/api/revoke", map[string]string{"email": "no good"}, nil, 400)
}

func TestRevocationFileEditing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revoked.txt")
	os.WriteFile(path, []byte("# comment\nold@example.com\nserial:AB12\n"), 0o600)
	r := NewRevocations(path)
	if err := r.Add("new@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := r.Add("NEW@example.com"); err != nil { // no duplicate
		t.Fatal(err)
	}
	if err := r.Add("serial:ff"); err != nil {
		t.Fatal(err)
	}
	if err := r.Remove("old@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := r.Remove("never@example.com"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if got := string(b); got != "# comment\nserial:AB12\nnew@example.com\nserial:ff\n" {
		t.Fatalf("file: %q", got)
	}
	emails, serials := r.List()
	if strings.Join(emails, ",") != "new@example.com" || strings.Join(serials, ",") != "ab12,ff" {
		t.Fatalf("list: %v %v", emails, serials)
	}
	if err := r.Add("not an address"); err == nil {
		t.Fatal("invalid entry")
	}
	if err := r.Add("serial:xyz"); err == nil {
		t.Fatal("invalid serial")
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	if err := NewRevocations("").Add("a@example.com"); err == nil {
		t.Fatal("no file, no revocation")
	}
}

func TestEnrollmentRulesAreEditableAndPersist(t *testing.T) {
	dir := t.TempDir()
	f := newAdminFixture(t, adminOpts{dir: dir})
	b := f.loggedIn(t)
	f.admin.AddLocalUser("bob", "bobs long password", "bob@other.org", "staff")

	// the configured domain restriction applies
	if _, code := enrollAs(t, f, "bob", "bobs long password", "bob@other.org"); code != 403 {
		t.Fatalf("domain not allowed: %d", code)
	}
	var rules map[string]any
	b.get("/admin/api/rules", &rules, 200)
	if rules["certTtlHours"].(float64) != 90*24 {
		t.Fatalf("default lifetime: %v", rules["certTtlHours"])
	}
	smtp := rules["smtp"].(map[string]any)
	if smtp["hasPass"] != false {
		t.Fatalf("smtp: %v", smtp)
	}

	put := func(mod func(m map[string]any)) (int, []byte) {
		m := map[string]any{
			"allowedDomains": []string{"example.com", "other.org"}, "certTtlHours": 48,
			"methods": []map[string]any{{"id": "email"}, {"id": "local", "groups": []string{"staff"}}},
			"smtp":    map[string]any{"addr": "smtp.example.com:587", "user": "mailer", "from": "relay@example.com", "tls": "starttls", "auth": "auto", "pass": "smtp secret"},
		}
		if mod != nil {
			mod(m)
		}
		return b.do("PUT", "/admin/api/rules", m, nil)
	}
	if code, raw := put(nil); code != 200 {
		t.Fatalf("put rules: %d %s", code, raw)
	}
	cert, code := enrollAs(t, f, "bob", "bobs long password", "bob@other.org")
	if code != 200 {
		t.Fatalf("after adding the domain: %d", code)
	}
	if exp := parseCert(t, cert).NotAfter.Sub(parseCert(t, cert).NotBefore).Hours(); exp < 48 || exp > 50 {
		t.Fatalf("lifetime %vh, want 48h (+1h of back-dating)", exp)
	}

	// the password is never sent back, and an edit without it keeps it
	b.get("/admin/api/rules", &rules, 200)
	if rules["smtp"].(map[string]any)["hasPass"] != true || strings.Contains(mustJSON(rules), "smtp secret") {
		t.Fatalf("smtp password leaked or lost: %v", rules["smtp"])
	}
	if code, _ := put(func(m map[string]any) { delete(m["smtp"].(map[string]any), "pass") }); code != 200 {
		t.Fatal("put without password")
	}
	if f.es.Rules().SMTP.Pass != "smtp secret" {
		t.Fatal("the SMTP password must be kept when not sent")
	}

	// required groups: bob is in staff, so requiring vpn refuses him
	if code, _ := put(func(m map[string]any) {
		m["methods"] = []map[string]any{{"id": "email"}, {"id": "local", "groups": []string{"vpn"}}}
	}); code != 200 {
		t.Fatal("put groups")
	}
	if _, code := enrollAs(t, f, "bob", "bobs long password", "bob@other.org"); code != 403 {
		t.Fatalf("missing group: %d", code)
	}

	// refusals
	bad := []func(m map[string]any){
		func(m map[string]any) { m["certTtlHours"] = 0 },
		func(m map[string]any) { m["allowedDomains"] = []string{"no spaces allowed"} },
		func(m map[string]any) {
			m["methods"] = []map[string]any{{"id": "email", "disabled": true}, {"id": "local", "disabled": true}}
		},
		func(m map[string]any) { m["methods"] = []map[string]any{{"id": "ghost", "disabled": true}} },
		func(m map[string]any) { m["smtp"].(map[string]any)["addr"] = "no-port" },
		func(m map[string]any) { m["smtp"].(map[string]any)["tls"] = "weird" },
	}
	for i, mod := range bad {
		if code, _ := put(mod); code != 400 {
			t.Fatalf("bad rules %d accepted: %d", i, code)
		}
	}

	// switching the e-mail code off changes what the relay offers
	if code, _ := put(func(m map[string]any) {
		m["methods"] = []map[string]any{{"id": "email", "disabled": true}, {"id": "local", "groups": []string{"vpn"}}}
	}); code != 200 {
		t.Fatal("disable email")
	}
	var offered struct {
		Methods []methodInfo `json:"methods"`
	}
	csr, _ := testCSR(t, "bob@other.org")
	raw, _ := json.Marshal(map[string]string{"email": "bob@other.org", "csr": string(csr)})
	resp, _ := http.Post(f.ts.URL+"/enroll", "application/json", bytes.NewReader(raw))
	json.NewDecoder(resp.Body).Decode(&offered)
	resp.Body.Close()
	if resp.StatusCode != 401 || len(offered.Methods) != 1 || offered.Methods[0].ID != "local" {
		t.Fatalf("relay offers %d %+v", resp.StatusCode, offered.Methods)
	}

	// restart: the rules come back from the database
	f.admin.Close()
	f2 := newAdminFixture(t, adminOpts{dir: dir})
	r := f2.es.Rules()
	if r.CertTTLHours != 48 || len(r.AllowedDomains) != 2 || !f2.es.emailDisabled() || r.SMTP.Pass != "smtp secret" ||
		strings.Join(r.RequireGroups["local"], ",") != "vpn" {
		t.Fatalf("rules after restart: %+v", r)
	}
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestAuditLogRecordsWhatHappens(t *testing.T) {
	f := newAdminFixture(t, adminOpts{})
	b := f.loggedIn(t)
	b.send("POST", "/admin/api/local-users", map[string]any{"username": "bob", "password": "bobs long password", "email": "bob@example.com"}, nil, 200)
	enrollAs(t, f, "bob", "bobs long password", "bob@example.com")
	enrollAs(t, f, "bob", "wrong wrong wrong", "bob@example.com")
	b.send("POST", "/admin/api/revoke", map[string]string{"email": "bob@example.com"}, nil, 200)

	var all []Event
	b.get("/admin/api/events?limit=100", &all, 200)
	kinds := map[string]int{}
	for _, e := range all {
		kinds[e.Kind]++
	}
	for _, want := range []string{"admin.login", "admin.user.add", "enroll.issued", "enroll.denied", "admin.revoke"} {
		if kinds[want] == 0 {
			t.Fatalf("no %s event in %v", want, kinds)
		}
	}
	// newest first
	for i := 1; i < len(all); i++ {
		if all[i].ID >= all[i-1].ID {
			t.Fatal("events are not newest first")
		}
	}
	var admins []Event
	b.get("/admin/api/events?kind=admin.", &admins, 200)
	for _, e := range admins {
		if !strings.HasPrefix(e.Kind, "admin.") {
			t.Fatalf("filter let %s through", e.Kind)
		}
	}
	var found []Event
	b.get("/admin/api/events?q="+url.QueryEscape("bob@example.com"), &found, 200)
	if len(found) == 0 {
		t.Fatal("search found nothing")
	}
	// LIKE wildcards in the search are literal
	var none []Event
	b.get("/admin/api/events?q=%25", &none, 200)
	if len(none) != 0 {
		t.Fatalf("a bare %% matched %d events", len(none))
	}
	// paging
	var page1, page2 []Event
	b.get("/admin/api/events?limit=2", &page1, 200)
	b.get("/admin/api/events?limit=2&before="+itoa(page1[1].ID), &page2, 200)
	if len(page1) != 2 || len(page2) == 0 || page2[0].ID >= page1[1].ID {
		t.Fatalf("paging: %+v %+v", page1, page2)
	}
	// secrets never reach the log
	if raw, _ := json.Marshal(all); strings.Contains(string(raw), "bobs long password") {
		t.Fatal("a password is in the audit log")
	}
}

func TestOverviewCounts(t *testing.T) {
	f := newAdminFixture(t, adminOpts{})
	srv := NewServer(mustStore(t))
	f.admin.SetServer(srv)
	b := f.loggedIn(t)
	b.send("POST", "/admin/api/local-users", map[string]any{"username": "bob", "password": "bobs long password", "email": "bob@example.com"}, nil, 200)
	enrollAs(t, f, "bob", "bobs long password", "bob@example.com")
	var ov struct {
		Counts map[string]int `json:"counts"`
		Online []OnlineDevice `json:"online"`
		Recent []Event        `json:"recent"`
	}
	b.get("/admin/api/overview", &ov, 200)
	if ov.Counts["certs"] != 1 || ov.Counts["localUsers"] != 2 || ov.Counts["devices"] != 0 || len(ov.Recent) == 0 || ov.Online == nil {
		t.Fatalf("overview: %+v", ov)
	}
	b.send("POST", "/admin/api/revoke", map[string]string{"email": "bob@example.com"}, nil, 200)
	b.get("/admin/api/overview", &ov, 200)
	if ov.Counts["revokedUsers"] != 1 {
		t.Fatalf("overview: %+v", ov.Counts)
	}
}

func TestAdminPageIsServedWithStrictHeaders(t *testing.T) {
	f := newAdminFixture(t, adminOpts{})
	for _, p := range []string{"/admin/", "/admin/some/client/route"} {
		resp, err := http.Get(f.ts.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d", p, resp.StatusCode)
		}
		if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") || resp.Header.Get("X-Frame-Options") != "DENY" ||
			resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("%s headers: %v", p, resp.Header)
		}
	}
	resp, _ := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Get(f.ts.URL + "/admin")
	resp.Body.Close()
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("/admin: %d", resp.StatusCode)
	}
}

func TestAdminSignInWithOpenIDConnect(t *testing.T) {
	idp := newFakeIdP(t)
	f := newAdminFixture(t, adminOpts{methods: []AuthMethod{{
		ID: "idp", Type: "oidc", Label: "Company sign-in",
		OIDC: &OIDCConfig{Issuer: idp.srv.URL, ClientID: "relay", ClientSecret: "s3cret"},
	}}})

	signIn := func(claims map[string]any, mutate func(b *browser)) *browser {
		idp.mu.Lock()
		idp.claims = claims
		idp.mu.Unlock()
		b := f.browser(t)
		var start struct {
			AuthURL string `json:"authUrl"`
		}
		b.send("POST", "/admin/api/login/idp/start", nil, &start, 200)
		if mutate != nil {
			mutate(b)
		}
		resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Get(start.AuthURL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		cb := resp.Header.Get("Location")
		if cb == "" {
			t.Fatalf("the provider did not send the browser back (%d)", resp.StatusCode)
		}
		u, _ := url.Parse(cb)
		code, _ := b.do("GET", u.RequestURI(), nil, nil)
		if code != http.StatusSeeOther && code != http.StatusForbidden {
			t.Fatalf("callback: %d", code)
		}
		return b
	}

	// an administrator of the provider signs in
	b := signIn(map[string]any{"sub": "u1", "email": "boss@example.com", "email_verified": true, "groups": []any{"admin"}}, nil)
	if s := b.refreshCSRF(); s["authenticated"] != true || s["email"] != "boss@example.com" {
		t.Fatalf("session after OIDC sign-in: %v", s)
	}
	b.get("/admin/api/overview", nil, 200)

	// somebody who is not an administrator signs in correctly and gets nothing
	b = signIn(map[string]any{"sub": "u2", "email": "alice@example.com", "email_verified": true, "groups": []any{"staff"}}, nil)
	if s := b.refreshCSRF(); s["authenticated"] != false {
		t.Fatalf("a non-administrator got a session: %v", s)
	}

	// the sign-in link is opened in another browser than the one that asked:
	// nothing is granted to either
	idp.mu.Lock()
	idp.claims = map[string]any{"sub": "u1", "email": "boss@example.com", "email_verified": true, "groups": []any{"admin"}}
	idp.mu.Unlock()
	victim := f.browser(t)
	var start struct {
		AuthURL string `json:"authUrl"`
	}
	victim.send("POST", "/admin/api/login/idp/start", nil, &start, 200)
	resp, _ := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Get(start.AuthURL)
	resp.Body.Close()
	cb, _ := url.Parse(resp.Header.Get("Location"))
	attacker := f.browser(t)
	if code, _ := attacker.do("GET", cb.RequestURI(), nil, nil); code != http.StatusForbidden {
		t.Fatalf("callback in another browser: %d", code)
	}
	if s := attacker.refreshCSRF(); s["authenticated"] != false {
		t.Fatal("the other browser got a session")
	}
	// and the state is spent
	if code, _ := victim.do("GET", cb.RequestURI(), nil, nil); code != http.StatusForbidden {
		t.Fatalf("replayed callback: %d", code)
	}
	// a form post to a browser method is refused
	b2 := f.browser(t)
	b2.send("POST", "/admin/api/login/idp", map[string]string{"username": "a", "password": "b"}, nil, 400)
	b2.send("POST", "/admin/api/login/nope", map[string]string{"username": "a", "password": "b"}, nil, 404)
}

func TestAdminByEmailAddress(t *testing.T) {
	dir := t.TempDir()
	admin, err := NewAdmin(AdminConfig{DBPath: filepath.Join(dir, "a.db"), Emails: []string{"Boss@Example.com"}, Revoked: NewRevocations(filepath.Join(dir, "r.txt"))})
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	ident := func(e string, g ...string) Identity { return Identity{Email: e, Groups: g} }
	if !admin.isAdmin(ident("boss@example.com")) || !admin.isAdmin(ident("BOSS@example.com")) {
		t.Fatal("listed address")
	}
	if admin.isAdmin(ident("other@example.com", "admin")) || admin.isAdmin(ident("")) || admin.isAdmin(ident("a@b@c")) {
		t.Fatal("not listed")
	}
}

func parseCert(t *testing.T, certPEM string) *x509.Certificate {
	t.Helper()
	b, _ := pem.Decode([]byte(certPEM))
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func serialHex(c *x509.Certificate) string { return strings.ToLower(c.SerialNumber.Text(16)) }

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func mustStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAdminManagesApplicationsAndGateways(t *testing.T) {
	dir := t.TempDir()
	f := newAdminFixture(t, adminOpts{dir: dir})
	cat := NewCatalog()
	srv := NewServer(mustStore(t))
	srv.AttachCatalog(cat)
	f.admin.SetServer(srv)
	if err := f.admin.SetCatalog(cat); err != nil {
		t.Fatal(err)
	}
	b := f.loggedIn(t)

	var got struct {
		Enabled  bool  `json:"enabled"`
		ReadOnly bool  `json:"readOnly"`
		Apps     []App `json:"apps"`
	}
	b.get("/admin/api/apps", &got, 200)
	if !got.Enabled || got.ReadOnly || len(got.Apps) != 0 {
		t.Fatalf("apps: %+v", got)
	}
	app := App{ID: "crm", Name: "CRM", Host: "crm.apps", Kind: "http", Gateway: "g1", Target: "http://10.0.0.5:8080", Groups: []string{"sales"}}
	b.send("PUT", "/admin/api/apps", map[string]any{"apps": []App{app}}, &got, 200)
	if len(got.Apps) != 1 || got.Apps[0].ID != "crm" || len(cat.Apps()) != 1 {
		t.Fatalf("saved: %+v", got)
	}
	// invalid catalogs are refused and change nothing
	bad := app
	bad.Host = "10.0.0.1"
	b.send("PUT", "/admin/api/apps", map[string]any{"apps": []App{bad}}, nil, 400)
	b.send("PUT", "/admin/api/apps", map[string]any{"apps": []App{app, app}}, nil, 400)
	if len(cat.Apps()) != 1 {
		t.Fatal("a refused catalog changed the live one")
	}

	// gateways: issue (the key is shown once), see it, revoke it
	var issued struct {
		Serial, CertPem, KeyPem, CaPem string
	}
	b.send("POST", "/admin/api/gateways", map[string]string{"id": "g1"}, &issued, 200)
	if issued.Serial == "" || !strings.Contains(issued.KeyPem, "PRIVATE KEY") || !strings.Contains(issued.CertPem, "CERTIFICATE") {
		t.Fatalf("issued: %+v", issued)
	}
	if id, ok := GatewayFromCert(parseCert(t, issued.CertPem)); !ok || id != "g1" {
		t.Fatalf("certificate identity: %q %v", id, ok)
	}
	b.send("POST", "/admin/api/gateways", map[string]string{"id": "Bad Id"}, nil, 400)
	var gws []GatewayInfo
	b.get("/admin/api/gateways", &gws, 200)
	if len(gws) != 1 || gws[0].ID != "g1" || gws[0].Online || gws[0].Apps != 1 || len(gws[0].Certs) != 1 || gws[0].Certs[0].Revoked {
		t.Fatalf("gateways: %+v", gws)
	}
	if strings.Contains(mustJSON(gws), "PRIVATE KEY") {
		t.Fatal("the key is kept")
	}
	b.send("POST", "/admin/api/gateways/g1/revoke", nil, nil, 200)
	if !NewRevocations(f.rev).Revoked(parseCert(t, issued.CertPem)) {
		t.Fatal("the gateway certificate is not revoked")
	}
	b.get("/admin/api/gateways", &gws, 200)
	if !gws[0].Certs[0].Revoked {
		t.Fatalf("gateways after revoke: %+v", gws)
	}
	b.send("POST", "/admin/api/gateways/Bad%20Id/revoke", nil, nil, 400)

	var kinds []Event
	b.get("/admin/api/events?kind=admin.&limit=50", &kinds, 200)
	seen := map[string]bool{}
	for _, e := range kinds {
		seen[e.Kind] = true
	}
	for _, k := range []string{"admin.app.save", "admin.gateway.issue", "admin.gateway.revoke"} {
		if !seen[k] {
			t.Fatalf("no %s event: %v", k, seen)
		}
	}

	// the catalog survives a restart
	f.admin.Close()
	f2 := newAdminFixture(t, adminOpts{dir: dir})
	cat2 := NewCatalog()
	if err := f2.admin.SetCatalog(cat2); err != nil {
		t.Fatal(err)
	}
	if len(cat2.Apps()) != 1 || cat2.Apps()[0].Target != "http://10.0.0.5:8080" {
		t.Fatalf("after restart: %+v", cat2.Apps())
	}

	// a catalog kept in a file is shown but not edited
	path := filepath.Join(t.TempDir(), "apps.yaml")
	os.WriteFile(path, []byte("apps: []\n"), 0o600)
	fc, err := LoadCatalogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer fc.Close()
	f3 := newAdminFixture(t, adminOpts{})
	f3.admin.SetCatalog(fc)
	b3 := f3.loggedIn(t)
	b3.get("/admin/api/apps", &got, 200)
	if !got.ReadOnly {
		t.Fatalf("file catalog: %+v", got)
	}
	b3.send("PUT", "/admin/api/apps", map[string]any{"apps": []App{app}}, nil, 400)
}

func TestAppsAreNotAvailableWithoutACatalog(t *testing.T) {
	f := newAdminFixture(t, adminOpts{})
	b := f.loggedIn(t)
	var got struct {
		Enabled bool `json:"enabled"`
	}
	b.get("/admin/api/apps", &got, 200)
	if got.Enabled {
		t.Fatal("apps enabled without a catalog")
	}
	b.send("PUT", "/admin/api/apps", map[string]any{"apps": []App{}}, nil, 404)
}

func enrollDevice(t *testing.T, f *adminFixture, user, pass, email, device string) string {
	t.Helper()
	csr, _ := testCSR(t, email)
	body, _ := json.Marshal(map[string]string{"email": email, "csr": string(csr), "username": user, "password": pass, "device": device})
	resp, err := http.Post(f.ts.URL+"/enroll-auth/local", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		CertPEM string `json:"certPem"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != 200 {
		t.Fatalf("enroll %s: %d", device, resp.StatusCode)
	}
	return out.CertPEM
}

func TestAdminListsAndRevokesDevices(t *testing.T) {
	f := newAdminFixture(t, adminOpts{})
	srv := NewServer(mustStore(t))
	f.admin.SetServer(srv)
	b := f.loggedIn(t)
	b.send("POST", "/admin/api/local-users", map[string]any{"username": "bob", "password": "bobs long password", "email": "bob@example.com"}, nil, 200)
	laptop := enrollDevice(t, f, "bob", "bobs long password", "bob@example.com", "laptop")
	phone1 := enrollDevice(t, f, "bob", "bobs long password", "bob@example.com", "phone")
	phone2 := enrollDevice(t, f, "bob", "bobs long password", "bob@example.com", "phone")
	srv.Store.RememberDevice("bob@example.com", "old-pc")

	var devs []AdminDevice
	b.get("/admin/api/devices?email=Bob@Example.com", &devs, 200)
	byName := map[string]AdminDevice{}
	for _, d := range devs {
		byName[d.Device] = d
	}
	if len(byName["laptop"].Certs) != 1 || len(byName["phone"].Certs) != 2 || len(byName["old-pc"].Certs) != 0 || len(devs) != 3 {
		t.Fatalf("devices: %+v", devs)
	}
	b.get("/admin/api/devices?email=nope", nil, 400)

	// revoking the phone leaves the laptop alone
	rev := NewRevocations(f.rev)
	b.send("POST", "/admin/api/revoke-device", map[string]any{"email": "bob@example.com", "device": "phone", "forget": false}, nil, 200)
	if !rev.Revoked(parseCert(t, phone1)) || !rev.Revoked(parseCert(t, phone2)) || rev.Revoked(parseCert(t, laptop)) {
		t.Fatal("exactly the phone's certificates must be revoked")
	}
	b.get("/admin/api/devices?email=bob@example.com", &devs, 200)
	for _, d := range devs {
		for _, c := range d.Certs {
			if (d.Device == "phone") != c.Revoked {
				t.Fatalf("revoked flags: %+v", d)
			}
		}
	}
	b.send("POST", "/admin/api/revoke-device", map[string]any{"email": "bob@example.com", "device": "phone"}, nil, 404) // nothing active left
	b.send("POST", "/admin/api/revoke-device", map[string]any{"email": "bob@example.com", "device": ""}, nil, 400)
	// forgetting removes it from the user's list
	b.send("POST", "/admin/api/revoke-device", map[string]any{"email": "bob@example.com", "device": "laptop", "forget": true}, nil, 200)
	srv.Store.RememberDevice("bob@example.com", "laptop")
	srv.Store.ForgetDevice("bob@example.com", "old-pc")
	if got := srv.Store.Devices("bob@example.com"); len(got) != 1 || got[0] != "laptop" {
		t.Fatalf("store devices: %v", got)
	}
	// the user's self-service page no longer offers revoked certificates
	if n := len(f.es.activeCerts("bob@example.com")); n != 0 {
		t.Fatalf("active certificates after revoking every device: %d", n)
	}
	var ev []Event
	b.get("/admin/api/events?kind=admin.revoke.device", &ev, 200)
	if len(ev) != 2 {
		t.Fatalf("events: %+v", ev)
	}
}

func TestAdminSendsInvitations(t *testing.T) {
	box := &mailbox{}
	f := newAdminFixture(t, adminOpts{mutate: func(c *EnrollConfig) {
		c.SendMail = box.send
		c.DownloadURL = "https://example.com/download"
	}})
	b := f.loggedIn(t)
	var out struct {
		Sent    int `json:"sent"`
		Results []struct {
			Email string
			OK    bool
			Error string
		}
	}
	b.send("POST", "/admin/api/invite", map[string]any{"emails": []string{"new@example.com", "NEW@example.com", "outside@other.org", "not an address", "second@example.com"}}, &out, 200)
	if out.Sent != 2 || len(out.Results) != 4 {
		t.Fatalf("results: %+v", out)
	}
	msgs := box.wait(t, 2)
	to := map[string]string{}
	for _, m := range msgs {
		to[m.to] = m.body
	}
	if !strings.Contains(to["new@example.com"], "https://example.com/download") || !strings.Contains(to["new@example.com"], f.ts.URL) {
		t.Fatalf("invitation: %s", to["new@example.com"])
	}
	for _, r := range out.Results {
		switch r.Email {
		case "outside@other.org":
			if r.OK || !strings.Contains(r.Error, "domain") {
				t.Fatalf("outside domain: %+v", r)
			}
		case "not an address":
			if r.OK {
				t.Fatal("invalid address invited")
			}
		}
	}
	b.send("POST", "/admin/api/invite", map[string]any{"emails": []string{}}, nil, 400)
	many := make([]string, maxInvites+1)
	for i := range many {
		many[i] = "u" + strconv.Itoa(i) + "@example.com"
	}
	b.send("POST", "/admin/api/invite", map[string]any{"emails": many}, nil, 400)
	// the same person is not invited over and over
	for i := 0; i < 4; i++ {
		b.send("POST", "/admin/api/invite", map[string]any{"emails": []string{"again@example.com"}}, &out, 200)
	}
	if out.Sent != 0 {
		t.Fatalf("a fourth invitation to one person went out: %+v", out)
	}
	var ev []Event
	b.get("/admin/api/events?kind=admin.invite", &ev, 200)
	if len(ev) < 2 {
		t.Fatalf("events: %+v", ev)
	}
}
