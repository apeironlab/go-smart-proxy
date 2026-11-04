package relay

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func init() { bcryptCost = bcrypt.MinCost } // keep the tests fast

// authServer starts an enrollment server with the given sign-in methods. The
// public address is only known once the server listens, so the handler is
// reached through an indirection.
func authServer(t *testing.T, mutate func(*EnrollConfig, string)) (*httptest.Server, *EnrollServer) {
	t.Helper()
	dir := t.TempDir()
	if err := InitCA(filepath.Join(dir, "ca")); err != nil {
		t.Fatal(err)
	}
	var h http.Handler = http.NotFoundHandler()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	t.Cleanup(ts.Close)
	cfg := EnrollConfig{
		CADir:       filepath.Join(dir, "ca"),
		PublicRelay: "relay.example.com:8443",
		PublicURL:   ts.URL,
		SendMail:    func(to, subject, body string) error { return nil },
	}
	if mutate != nil {
		mutate(&cfg, dir)
	}
	es, err := NewEnrollServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h = es.Handler()
	return ts, es
}

func certEmail(t *testing.T, certPEM string) string {
	t.Helper()
	b, _ := pem.Decode([]byte(certPEM))
	if b == nil {
		t.Fatal("no certificate in the answer")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	e, ok := EmailFromCert(c)
	if !ok {
		t.Fatal("certificate without e-mail identity")
	}
	return e
}

func TestGroupMatches(t *testing.T) {
	have := []string{"CN=VPN-Users,OU=Groups,DC=example,DC=com", "staff"}
	cases := []struct {
		need []string
		want bool
	}{
		{nil, true},
		{[]string{"vpn-users"}, true}, // CN of a distinguished name
		{[]string{"CN=VPN-Users,OU=Groups,DC=example,DC=com"}, true}, // the whole DN
		{[]string{"STAFF"}, true},                                    // case-insensitive
		{[]string{"admins", "staff"}, true},                          // any of
		{[]string{"admins"}, false},
		{[]string{"users"}, false}, // no partial match
		{[]string{""}, false},
	}
	for _, c := range cases {
		if got := groupMatches(have, c.need); got != c.want {
			t.Errorf("groupMatches(%v) = %v", c.need, got)
		}
	}
	if groupMatches(nil, []string{"x"}) {
		t.Error("nobody is in a required group")
	}
}

func TestAuthConfigValidation(t *testing.T) {
	ok := AuthMethod{ID: "local", Type: "password", Password: &PasswordConfig{UsersFile: "u.txt"}}
	if err := (&AuthConfig{Methods: []AuthMethod{ok}}).Validate(); err != nil {
		t.Fatal(err)
	}
	if (*AuthConfig)(nil).Validate() != nil {
		t.Fatal("no config is valid")
	}
	bad := map[string]AuthMethod{
		"bad id":          {ID: "Bad Id", Type: "password", Password: &PasswordConfig{UsersFile: "u"}},
		"reserved id":     {ID: "email", Type: "password", Password: &PasswordConfig{UsersFile: "u"}},
		"no section":      {ID: "x", Type: "password"},
		"two sections":    {ID: "x", Type: "password", Password: &PasswordConfig{UsersFile: "u"}, LDAP: &LDAPConfig{}},
		"type mismatch":   {ID: "x", Type: "ldap", Password: &PasswordConfig{UsersFile: "u"}},
		"unknown type":    {ID: "x", Type: "kerberos", Password: &PasswordConfig{UsersFile: "u"}},
		"empty users":     {ID: "x", Type: "password", Password: &PasswordConfig{}},
		"plain ldap":      {ID: "x", Type: "ldap", LDAP: &LDAPConfig{URL: "ldap://dir.example.com", BaseDN: "dc=example"}},
		"ldap no base":    {ID: "x", Type: "ldap", LDAP: &LDAPConfig{URL: "ldaps://dir.example.com"}},
		"ldap bad filter": {ID: "x", Type: "ldap", LDAP: &LDAPConfig{URL: "ldaps://d", BaseDN: "dc=e", UserFilter: "(uid=bob)"}},
		"ldap bind no pw": {ID: "x", Type: "ldap", LDAP: &LDAPConfig{URL: "ldaps://d", BaseDN: "dc=e", BindDN: "cn=svc"}},
		"oidc http":       {ID: "x", Type: "oidc", OIDC: &OIDCConfig{Issuer: "http://idp.example.com", ClientID: "c"}},
		"oidc no client":  {ID: "x", Type: "oidc", OIDC: &OIDCConfig{Issuer: "https://idp.example.com"}},
		"saml neither":    {ID: "x", Type: "saml", SAML: &SAMLConfig{}},
		"saml both":       {ID: "x", Type: "saml", SAML: &SAMLConfig{IDPMetadataURL: "https://i/m", IDPMetadataFile: "m.xml"}},
		"saml half key":   {ID: "x", Type: "saml", SAML: &SAMLConfig{IDPMetadataFile: "m.xml", CertFile: "c.pem"}},
	}
	for name, m := range bad {
		if err := (&AuthConfig{Methods: []AuthMethod{m}}).Validate(); err == nil {
			t.Errorf("%s must be rejected", name)
		}
	}
	if err := (&AuthConfig{Methods: []AuthMethod{ok, ok}}).Validate(); err == nil {
		t.Error("duplicate ids must be rejected")
	}
	if err := (&AuthConfig{Methods: []AuthMethod{{ID: "l", Type: "ldap", LDAP: &LDAPConfig{URL: "ldap://d", StartTLS: true, BaseDN: "dc=e"}}}}).Validate(); err != nil {
		t.Errorf("ldap with start_tls is fine: %v", err)
	}
}

func TestLoadAuthConfigExpandsSecretsFromTheEnvironment(t *testing.T) {
	t.Setenv("TEST_LDAP_PW", "s3cret")
	path := filepath.Join(t.TempDir(), "auth.yml")
	os.WriteFile(path, []byte(`
disable_email: true
methods:
  - id: dir
    type: ldap
    label: Directory
    ldap:
      url: ldaps://dir.example.com
      bind_dn: cn=svc,dc=example,dc=com
      bind_password: ${TEST_LDAP_PW}
      base_dn: dc=example,dc=com
      require_groups: [vpn]
`), 0o600)
	cfg, err := LoadAuthConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.DisableEmail || cfg.Methods[0].LDAP.BindPassword != "s3cret" || cfg.Methods[0].LDAP.RequireGroups[0] != "vpn" {
		t.Fatalf("%+v", cfg.Methods[0].LDAP)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	// a typo in a key is an error, not silently ignored
	os.WriteFile(path, []byte("methods:\n  - id: x\n    typ: password\n"), 0o600)
	if _, err := LoadAuthConfig(path); err == nil {
		t.Fatal("unknown keys must be rejected")
	}
}

func usersFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "users.txt")
	if err := AddPasswordUser(path, "alice", "correct horse", "alice@example.com", "staff", "vpn"); err != nil {
		t.Fatal(err)
	}
	if err := AddPasswordUser(path, "bob@example.com", "battery staple", ""); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPasswordMethod(t *testing.T) {
	path := usersFile(t)
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("users file mode %v", info.Mode().Perm())
	}
	m, err := newPasswordMethod(&PasswordConfig{UsersFile: path})
	if err != nil {
		t.Fatal(err)
	}
	id, err := m.Authenticate(nil, " Alice ", "correct horse")
	if err != nil || id.Email != "alice@example.com" || len(id.Groups) != 2 {
		t.Fatalf("alice: %+v %v", id, err)
	}
	if id, err := m.Authenticate(nil, "bob@example.com", "battery staple"); err != nil || id.Email != "bob@example.com" {
		t.Fatalf("a user name that is an e-mail address: %+v %v", id, err)
	}
	for _, c := range [][2]string{{"alice", "wrong"}, {"nobody", "correct horse"}, {"alice", ""}, {"", ""}} {
		if _, err := m.Authenticate(nil, c[0], c[1]); err != ErrInvalidCredentials {
			t.Errorf("%v must give ErrInvalidCredentials, got %v", c, err)
		}
	}

	// the file is re-read when it changes
	time.Sleep(10 * time.Millisecond)
	AddPasswordUser(path, "carol", "twelve chars!", "carol@example.com")
	os.Chtimes(path, time.Now().Add(time.Minute), time.Now().Add(time.Minute))
	if _, err := m.Authenticate(nil, "carol", "twelve chars!"); err != nil {
		t.Fatalf("a user added later: %v", err)
	}

	if _, err := HashPassword("short"); err == nil {
		t.Error("short passwords are refused")
	}
	if err := AddPasswordUser(path, "bad name", "long enough pw", "x@example.com"); err == nil {
		t.Error("a user name with spaces is refused")
	}
	os.WriteFile(path, []byte("broken line\n"), 0o600)
	if _, err := newPasswordMethod(&PasswordConfig{UsersFile: path}); err == nil {
		t.Error("a malformed users file is an error at start-up")
	}
}

func TestEnrollOverHTTPWithPassword(t *testing.T) {
	path := usersFile(t)
	ts, _ := authServer(t, func(c *EnrollConfig, _ string) {
		c.AllowedDomains = []string{"example.com"}
		c.Auth = &AuthConfig{Methods: []AuthMethod{
			{ID: "local", Type: "password", Label: "Company password", Password: &PasswordConfig{UsersFile: path}},
			{ID: "vpnonly", Type: "password", Password: &PasswordConfig{UsersFile: path, RequireGroups: []string{"vpn"}}},
		}}
	})

	// discovery: the normal request, with no method, is answered 401 with the
	// ways to authenticate, and nothing is sent
	probe := func(body map[string]string) (*http.Response, []methodInfo) {
		csr, _ := testCSR(t, "alice@example.com")
		body["csr"] = string(csr)
		b, _ := json.Marshal(body)
		resp, err := http.Post(ts.URL+"/enroll", "application/json", strings.NewReader(string(b)))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out struct {
			Error   string       `json:"error"`
			Methods []methodInfo `json:"methods"`
		}
		json.NewDecoder(resp.Body).Decode(&out)
		return resp, out.Methods
	}
	resp, methods := probe(map[string]string{"email": "alice@example.com"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a request with no method must get 401, got %d", resp.StatusCode)
	}
	if len(methods) != 3 || methods[0].ID != "email" || methods[0].Flow != "code" ||
		methods[1].ID != "local" || methods[1].Label != "Company password" || methods[1].Flow != "form" || methods[2].ID != "vpnonly" {
		t.Fatalf("methods: %+v", methods)
	}
	challenges := resp.Header.Values("WWW-Authenticate")
	if len(challenges) != 3 || !strings.HasPrefix(challenges[0], "GSP-Code ") ||
		challenges[1] != `GSP-Form id="local", type="password", realm="Company password"` {
		t.Fatalf("WWW-Authenticate: %q", challenges)
	}
	// asking for the e-mail code by name works and sends it
	if resp, _ := probe(map[string]string{"email": "alice@example.com", "method": "email"}); resp.StatusCode != 200 {
		t.Fatalf("method email: %d", resp.StatusCode)
	}
	// other methods are not reached through /enroll
	if resp, _ := probe(map[string]string{"email": "alice@example.com", "method": "local"}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("method local on /enroll: %d", resp.StatusCode)
	}
	// an address that may not enroll is told so, not given the list
	csr, _ := testCSR(t, "mallory@evil.example")
	postJSONTest(t, ts.URL+"/enroll", "", map[string]string{"email": "mallory@evil.example", "csr": string(csr)}, nil, http.StatusForbidden)

	login := func(method, email, user, pass string, want int) map[string]any {
		csr, _ := testCSR(t, email)
		var out map[string]any
		postJSONTest(t, ts.URL+"/enroll-auth/"+method, "", map[string]string{
			"email": email, "csr": string(csr), "device": "laptop", "username": user, "password": pass,
		}, &out, want)
		return out
	}
	out := login("local", "alice@example.com", "alice", "correct horse", 200)
	if got := certEmail(t, out["certPem"].(string)); got != "alice@example.com" {
		t.Fatalf("certificate for %q", got)
	}
	if out["relayAddress"] != "relay.example.com:8443" {
		t.Fatalf("relay address: %v", out["relayAddress"])
	}

	// refusals never say whether the user exists
	{
		csr, _ := testCSR(t, "alice@example.com")
		b, _ := json.Marshal(map[string]string{"email": "alice@example.com", "csr": string(csr), "username": "alice", "password": "wrong"})
		resp, err := http.Post(ts.URL+"/enroll-auth/local", "application/json", strings.NewReader(string(b)))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), `GSP-Form id="local"`) {
			t.Fatalf("a wrong password: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
		}
	}
	a := login("local", "alice@example.com", "alice", "wrong", http.StatusUnauthorized)
	b := login("local", "alice@example.com", "nobody", "whatever", http.StatusUnauthorized)
	if a["error"] != b["error"] {
		t.Fatalf("unknown user and wrong password must look the same: %v / %v", a, b)
	}
	// a valid login for another address cannot be used to get alice's certificate
	login("local", "mallory@example.com", "alice", "correct horse", http.StatusForbidden)
	// Bob is not in the vpn group
	login("vpnonly", "bob@example.com", "bob@example.com", "battery staple", http.StatusForbidden)
	login("vpnonly", "alice@example.com", "alice", "correct horse", 200)
	// domain list, unknown method, wrong flow
	login("local", "alice@evil.example", "alice", "correct horse", http.StatusForbidden)
	login("nope", "alice@example.com", "alice", "correct horse", http.StatusNotFound)
	csr, _ = testCSR(t, "alice@example.com")
	postJSONTest(t, ts.URL+"/enroll-auth/local/start", "", map[string]string{"email": "alice@example.com", "csr": string(csr)}, nil, http.StatusBadRequest)

	// a certificate request for someone else is refused before any password check
	other, _ := testCSR(t, "carol@example.com")
	postJSONTest(t, ts.URL+"/enroll-auth/local", "", map[string]string{
		"email": "alice@example.com", "csr": string(other), "username": "alice", "password": "correct horse",
	}, nil, http.StatusBadRequest)
}

func TestPasswordGuessingIsSlowedDown(t *testing.T) {
	path := usersFile(t)
	ts, _ := authServer(t, func(c *EnrollConfig, _ string) {
		c.Auth = &AuthConfig{Methods: []AuthMethod{{ID: "local", Type: "password", Password: &PasswordConfig{UsersFile: path}}}}
	})
	csr, _ := testCSR(t, "alice@example.com")
	try := func(pass string, want int) {
		postJSONTest(t, ts.URL+"/enroll-auth/local", "", map[string]string{
			"email": "alice@example.com", "csr": string(csr), "username": "alice", "password": pass,
		}, nil, want)
	}
	for i := 0; i < 10; i++ {
		try("wrong", http.StatusUnauthorized)
	}
	// from now on even the right password is refused for a while
	try("correct horse", http.StatusTooManyRequests)
}

func TestEmailCodeCanBeSwitchedOff(t *testing.T) {
	path := usersFile(t)
	ts, _ := authServer(t, func(c *EnrollConfig, _ string) {
		c.SendMail = nil // not needed: there is no e-mail code
		c.Auth = &AuthConfig{DisableEmail: true, Methods: []AuthMethod{{ID: "local", Type: "password", Password: &PasswordConfig{UsersFile: path}}}}
	})
	csr, _ := testCSR(t, "alice@example.com")
	b, _ := json.Marshal(map[string]string{"email": "alice@example.com", "csr": string(csr)})
	resp, err := http.Post(ts.URL+"/enroll", "application/json", strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	var out struct{ Methods []methodInfo }
	json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || len(out.Methods) != 1 || out.Methods[0].ID != "local" {
		t.Fatalf("only the password method must be offered: %d %+v", resp.StatusCode, out.Methods)
	}
	// asking for the code anyway is refused
	postJSONTest(t, ts.URL+"/enroll", "", map[string]string{"email": "alice@example.com", "csr": string(csr), "method": "email"}, nil, http.StatusForbidden)

	// and a relay with no way left to enroll refuses to start
	dir := t.TempDir()
	InitCA(filepath.Join(dir, "ca"))
	if _, err := NewEnrollServer(EnrollConfig{CADir: filepath.Join(dir, "ca"), PublicRelay: "r:1", Auth: &AuthConfig{DisableEmail: true}}); err == nil ||
		!strings.Contains(err.Error(), "no other method") {
		t.Fatalf("e-mail off and nothing else: %v", err)
	}
}

func TestRelaysWithoutAuthConfigAnswerAsAlwaysAndDoNotChallenge(t *testing.T) {
	ts, code := testEnrollServer(t)
	csr, _ := testCSR(t, "alice@example.com")
	// no method named: the e-mail code is sent, as before (no 401)
	postJSONTest(t, ts.URL+"/enroll", "", map[string]string{"email": "alice@example.com", "csr": string(csr)}, nil, 200)
	if *code == "" {
		t.Fatal("the e-mail code must have been sent")
	}
	// naming the e-mail method is the same
	postJSONTest(t, ts.URL+"/enroll", "", map[string]string{"email": "bob@example.com", "csr": string(mustCSR(t, "bob@example.com")), "method": "email"}, nil, 200)
	// the method endpoints do not exist
	postJSONTest(t, ts.URL+"/enroll-auth/local", "", map[string]string{}, nil, http.StatusNotFound)
}

func mustCSR(t *testing.T, email string) []byte {
	csr, _ := testCSR(t, email)
	return csr
}

func jsonDecode(r interface{ Read([]byte) (int, error) }, v any) { json.NewDecoder(r).Decode(v) }
