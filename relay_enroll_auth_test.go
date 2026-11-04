package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"proxy/relay"
)

// enrollEnv gives a test an empty configuration that can be saved.
func enrollEnv(t *testing.T) {
	t.Helper()
	t.Chdir(t.TempDir())
	t.Setenv(noKeychainEnv, "1")
	old := configuration
	t.Cleanup(func() {
		configuration = old
		clearConfigCrypto()
		relayHub.reset()
		relayEnrollCancel()
	})
	configuration = Configuration{}
	relayHub.reset()
	relayEnrollCancel()
	setConfigCrypto(make([]byte, secretKeySize), make([]byte, secretSaltSize))
}

func certPEM(ts *httptest.Server) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}))
}

// realEnrollServer is a relay enrollment endpoint over TLS with a password method.
func realEnrollServer(t *testing.T) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	if err := relay.InitCA(filepath.Join(dir, "ca")); err != nil {
		t.Fatal(err)
	}
	users := filepath.Join(dir, "users.txt")
	if err := relay.AddPasswordUser(users, "alice", "correct horse", "alice@example.com"); err != nil {
		t.Fatal(err)
	}
	es, err := relay.NewEnrollServer(relay.EnrollConfig{
		CADir: filepath.Join(dir, "ca"), PublicRelay: "relay.example.com:8443",
		SendMail: func(to, subject, body string) error { return nil },
		Auth: &relay.AuthConfig{Methods: []relay.AuthMethod{
			{ID: "local", Type: "password", Label: "Company password", Password: &relay.PasswordConfig{UsersFile: users}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewTLSServer(es.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func TestRelayAnswers401WithTheMethods(t *testing.T) {
	enrollEnv(t)
	ts := realEnrollServer(t)
	begin, err := relayEnroll("", ts.URL, "alice@example.com", certPEM(ts), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if begin.CodeSent {
		t.Fatal("a relay that offers several methods must not send a code unasked")
	}
	if len(begin.Methods) != 2 || begin.Methods[0].ID != "email" || begin.Methods[0].Flow != "code" ||
		begin.Methods[1].ID != "local" || begin.Methods[1].Flow != "form" || begin.Methods[1].Label != "Company password" {
		t.Fatalf("methods: %+v", begin.Methods)
	}
	if enrollPendingInfo()["pending"] == true {
		t.Fatal("nothing is pending until the user chooses")
	}

	// choosing the e-mail code asks for it
	begin, err = relayEnroll("", ts.URL, "alice@example.com", certPEM(ts), "", "email")
	if err != nil || !begin.CodeSent {
		t.Fatalf("method email: %+v %v", begin, err)
	}
	if info := enrollPendingInfo(); info["pending"] != true || info["phase"] != "code" {
		t.Fatalf("after asking for the code: %v", info)
	}
	// the other methods do not start here
	if _, err := relayEnroll("", ts.URL, "alice@example.com", certPEM(ts), "", "local"); err == nil {
		t.Fatal("a form method does not start with /enroll")
	}
	if _, err := relayEnroll("", ts.URL, "not an email", certPEM(ts), "", ""); err == nil {
		t.Fatal("an invalid e-mail address is refused before anything is sent")
	}
}

func TestRelaysWithOnlyTheEmailCodeKeepWorking(t *testing.T) {
	enrollEnv(t)
	dir := t.TempDir()
	if err := relay.InitCA(filepath.Join(dir, "ca")); err != nil {
		t.Fatal(err)
	}
	es, err := relay.NewEnrollServer(relay.EnrollConfig{
		CADir: filepath.Join(dir, "ca"), PublicRelay: "relay.example.com:8443",
		SendMail: func(to, subject, body string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewTLSServer(es.Handler())
	defer ts.Close()
	begin, err := relayEnroll("", ts.URL, "alice@example.com", certPEM(ts), "", "")
	if err != nil || !begin.CodeSent || len(begin.Methods) != 0 {
		t.Fatalf("a relay with no other method sends the code straight away: %+v %v", begin, err)
	}
}

func TestEnrollMethodsFromARelayAreSanitized(t *testing.T) {
	enrollEnv(t)
	answer := func(status int, body any) *httptest.Server {
		return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			if s, ok := body.(string); ok {
				io.WriteString(w, s)
				return
			}
			json.NewEncoder(w).Encode(body)
		}))
	}
	evil := answer(401, map[string]any{"methods": []map[string]string{
		{"id": "email", "type": "email", "label": "E-mail", "flow": "code"},
		{"id": "../../x", "type": "oidc", "label": "path trick", "flow": "browser"},
		{"id": "ok", "type": "ldap", "label": strings.Repeat("L", 500), "flow": "form"},
		{"id": "bad", "type": "x", "label": "weird flow", "flow": "javascript"},
		{"id": "email2", "type": "x", "label": "code flow for a non-email id", "flow": "code"},
		{"id": "email", "type": "email", "label": "email id with form flow", "flow": "form"},
	}})
	defer evil.Close()
	begin, err := relayEnroll("", evil.URL, "alice@example.com", certPEM(evil), "", "")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, m := range begin.Methods {
		ids = append(ids, m.ID)
		if len(m.Label) > 60 {
			t.Errorf("labels are bounded: %d", len(m.Label))
		}
	}
	if strings.Join(ids, ",") != "email,ok" {
		t.Fatalf("only well-formed methods may survive, got %v", ids)
	}

	// a 401 that lists nothing usable is an error that says what the relay said
	none := answer(401, map[string]any{"error": "accesso negato dal relay", "methods": []map[string]string{{"id": "x y", "flow": "form"}}})
	defer none.Close()
	if _, err := relayEnroll("", none.URL, "alice@example.com", certPEM(none), "", ""); err == nil || !strings.Contains(err.Error(), "accesso negato dal relay") {
		t.Fatalf("401 with nothing usable: %v", err)
	}
	garbage := answer(401, "<html>proxy login</html>")
	defer garbage.Close()
	if _, err := relayEnroll("", garbage.URL, "alice@example.com", certPEM(garbage), "", ""); err == nil {
		t.Fatal("a 401 that is not ours is an error, not a list")
	}
	// other failures keep the relay's own message
	broken := answer(500, map[string]any{"error": "disco pieno"})
	defer broken.Close()
	if _, err := relayEnroll("", broken.URL, "alice@example.com", certPEM(broken), "", ""); err == nil || !strings.Contains(err.Error(), "disco pieno") {
		t.Fatalf("500: %v", err)
	}
}

func TestUntrustedEnrollmentCertificateIsAPrompt(t *testing.T) {
	enrollEnv(t)
	ts := realEnrollServer(t)
	// no CA given: the self-signed test certificate is not trusted
	_, err := relayEnroll("", ts.URL, "alice@example.com", "", "", "")
	var untrusted *untrustedCertificateError
	if !errorsAs(err, &untrusted) {
		t.Fatalf("expected the fingerprint prompt, got %v", err)
	}
	if untrusted.Info.Fingerprint == "" {
		t.Fatal("the prompt must carry the fingerprint")
	}
	// a fingerprint nobody showed is not accepted
	if _, err := relayEnroll("", ts.URL, "alice@example.com", "", strings.Repeat("ab", 32), ""); err == nil {
		t.Fatal("an unknown fingerprint must be refused")
	}
	// accepting the one that was shown pins the connection; the list comes back
	begin, err := relayEnroll("", ts.URL, "alice@example.com", "", untrusted.Info.Fingerprint, "")
	if err != nil || len(begin.Methods) != 2 {
		t.Fatalf("after accepting: %+v %v", begin, err)
	}
	// ... and so does the sign-in that follows
	if err := relayEnrollLogin("partner", ts.URL, "alice@example.com", "", untrusted.Info.Fingerprint, "local", "alice", "correct horse"); err != nil {
		t.Fatalf("sign-in over the pinned connection: %v", err)
	}
}

func TestEnrollWithPasswordConfiguresTheRelay(t *testing.T) {
	enrollEnv(t)
	ts := realEnrollServer(t)

	err := relayEnrollLogin("partner", ts.URL, "alice@example.com", certPEM(ts), "", "local", "alice", "wrong password")
	if err == nil || !strings.Contains(err.Error(), "utente o password non validi") {
		t.Fatalf("a wrong password: %v", err)
	}
	configMu.Lock()
	n := len(configuration.Relays)
	configMu.Unlock()
	if n != 0 {
		t.Fatal("a failed sign-in must not create a relay")
	}
	if err := relayEnrollLogin("partner", ts.URL, "alice@example.com", certPEM(ts), "", "../x", "alice", "correct horse"); err == nil {
		t.Fatal("an invalid method id is refused")
	}
	if err := relayEnrollLogin("partner", ts.URL, "alice@example.com", certPEM(ts), "", "local", "", ""); err == nil {
		t.Fatal("user and password are required")
	}

	if err := relayEnrollLogin("partner", ts.URL, "alice@example.com", certPEM(ts), "", "local", "alice", "correct horse"); err != nil {
		t.Fatal(err)
	}
	configMu.Lock()
	defer configMu.Unlock()
	if len(configuration.Relays) != 1 {
		t.Fatalf("relays: %+v", configuration.Relays)
	}
	cfg := configuration.Relays[0]
	if cfg.Name != "partner" || cfg.Address != "relay.example.com:8443" || cfg.CertPEM == "" || cfg.KeyPEM == "" || cfg.Device == "" || cfg.EnrollURL != ts.URL {
		t.Fatalf("relay config: %+v", cfg)
	}
	block, _ := pem.Decode([]byte(cfg.CertPEM))
	leaf, _ := x509.ParseCertificate(block.Bytes)
	if e, _ := relay.EmailFromCert(leaf); e != "alice@example.com" {
		t.Fatalf("certificate identity %q", e)
	}
	if _, err := tls.X509KeyPair([]byte(cfg.CertPEM), []byte(cfg.KeyPEM)); err != nil {
		t.Fatalf("the stored key must match the certificate: %v", err)
	}
	if relayHub.get("partner") == nil {
		t.Fatal("the relay client must have been started")
	}
}

// stubBrowserRelay is an enrollment endpoint whose browser sign-in finishes
// when the test says so, issuing a real certificate.
type stubBrowserRelay struct {
	ts      *httptest.Server
	caDir   string
	mu      sync.Mutex
	csr     string
	email   string
	done    bool
	authURL string
	polls   int
}

func newStubBrowserRelay(t *testing.T) *stubBrowserRelay {
	t.Helper()
	s := &stubBrowserRelay{caDir: filepath.Join(t.TempDir(), "ca"), authURL: "https://idp.example.com/login?x=1"}
	if err := relay.InitCA(s.caDir); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /enroll-auth/idp/start", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Email, CSR string }
		json.NewDecoder(r.Body).Decode(&in)
		s.mu.Lock()
		s.csr, s.email = in.CSR, in.Email
		s.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{
			"id": "enr1", "pollToken": "tok1", "authUrl": s.authURL, "relayAddress": "relay.example.com:8443",
			"expiresAt": time.Now().Add(10 * time.Minute),
		})
	})
	mux.HandleFunc("GET /enroll/enr1", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok1" {
			http.Error(w, `{"error":"no"}`, http.StatusNotFound)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		s.polls++
		if !s.done {
			json.NewEncoder(w).Encode(map[string]any{"status": "pending"})
			return
		}
		signed, err := relay.SignCSR(s.caDir, []byte(s.csr), s.email, time.Hour)
		if err != nil {
			t.Error(err)
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "approved", "certPem": string(signed), "relayAddress": "relay.example.com:8443"})
	})
	s.ts = httptest.NewTLSServer(mux)
	t.Cleanup(s.ts.Close)
	return s
}

func (s *stubBrowserRelay) finish() { s.mu.Lock(); s.done = true; s.mu.Unlock() }

func TestEnrollInTheBrowser(t *testing.T) {
	enrollEnv(t)
	s := newStubBrowserRelay(t)

	authURL, err := relayEnrollStart("office", s.ts.URL, "alice@example.com", certPEM(s.ts), "", "idp")
	if err != nil || authURL != s.authURL {
		t.Fatalf("start: %q %v", authURL, err)
	}
	info := enrollPendingInfo()
	if info["pending"] != true || info["phase"] != "browser" || info["authUrl"] != s.authURL || info["name"] != "office" {
		t.Fatalf("pending info: %v", info)
	}

	// still waiting: nothing is configured
	pollBrowserEnrollment()
	configMu.Lock()
	n := len(configuration.Relays)
	configMu.Unlock()
	if n != 0 || enrollPendingInfo()["pending"] != true {
		t.Fatal("before the user signs in nothing changes")
	}
	// the e-mail code does not apply to a browser sign-in
	if err := relayEnrollConfirm("ABCD-EFGH"); err == nil {
		t.Fatal("a browser sign-in cannot be confirmed with a code")
	}

	s.finish()
	pollBrowserEnrollment()
	configMu.Lock()
	defer configMu.Unlock()
	if len(configuration.Relays) != 1 || configuration.Relays[0].Name != "office" || configuration.Relays[0].CertPEM == "" {
		t.Fatalf("after the sign-in: %+v", configuration.Relays)
	}
	// the page, which polls, learns how it ended
	info = enrollPendingInfo()
	res, _ := info["result"].(map[string]any)
	if info["pending"] != false || res == nil || res["name"] != "office" || res["error"] != "" {
		t.Fatalf("the outcome must be reported: %v", info)
	}
	enrollMu.Lock()
	still := enrollPending
	enrollMu.Unlock()
	if still != nil {
		t.Fatal("the enrollment is over")
	}
}

func TestBrowserEnrollmentRefusesStrangeAddresses(t *testing.T) {
	for _, bad := range []string{"javascript:alert(1)", "data:text/html,x", "file:///etc/passwd", "ftp://x/y", "//no-scheme", ""} {
		enrollEnv(t)
		s := newStubBrowserRelay(t)
		s.authURL = bad
		if _, err := relayEnrollStart("", s.ts.URL, "alice@example.com", certPEM(s.ts), "", "idp"); err == nil {
			t.Errorf("the sign-in address %q must be refused", bad)
		}
		if enrollPendingInfo()["pending"] == true {
			t.Errorf("nothing may be left pending for %q", bad)
		}
	}
}

func TestBrowserEnrollmentCanBeCancelledAndExpires(t *testing.T) {
	enrollEnv(t)
	s := newStubBrowserRelay(t)
	if _, err := relayEnrollStart("", s.ts.URL, "alice@example.com", certPEM(s.ts), "", "idp"); err != nil {
		t.Fatal(err)
	}
	relayEnrollCancel()
	if enrollPendingInfo()["pending"] == true {
		t.Fatal("cancelled")
	}
	s.finish()
	pollBrowserEnrollment() // nothing pending: nothing happens
	configMu.Lock()
	n := len(configuration.Relays)
	configMu.Unlock()
	if n != 0 {
		t.Fatal("a cancelled sign-in must not configure anything even if the relay approved it")
	}

	if _, err := relayEnrollStart("", s.ts.URL, "alice@example.com", certPEM(s.ts), "", "idp"); err != nil {
		t.Fatal(err)
	}
	enrollMu.Lock()
	enrollPending.Expires = time.Now().Add(-time.Minute)
	enrollMu.Unlock()
	pollBrowserEnrollment()
	info := enrollPendingInfo()
	if info["pending"] == true {
		t.Fatal("an expired sign-in is dropped")
	}
	if res, _ := info["result"].(map[string]any); res == nil || res["error"] == "" {
		t.Fatalf("an expired sign-in must be reported as failed: %v", info)
	}
	relayEnrollCancel()
	if _, has := enrollPendingInfo()["result"]; has {
		t.Fatal("cancelling clears the outcome")
	}
}

func TestEnrollAPIEndpoints(t *testing.T) {
	enrollEnv(t)
	ts := realEnrollServer(t)
	call := func(method, path, body string) (int, map[string]any) {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		w := httptest.NewRecorder()
		apiMux.ServeHTTP(w, r)
		var out map[string]any
		json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	j := func(m map[string]any) string { b, _ := json.Marshal(m); return string(b) }

	// the untrusted certificate comes back as a question, with its fingerprint
	code, out := call("POST", "/api/relay/enroll", j(map[string]any{"address": ts.URL, "email": "alice@example.com"}))
	cert, _ := out["certificate"].(map[string]any)
	if code != http.StatusConflict || cert == nil || cert["fingerprint"] == "" {
		t.Fatalf("untrusted: %d %v", code, out)
	}
	// the relay's 401 is the next step for the page, not an error
	code, out = call("POST", "/api/relay/enroll", j(map[string]any{"address": ts.URL, "email": "alice@example.com", "caPem": certPEM(ts)}))
	if code != 200 || out["status"] != "auth_required" || out["methods"] == nil || len(out["methods"].([]any)) != 2 {
		t.Fatalf("auth required: %d %v", code, out)
	}
	// choosing the e-mail code
	code, out = call("POST", "/api/relay/enroll", j(map[string]any{"address": ts.URL, "email": "alice@example.com", "caPem": certPEM(ts), "method": "email"}))
	if code != 200 || out["status"] != "code_sent" {
		t.Fatalf("code: %d %v", code, out)
	}
	relayEnrollCancel()
	if code, out = call("POST", "/api/relay/enroll/login", j(map[string]any{
		"name": "partner", "address": ts.URL, "email": "alice@example.com", "caPem": certPEM(ts),
		"method": "local", "username": "alice", "password": "nope",
	})); code != http.StatusBadGateway || !strings.Contains(out["error"].(string), "non validi") {
		t.Fatalf("a wrong password: %d %v", code, out)
	}
	if code, _ = call("POST", "/api/relay/enroll/login", j(map[string]any{
		"name": "partner", "address": ts.URL, "email": "alice@example.com", "caPem": certPEM(ts),
		"method": "local", "username": "alice", "password": "correct horse",
	})); code != 200 {
		t.Fatalf("login: %d", code)
	}
	if code, out = call("GET", "/api/relay/enroll", ""); code != 200 || out["pending"] != false {
		t.Fatalf("nothing is pending afterwards: %d %v", code, out)
	}
	if code, _ = call("POST", "/api/relay/enroll/login", "{broken"); code != 400 {
		t.Fatalf("a malformed body: %d", code)
	}
	if code, _ = call("DELETE", "/api/relay/enroll", ""); code != 200 {
		t.Fatalf("cancel: %d", code)
	}
}

func TestPasswordsAreNeverLogged(t *testing.T) {
	enrollEnv(t)
	ts := realEnrollServer(t)
	var captured strings.Builder
	oldOut := logWriter()
	setLogWriter(&captured)
	defer setLogWriter(oldOut)
	relayEnrollLogin("partner", ts.URL, "alice@example.com", certPEM(ts), "", "local", "alice", "S3cret-password-xyz")
	relayEnrollLogin("partner", ts.URL, "alice@example.com", certPEM(ts), "", "local", "alice", "correct horse")
	if strings.Contains(captured.String(), "S3cret-password-xyz") || strings.Contains(captured.String(), "correct horse") {
		t.Fatalf("a password reached the log:\n%s", captured.String())
	}
}

func errorsAs(err error, target **untrustedCertificateError) bool {
	for err != nil {
		if e, ok := err.(*untrustedCertificateError); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func logWriter() io.Writer     { return log.Writer() }
func setLogWriter(w io.Writer) { log.SetOutput(w) }
