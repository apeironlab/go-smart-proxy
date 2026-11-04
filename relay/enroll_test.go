package relay

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func testCSR(t *testing.T, email string) (csrPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: email},
		EmailAddresses: []string{email},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})
}

func testEnrollServer(t *testing.T) (*httptest.Server, *string) {
	t.Helper()
	dir := t.TempDir()
	if err := InitCA(filepath.Join(dir, "ca")); err != nil {
		t.Fatal(err)
	}
	code := new(string)
	es, err := NewEnrollServer(EnrollConfig{
		CADir:       filepath.Join(dir, "ca"),
		PublicRelay: "relay.example.com:8443",
		SendMail: func(to, subject, body string) error {
			// Other mails (the notification of a new device) carry no code and,
			// sent in the background, must not touch it.
			re := regexp.MustCompile(`[A-Z2-9]{4}-[A-Z2-9]{4}`)
			if c := re.FindString(body); c != "" {
				*code = c
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(es.Handler())
	t.Cleanup(ts.Close)
	return ts, code
}

func postJSONTest(t *testing.T, url, bearer string, in, out any, want int) {
	t.Helper()
	b, _ := json.Marshal(in)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != want {
		var e map[string]string
		json.NewDecoder(resp.Body).Decode(&e)
		t.Fatalf("status = %d, want %d (%v)", resp.StatusCode, want, e)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLoginAuth(t *testing.T) {
	a := &loginAuth{user: "alice", pass: "secret"}
	mech, _, err := a.Start(nil)
	if err != nil || mech != "LOGIN" {
		t.Fatalf("Start = %q, %v", mech, err)
	}
	if b, err := a.Next([]byte("Username:"), true); err != nil || string(b) != "alice" {
		t.Fatalf("username = %q, %v", b, err)
	}
	if b, err := a.Next([]byte("Password:"), true); err != nil || string(b) != "secret" {
		t.Fatalf("password = %q, %v", b, err)
	}
	if b, err := a.Next(nil, false); err != nil || b != nil {
		t.Fatalf("final = %q, %v", b, err)
	}
}

func TestSendInvite(t *testing.T) {
	var gotTo, gotBody string
	cfg := EnrollConfig{
		PublicURL:   "https://relay.example.com:8444",
		DownloadURL: "https://example.com/proxy.dmg",
		SendMail: func(to, subject, body string) error {
			gotTo, gotBody = to, body
			return nil
		},
	}
	if err := SendInvite(cfg, "alice@example.com"); err != nil {
		t.Fatal(err)
	}
	if gotTo != "alice@example.com" {
		t.Fatalf("to = %q", gotTo)
	}
	if !strings.Contains(gotBody, cfg.PublicURL) || !strings.Contains(gotBody, cfg.DownloadURL) {
		t.Fatalf("invitation body lacks the addresses: %s", gotBody)
	}
}

func TestEnrollmentFlow(t *testing.T) {
	ts, code := testEnrollServer(t)
	email := "alice@example.com"
	csrPEM, keyPEM := testCSR(t, email)

	var created struct {
		ID           string `json:"id"`
		PollToken    string `json:"pollToken"`
		RelayAddress string `json:"relayAddress"`
	}
	postJSONTest(t, ts.URL+"/enroll", "", map[string]string{
		"email": email, "csr": string(csrPEM), "device": "quiet-otter-7f3a",
	}, &created, http.StatusOK)
	if created.ID == "" || created.PollToken == "" || created.RelayAddress != "relay.example.com:8443" {
		t.Fatalf("unexpected enrollment response: %+v", created)
	}
	if *code == "" {
		t.Fatal("the confirmation code was not sent")
	}

	var confirmed struct {
		CertPEM      string `json:"certPem"`
		RelayAddress string `json:"relayAddress"`
	}
	postJSONTest(t, ts.URL+"/enroll/"+created.ID+"/confirm", created.PollToken, map[string]string{
		"code": *code,
	}, &confirmed, http.StatusOK)
	if confirmed.CertPEM == "" {
		t.Fatal("no certificate returned")
	}

	pair, err := tls.X509KeyPair([]byte(confirmed.CertPEM), keyPEM)
	if err != nil {
		t.Fatalf("certificate does not match the private key: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range leaf.EmailAddresses {
		if e == email {
			found = true
		}
	}
	if !found || leaf.NotAfter.Before(time.Now().Add(24*time.Hour)) {
		t.Fatalf("unexpected certificate: emails=%v notAfter=%v", leaf.EmailAddresses, leaf.NotAfter)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("unexpected key usage: %v", leaf.ExtKeyUsage)
	}

	// A wrong code is rejected and does not sign anything.
	csr2, _ := testCSR(t, email)
	var created2 struct {
		ID        string `json:"id"`
		PollToken string `json:"pollToken"`
	}
	postJSONTest(t, ts.URL+"/enroll", "", map[string]string{
		"email": email, "csr": string(csr2), "device": "desktop-1234",
	}, &created2, http.StatusOK)
	postJSONTest(t, ts.URL+"/enroll/"+created2.ID+"/confirm", created2.PollToken, map[string]string{
		"code": "ZZZZ-ZZZZ",
	}, nil, http.StatusForbidden)
}
