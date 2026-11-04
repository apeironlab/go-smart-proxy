package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNormalizeEnrollURL(t *testing.T) {
	for _, bad := range []string{"", "   ", "http://relay.example.org", "https://", "https://relay.example.org/enroll", "ftp://relay.example.org"} {
		if _, err := normalizeEnrollURL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for in, want := range map[string]string{
		"relay.example.org:8444":           "https://relay.example.org:8444",
		"https://relay.example.org":        "https://relay.example.org",
		"https://relay.example.org/?x=1":   "https://relay.example.org",
		" https://relay.example.org:8444/": "https://relay.example.org:8444",
	} {
		u, err := normalizeEnrollURL(in)
		if err != nil || u.String() != want {
			t.Errorf("%q -> %v %v, want %s", in, u, err, want)
		}
	}
	if normalizeFingerprint("AB:cd ef") != "abcdef" {
		t.Error("normalizeFingerprint")
	}
	csr, key, err := generateCSR("ann@example.org")
	if err != nil || !strings.Contains(string(csr), "CERTIFICATE REQUEST") || !strings.Contains(string(key), "PRIVATE KEY") {
		t.Errorf("generateCSR: %v", err)
	}
}

func TestEnrollmentClientPinsTheServer(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer ts.Close()
	fp := fingerprintDER(ts.Certificate().Raw)

	good, err := enrollmentClient("", fp, ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	// httptest certificates are for 127.0.0.1 / example.com: the pin matches and the name checks out
	if resp, err := good.Get(ts.URL); err != nil {
		t.Errorf("a pinned server was refused: %v", err)
	} else {
		resp.Body.Close()
	}
	wrong, _ := enrollmentClient("", strings.Repeat("00", 32), ts.URL)
	if _, err := wrong.Get(ts.URL); err == nil || !strings.Contains(err.Error(), "è cambiato") {
		t.Errorf("a different certificate was accepted: %v", err)
	}
	if _, err := enrollmentClient("", fp, "://bad"); err == nil {
		t.Error("a bad base URL was accepted")
	}
	if _, err := enrollmentClient("not a pem", "", ts.URL); err == nil {
		t.Error("a bad CA was accepted")
	}
	if c, err := enrollmentClient("", "", ts.URL); err != nil || c == nil {
		t.Errorf("default client: %v", err)
	}
	// without a pin the system roots apply, and the test server is not among them
	plain, _ := enrollmentClient("", "", ts.URL)
	if _, err := plain.Get(ts.URL); err == nil {
		t.Error("an unknown server was trusted")
	} else if !isCertificateError(err) {
		t.Errorf("not recognised as an untrusted certificate: %v", err)
	}
	_ = tls.VersionTLS12
}

func TestBrowserEnrollmentPollEndsWhenTheRelayForgets(t *testing.T) {
	gone := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusGone) }))
	defer gone.Close()
	pin := fingerprintDER(gone.Certificate().Raw)

	set := func(p *pendingEnrollment) { enrollMu.Lock(); enrollPending = p; enrollResult = nil; enrollMu.Unlock() }
	t.Cleanup(func() { enrollMu.Lock(); enrollPending, enrollResult = nil, nil; enrollMu.Unlock() })

	set(nil)
	pollBrowserEnrollment() // nothing to poll
	set(&pendingEnrollment{Method: "code"})
	pollBrowserEnrollment() // not a browser enrollment

	// expired
	set(&pendingEnrollment{Name: "home", Method: "browser", Expires: time.Now().Add(-time.Minute)})
	pollBrowserEnrollment()
	enrollMu.Lock()
	cleared, res := enrollPending == nil, enrollResult
	enrollMu.Unlock()
	if !cleared || res == nil || res.Error == "" {
		t.Errorf("expired: pending cleared=%v result=%+v", cleared, res)
	}
	// the relay answers 410 Gone
	set(&pendingEnrollment{Name: "home", Method: "browser", BaseURL: gone.URL, ServerPin: pin, ID: "x", PollToken: "t", Expires: time.Now().Add(time.Minute)})
	pollBrowserEnrollment()
	enrollMu.Lock()
	cleared, res = enrollPending == nil, enrollResult
	enrollMu.Unlock()
	if !cleared || res == nil || res.Error == "" {
		t.Errorf("gone: pending cleared=%v result=%+v", cleared, res)
	}
	// a relay that cannot be reached leaves the enrollment pending
	set(&pendingEnrollment{Name: "home", Method: "browser", BaseURL: "https://127.0.0.1:1", ID: "x", PollToken: "t", Expires: time.Now().Add(time.Minute)})
	pollBrowserEnrollment()
	enrollMu.Lock()
	still := enrollPending != nil
	enrollMu.Unlock()
	if !still {
		t.Error("an unreachable relay ended the enrollment")
	}
	// approved with a certificate that does not fit: the enrollment ends with the reason
	bad := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"approved","certPem":"nonsense","relayAddress":"relay.example.org:8443"}`))
	}))
	defer bad.Close()
	set(&pendingEnrollment{Name: "home", Method: "browser", BaseURL: bad.URL, ServerPin: fingerprintDER(bad.Certificate().Raw), ID: "x", PollToken: "t", KeyPEM: []byte("k"), Expires: time.Now().Add(time.Minute)})
	pollBrowserEnrollment()
	enrollMu.Lock()
	cleared, res = enrollPending == nil, enrollResult
	enrollMu.Unlock()
	if !cleared || res == nil || res.Error == "" {
		t.Errorf("bad certificate: cleared=%v result=%+v", cleared, res)
	}
}
