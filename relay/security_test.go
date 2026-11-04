package relay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNormalizeEmailRejectsAmbiguousAddresses(t *testing.T) {
	bad := []string{
		"a@evil.com@allowed.com", "a@b@c", "@x.com", "x@", "a b@x.com",
		"a\x00@x.com", "a,b@x.com", "<a@x.com>", "a@x.com\r\nBcc: v@x.com",
	}
	for _, e := range bad {
		if v, ok := NormalizeEmail(e); ok {
			t.Errorf("NormalizeEmail(%q) accepted as %q", e, v)
		}
	}
	for _, e := range []string{"Mario.Rossi@Example.com", "o'brien@example.com", "a+b@example.org"} {
		if _, ok := NormalizeEmail(e); !ok {
			t.Errorf("NormalizeEmail(%q) rejected", e)
		}
	}
}

func TestAllowedDomainCannotBeBypassed(t *testing.T) {
	email, ok := NormalizeEmail("attacker@evil.com@allowed.com")
	if ok && allowedDomain(email, []string{"allowed.com"}) {
		t.Fatal("domain allow-list bypassed with a double @ address")
	}
}

func testCert(t *testing.T, email string, serial int64) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber:   big.NewInt(serial),
		Subject:        pkix.Name{CommonName: email},
		EmailAddresses: []string{email},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func TestRevocations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revoked.txt")
	r := NewRevocations(path)
	bob := testCert(t, "bob@example.com", 0x1234)
	if r.Revoked(bob) {
		t.Fatal("nothing is revoked yet")
	}
	if err := Revoke(path, "Bob@Example.com"); err != nil {
		t.Fatal(err)
	}
	// Force the mtime forward so the reload is observed even on coarse clocks.
	os.Chtimes(path, time.Now().Add(time.Second), time.Now().Add(time.Second))
	if !r.Revoked(bob) {
		t.Fatal("e-mail revocation not applied")
	}
	if r.Revoked(testCert(t, "alice@example.com", 9)) {
		t.Fatal("unrelated identity revoked")
	}
	if err := Revoke(path, "serial:ABCD"); err != nil {
		t.Fatal(err)
	}
	os.Chtimes(path, time.Now().Add(2*time.Second), time.Now().Add(2*time.Second))
	if !r.Revoked(testCert(t, "carol@example.com", 0xabcd)) {
		t.Fatal("serial revocation not applied")
	}
	if err := Revoke(path, "not an email"); err == nil {
		t.Fatal("invalid entry must be rejected")
	}
	var none *Revocations
	if none.Revoked(bob) {
		t.Fatal("nil list revokes nothing")
	}
}

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	// A pre-created symlink at the old predictable name must not be followed.
	victim := filepath.Join(dir, "victim")
	os.WriteFile(victim, []byte("keep"), 0o600)
	os.Symlink(victim, path+".tmp")
	if err := WriteFileAtomic(path, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatalf("symlink target was overwritten: %q", b)
	}
	if b, _ := os.ReadFile(path); string(b) != "data" {
		t.Fatalf("unexpected content %q", b)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode().Perm())
	}
}

func TestEnrollPruneExpiredState(t *testing.T) {
	s := &EnrollServer{items: map[string]*Enrollment{}, rate: map[string][]time.Time{}}
	now := time.Now()
	s.items["old"] = &Enrollment{ID: "old", Expires: now.Add(-3 * time.Hour)}
	s.items["live"] = &Enrollment{ID: "live", Expires: now.Add(time.Minute)}
	s.rate["ip:1.1.1.1"] = []time.Time{now.Add(-time.Hour)}
	s.rate["ip:2.2.2.2"] = []time.Time{now}
	s.mu.Lock()
	s.pruneLocked(now, now.Add(-enrollRateWindow))
	s.mu.Unlock()
	if _, ok := s.items["old"]; ok {
		t.Error("expired enrollment kept")
	}
	if _, ok := s.items["live"]; !ok {
		t.Error("live enrollment dropped")
	}
	if _, ok := s.rate["ip:1.1.1.1"]; ok {
		t.Error("stale rate entry kept")
	}
	if _, ok := s.rate["ip:2.2.2.2"]; !ok {
		t.Error("fresh rate entry dropped")
	}
}

func TestClientIPForwardedFor(t *testing.T) {
	r := httptest.NewRequest("POST", "/enroll", nil)
	r.RemoteAddr = "10.0.0.5:1234"
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 203.0.113.9")
	if got := (&EnrollServer{}).clientIP(r); got != "10.0.0.5" {
		t.Errorf("untrusted XFF must be ignored, got %s", got)
	}
	if got := (&EnrollServer{cfg: EnrollConfig{TrustForwardedFor: true}}).clientIP(r); got != "203.0.113.9" {
		t.Errorf("trusted XFF: got %s", got)
	}
}
