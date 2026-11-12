package relay

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func csrFor(t *testing.T, key any, cn string, emails ...string) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, EmailAddresses: emails}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestSignCSRKeysAndIdentity(t *testing.T) {
	dir := t.TempDir()
	if err := InitCA(dir); err != nil {
		t.Fatal(err)
	}
	if err := InitCA(dir); err == nil {
		t.Error("a second CA was created over the first")
	}
	ec256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ec384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ec521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	rsa2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsa1024, _ := rsa.GenerateKey(rand.Reader, 1024)

	ok := map[string][]byte{
		"p256":    csrFor(t, ec256, "x", "ann@example.org"),
		"p384":    csrFor(t, ec384, "x", "ann@example.org"),
		"ed25519": csrFor(t, ed, "x", "ann@example.org"),
		"rsa2048": csrFor(t, rsa2048, "x", "Ann@Example.org"),
		"cn only": csrFor(t, ec256, "ann@example.org"),
	}
	for name, csr := range ok {
		certPEM, err := SignCSR(dir, csr, "ann@example.org", 0)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		block, _ := pem.Decode(certPEM)
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if e, _ := EmailFromCert(cert); e != "ann@example.org" {
			t.Errorf("%s: identity %q", name, e)
		}
		if time.Until(cert.NotAfter) < 80*24*time.Hour { // the default lifetime is 90 days
			t.Errorf("%s: lifetime %v", name, time.Until(cert.NotAfter))
		}
	}
	bad := map[string]struct {
		csr    []byte
		email  string
		device string
	}{
		"other address": {csrFor(t, ec256, "x", "bob@example.org"), "ann@example.org", ""},
		"small rsa":     {csrFor(t, rsa1024, "x", "ann@example.org"), "ann@example.org", ""},
		"p521":          {csrFor(t, ec521, "x", "ann@example.org"), "ann@example.org", ""},
		"not a pem":     {[]byte("nope"), "ann@example.org", ""},
		"wrong type":    {pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2}}), "ann@example.org", ""},
		"garbage der":   {pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte{1, 2}}), "ann@example.org", ""},
		"bad email":     {csrFor(t, ec256, "x", "ann@example.org"), "nonsense", ""},
		"bad device":    {csrFor(t, ec256, "x", "ann@example.org"), "ann@example.org", "bad device!"},
	}
	for name, c := range bad {
		if _, err := SignCSRForDevice(dir, c.csr, c.email, c.device, time.Hour); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// a request with a broken signature
	good := csrFor(t, ec256, "x", "ann@example.org")
	block, _ := pem.Decode(good)
	block.Bytes[len(block.Bytes)-3] ^= 0xff
	if _, err := SignCSR(dir, pem.EncodeToMemory(block), "ann@example.org", time.Hour); err == nil {
		t.Error("a request with a broken signature was signed")
	}
	// no CA at all
	if _, err := SignCSR(t.TempDir(), good, "ann@example.org", time.Hour); err == nil {
		t.Error("signed without a CA")
	}
}

func TestIssueFilesAndErrors(t *testing.T) {
	dir := t.TempDir()
	if err := InitCA(dir); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	if err := IssueServer(dir, out, nil); err == nil {
		t.Error("a server certificate without hosts")
	}
	if err := IssueServer(dir, out, []string{"relay.example.org", "10.0.0.1", "localhost"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(out, "server.pem"))
	block, _ := pem.Decode(b)
	cert, _ := x509.ParseCertificate(block.Bytes)
	if len(cert.DNSNames) != 2 || len(cert.IPAddresses) != 1 {
		t.Errorf("names: %v %v", cert.DNSNames, cert.IPAddresses)
	}
	if err := IssueClient(dir, out, "not an address"); err == nil {
		t.Error("a client certificate for an invalid address")
	}
	if err := IssueClient(dir, out, "ann@example.org"); err != nil {
		t.Fatal(err)
	}
	if err := IssueGateway(dir, filepath.Join(dir, "gw"), "Bad Id"); err == nil {
		t.Error("an invalid gateway id")
	}
	if err := IssueGateway(dir, filepath.Join(dir, "gw"), "gw1"); err != nil {
		t.Fatal(err)
	}
	// without a CA every issue fails
	empty := t.TempDir()
	if err := IssueServer(empty, out, []string{"a.example.org"}); err == nil {
		t.Error("issued without a CA")
	}
	if err := IssueGateway(empty, out, "gw1"); err == nil {
		t.Error("gateway issued without a CA")
	}
	if _, err := newReplicaCertificate(empty, "r1", time.Hour); err == nil {
		t.Error("replica certificate without a CA")
	}
	if c, err := newReplicaCertificate(dir, "r1", time.Hour); err != nil {
		t.Error(err)
	} else if x, _ := x509.ParseCertificate(c.Certificate[0]); x == nil {
		t.Error("unparseable replica certificate")
	} else if id, ok := ReplicaFromCert(x); !ok || id != "r1" {
		t.Errorf("replica id %q", id)
	}
	if _, err := NewGatewayCredentials(dir, "gw1", time.Hour); err != nil {
		t.Error(err)
	}
	// a damaged CA key
	os.WriteFile(filepath.Join(dir, caKey), []byte("junk"), 0o600)
	if _, _, err := loadCA(dir); err == nil {
		t.Error("loaded a damaged CA key")
	}
	if _, err := LoadPool(filepath.Join(dir, "missing.pem")); err == nil {
		t.Error("loaded a missing pool")
	}
	os.WriteFile(filepath.Join(dir, "empty.pem"), []byte("nothing"), 0o644)
	if _, err := LoadPool(filepath.Join(dir, "empty.pem")); err == nil || !strings.Contains(err.Error(), "no certificates") {
		t.Errorf("empty pool: %v", err)
	}
	if _, err := LoadPool(filepath.Join(out, "server.pem")); err != nil {
		t.Error(err)
	}
}

func TestWriteFileAtomicErrors(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.txt")
	if err := WriteFileAtomic(p, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(p, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "two" {
		t.Errorf("content %q", b)
	}
	if s, err := ReadPEMFile(p); err != nil || s != "two" {
		t.Errorf("ReadPEMFile %q %v", s, err)
	}
	if _, err := ReadPEMFile(filepath.Join(dir, "none")); err == nil {
		t.Error("read a missing file")
	}
	if err := WriteFileAtomic(filepath.Join(dir, "no", "dir", "f"), []byte("x"), 0o600); err == nil {
		t.Error("wrote into a missing directory")
	}
	// the destination is a directory: the rename fails and nothing is left behind
	d := filepath.Join(dir, "d")
	os.Mkdir(d, 0o700)
	os.WriteFile(filepath.Join(d, "keep"), []byte("x"), 0o600)
	if err := WriteFileAtomic(d, []byte("x"), 0o600); err == nil {
		t.Error("replaced a directory")
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "d.*.tmp")); len(m) != 0 {
		t.Errorf("temporary files left: %v", m)
	}
}
