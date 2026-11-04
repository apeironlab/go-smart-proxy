package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/apeironlab/go-smart-proxy/relay"
)

func leafSerial(t *testing.T, certPEM string) (serial string, device string, notAfter time.Time) {
	t.Helper()
	b, _ := pem.Decode([]byte(certPEM))
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c.SerialNumber.Text(16), relay.DeviceFromCert(c), c.NotAfter
}

func TestProxyRenewsItsCertificateByItself(t *testing.T) {
	oldFirst, oldEvery := renewFirstCheck.Load(), renewEvery.Load()
	renewFirstCheck.Store(int64(200 * time.Millisecond))
	renewEvery.Store(int64(200 * time.Millisecond))
	t.Cleanup(func() { renewFirstCheck.Store(oldFirst); renewEvery.Store(oldEvery) })

	// a configuration that can be saved
	resetEnv(t, nil, nil)
	t.Chdir(t.TempDir())
	oldConfig := configuration
	t.Cleanup(func() { configuration = oldConfig; clearConfigCrypto() })
	t.Setenv(secretEnv, "test-master-password")
	t.Setenv(noKeychainEnv, "1")
	enc, _ := encryptSecret("test-master-password", []byte("Address: 127.0.0.1:9999\nRoutes: []\n"))
	writeSecretFileAtomic(encryptedConfig, enc)
	loadConfiguration()
	relayHub.reset()
	t.Cleanup(relayHub.reset)

	// a relay that renews
	srv, ca, rls := startRenewingRelay(t)
	csr, key, err := generateCSR("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	first, err := relay.SignCSRForDevice(ca, csr, "alice@example.com", "laptop", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &RelayConfig{
		Name: "default", Address: srv.addr, CertPEM: string(first), KeyPEM: string(key), CAPEM: srv.caPEM, Device: "something-else",
	}
	configMu.Lock()
	configuration.Relays = []*RelayConfig{cfg}
	configMu.Unlock()
	c := relayHub.apply(cfg)
	t.Cleanup(c.stop)

	firstSerial, dev, _ := leafSerial(t, string(first))
	if dev != "laptop" {
		t.Fatalf("device in the first certificate: %q", dev)
	}
	waitFor(t, "connected", func() bool { return c.Status().Connected })
	// the device is the certificate's, not the configuration's
	if got := c.Status().Device; got != "laptop" {
		t.Fatalf("device shown: %q", got)
	}

	waitFor(t, "renewed", func() bool {
		configMu.Lock()
		defer configMu.Unlock()
		s, _, _ := leafSerial(t, findRelayConfigLocked("default").CertPEM)
		return s != firstSerial
	})
	configMu.Lock()
	cur := findRelayConfigLocked("default")
	newSerial, newDev, notAfter := leafSerial(t, cur.CertPEM)
	if newDev != "laptop" || cur.Cert != "" || cur.KeyPEM == string(key) {
		configMu.Unlock()
		t.Fatalf("renewed configuration: device %q, key reused: %v", newDev, cur.KeyPEM == string(key))
	}
	// what was saved is what is on disk, encrypted
	if _, err := os.Stat(filepath.Join(".", encryptedConfig)); err != nil {
		t.Fatal(err)
	}
	configMu.Unlock()
	if !notAfter.After(time.Now().Add(23 * time.Hour)) {
		t.Fatalf("new certificate lasts until %v", notAfter)
	}
	// and the connection came back with it
	waitFor(t, "reconnected", func() bool { return c.Status().Connected && rls.lastSerial() == newSerial })

}

type renewingRelay struct{ srv *relay.Server }

func (r *renewingRelay) lastSerial() string {
	for _, d := range r.srv.Online() {
		if d.Email == "alice@example.com" {
			return d.Serial
		}
	}
	return ""
}

// startRenewingRelay is a relay whose renewals give 90-day certificates.
func startRenewingRelay(t *testing.T) (*testRelayServer, string, *renewingRelay) {
	t.Helper()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca")
	if err := relay.InitCA(ca); err != nil {
		t.Fatal(err)
	}
	relay.IssueServer(ca, filepath.Join(dir, "srv"), []string{"127.0.0.1"})
	cfg, err := relay.TLSConfig(filepath.Join(dir, "srv", "server.pem"), filepath.Join(dir, "srv", "server-key.pem"), filepath.Join(ca, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	store, _ := relay.NewStore("")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	srv := relay.NewServer(store)
	srv.SetRenewer(func(c relay.RenewContext, csr []byte) (string, error) {
		b, err := relay.SignCSRForDevice(ca, csr, c.Email, c.Device, 90*24*time.Hour)
		return string(b), err
	})
	go srv.Serve(ln)
	caPEM, _ := os.ReadFile(filepath.Join(ca, "ca.pem"))
	return &testRelayServer{addr: ln.Addr().String(), dir: dir, caPEM: string(caPEM)}, ca, &renewingRelay{srv: srv}
}
