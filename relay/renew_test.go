package relay

import (
	"crypto/tls"
	"crypto/x509"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type renewEnv struct {
	*appEnv
	es  *EnrollServer
	box *mailbox
	rev *Revocations
}

func newRenewEnv(t *testing.T, ttl, maxAge time.Duration, domains ...string) (*renewEnv, func(t *testing.T, cert tls.Certificate, device string) *testClient) {
	t.Helper()
	env, _, _ := newAppRelay(t)
	box := &mailbox{}
	rev := NewRevocations(filepath.Join(env.dir, "rev.txt"))
	env.srv.Revoked = rev
	es, err := NewEnrollServer(EnrollConfig{
		CADir: env.ca, PublicRelay: "127.0.0.1:1", PublicURL: "https://enroll.example.com", SendMail: box.send,
		CertTTL: ttl, MaxRenewAge: maxAge, Revoked: rev, AllowedDomains: domains, Store: env.store,
	})
	if err != nil {
		t.Fatal(err)
	}
	env.srv.SetRenewer(es.RenewCertificate)
	pool, _ := LoadPool(filepath.Join(env.ca, "ca.pem"))
	connect := func(t *testing.T, cert tls.Certificate, device string) *testClient {
		return connectTestClient(t, env.addr, pool, cert, "x", device)
	}
	return &renewEnv{appEnv: env, es: es, box: box, rev: rev}, connect
}

// issueFor gives a certificate (and key) the way enrollment does.
func (e *renewEnv) issueFor(t *testing.T, email, device string) tls.Certificate {
	t.Helper()
	csr, key := testCSR(t, email)
	certPEM, err := e.es.sign(csr, email, device, "password", "203.0.113.5")
	if err != nil {
		t.Fatal(err)
	}
	c, err := tls.X509KeyPair([]byte(certPEM), key)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func renewVia(t *testing.T, c *testClient, email string) RenewResp {
	t.Helper()
	csr, _ := testCSR(t, email)
	st, err := c.ys.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	WriteLine(st, RenewReq{T: TRenew, CSR: string(csr)})
	var resp RenewResp
	st.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err := ReadLine(NewReader(st), &resp); err != nil {
		t.Fatalf("renewal answer: %v", err)
	}
	return resp
}

func leafOf(t *testing.T, c tls.Certificate) string {
	t.Helper()
	return serialHex(parseCertDER(t, c.Certificate[0]))
}

func TestCertificateIsBoundToTheDeviceAndTheRelayEnforcesIt(t *testing.T) {
	e, connect := newRenewEnv(t, 24*time.Hour, 0)
	cert := e.issueFor(t, "alice@example.com", "laptop")
	if d := DeviceFromCert(parseCertDER(t, cert.Certificate[0])); d != "laptop" {
		t.Fatalf("device in the certificate: %q", d)
	}
	// the client claims another device: the certificate wins
	c := connect(t, cert, "someone-elses")
	waitFor(t, func() bool { return len(e.srv.Online()) == 1 })
	if d := e.srv.Online()[0].Device; d != "laptop" {
		t.Fatalf("session device %q, want laptop", d)
	}
	// nothing claimed: the certificate gives it
	c.ys.Close()
	waitFor(t, func() bool { return len(e.srv.Online()) == 0 })
	connect(t, cert, "")
	waitFor(t, func() bool { return len(e.srv.Online()) == 1 && e.srv.Online()[0].Device == "laptop" })

	// a user certificate without a device (older ones) keeps working as before
	old := filepath.Join(e.dir, "old")
	if err := IssueClient(e.ca, old, "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	oc, _ := tls.LoadX509KeyPair(filepath.Join(old, "client.pem"), filepath.Join(old, "client-key.pem"))
	connect(t, oc, "pc")
	waitFor(t, func() bool { return len(e.srv.Online()) == 2 })
	found := false
	for _, d := range e.srv.Online() {
		if d.Email == "bob@example.com" && d.Device == "pc" {
			found = true
		}
	}
	if !found {
		t.Fatalf("legacy certificate: %+v", e.srv.Online())
	}
	// an invalid device code cannot be put in a certificate
	csr, _ := testCSR(t, "alice@example.com")
	if _, err := SignCSRForDevice(e.ca, csr, "alice@example.com", "Bad Device!", time.Hour); err == nil {
		t.Fatal("invalid device code accepted")
	}
}

func TestRenewalOverTheAuthenticatedConnection(t *testing.T) {
	e, connect := newRenewEnv(t, 24*time.Hour, 0, "example.com")
	cert := e.issueFor(t, "alice@example.com", "laptop")
	e.box.wait(t, 1) // the notification of the new device
	c := connect(t, cert, "laptop")
	waitFor(t, func() bool { return len(e.srv.Online()) == 1 })

	resp := renewVia(t, c, "alice@example.com")
	if !resp.OK || resp.CertPEM == "" {
		t.Fatalf("renewal: %+v", resp)
	}
	renewed := parseCert(t, resp.CertPEM)
	if serialHex(renewed) == leafOf(t, cert) {
		t.Fatal("the same certificate came back")
	}
	if DeviceFromCert(renewed) != "laptop" || renewed.EmailAddresses[0] != "alice@example.com" {
		t.Fatalf("renewed certificate: %v %v", renewed.URIs, renewed.EmailAddresses)
	}
	// the owner is told, and the audit log has it
	ms := e.box.wait(t, 2)
	if !strings.Contains(ms[1].subject, "rinnovato") || !strings.Contains(ms[1].body, "laptop") {
		t.Fatalf("notice: %+v", ms[1])
	}
	// the old certificate still works until it expires
	connect(t, cert, "laptop")

	// the ledger remembers where the chain started and which device it is
	var led *IssuedCert
	e.es.mu.Lock()
	for _, x := range e.es.certs {
		if x.Serial == serialHex(renewed) {
			led = x
		}
	}
	e.es.mu.Unlock()
	if led == nil || led.Device != "laptop" || led.Method != "renewal" || led.Origin.IsZero() || time.Since(led.Origin) > time.Minute {
		t.Fatalf("ledger entry: %+v", led)
	}
}

func TestRenewalRules(t *testing.T) {
	t.Run("too early", func(t *testing.T) {
		e, connect := newRenewEnv(t, 90*24*time.Hour, 0)
		c := connect(t, e.issueFor(t, "alice@example.com", "laptop"), "laptop")
		waitFor(t, func() bool { return len(e.srv.Online()) == 1 })
		if r := renewVia(t, c, "alice@example.com"); r.OK || !strings.Contains(r.Error, "too early") {
			t.Fatalf("early renewal: %+v", r)
		}
	})
	t.Run("a chain of renewals ends", func(t *testing.T) {
		e, connect := newRenewEnv(t, 24*time.Hour, time.Millisecond)
		c := connect(t, e.issueFor(t, "alice@example.com", "laptop"), "laptop")
		waitFor(t, func() bool { return len(e.srv.Online()) == 1 })
		time.Sleep(20 * time.Millisecond)
		if r := renewVia(t, c, "alice@example.com"); r.OK || !strings.Contains(r.Error, "sign in again") {
			t.Fatalf("old chain: %+v", r)
		}
	})
	t.Run("revoked after connecting", func(t *testing.T) {
		e, connect := newRenewEnv(t, 24*time.Hour, 0)
		cert := e.issueFor(t, "alice@example.com", "laptop")
		c := connect(t, cert, "laptop")
		waitFor(t, func() bool { return len(e.srv.Online()) == 1 })
		e.rev.Add("serial:" + leafOf(t, cert))
		if r := renewVia(t, c, "alice@example.com"); r.OK || !strings.Contains(r.Error, "revoked") {
			t.Fatalf("revoked: %+v", r)
		}
		e.rev.Remove("serial:" + leafOf(t, cert))
		e.rev.Add("alice@example.com")
		if r := renewVia(t, c, "alice@example.com"); r.OK {
			t.Fatalf("identity revoked: %+v", r)
		}
	})
	t.Run("the request must be for the same user", func(t *testing.T) {
		e, connect := newRenewEnv(t, 24*time.Hour, 0)
		c := connect(t, e.issueFor(t, "alice@example.com", "laptop"), "laptop")
		waitFor(t, func() bool { return len(e.srv.Online()) == 1 })
		if r := renewVia(t, c, "bob@example.com"); r.OK {
			t.Fatalf("a certificate for somebody else was issued: %+v", r)
		}
	})
	t.Run("domain no longer allowed", func(t *testing.T) {
		e, connect := newRenewEnv(t, 24*time.Hour, 0, "other.org")
		c := connect(t, e.issueFor(t, "alice@example.com", "laptop"), "laptop")
		waitFor(t, func() bool { return len(e.srv.Online()) == 1 })
		if r := renewVia(t, c, "alice@example.com"); r.OK || !strings.Contains(r.Error, "no longer allowed") {
			t.Fatalf("domain: %+v", r)
		}
	})
	t.Run("an old certificate gets bound to its device when renewed", func(t *testing.T) {
		e, connect := newRenewEnv(t, 24*time.Hour, 0)
		old := filepath.Join(e.dir, "old")
		IssueClient(e.ca, old, "bob@example.com")
		oc, _ := tls.LoadX509KeyPair(filepath.Join(old, "client.pem"), filepath.Join(old, "client-key.pem"))
		c := connect(t, oc, "pc")
		waitFor(t, func() bool { return len(e.srv.Online()) == 1 })
		// IssueClient certificates live two years: too early for them
		if r := renewVia(t, c, "bob@example.com"); r.OK {
			t.Fatalf("two-year certificate renewed at once: %+v", r)
		}
	})
	t.Run("relays without a renewer refuse", func(t *testing.T) {
		e, connect := newRenewEnv(t, 24*time.Hour, 0)
		e.srv.SetRenewer(nil)
		c := connect(t, e.issueFor(t, "alice@example.com", "laptop"), "laptop")
		waitFor(t, func() bool { return len(e.srv.Online()) == 1 })
		if r := renewVia(t, c, "alice@example.com"); r.OK || r.Error == "" {
			t.Fatalf("no renewer: %+v", r)
		}
	})
}

func TestRenewWindow(t *testing.T) {
	now := time.Now()
	if w := RenewWindow(now, now.Add(90*24*time.Hour)); w != 30*24*time.Hour {
		t.Fatalf("90 days: %v", w)
	}
	if w := RenewWindow(now, now.Add(12*24*time.Hour)); w != 7*24*time.Hour {
		t.Fatalf("12 days: %v (at least a week)", w)
	}
	if w := RenewWindow(now, now.Add(24*time.Hour)); w != 24*time.Hour {
		t.Fatalf("one day: %v (never more than its life)", w)
	}
}

func parseCertDER(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
