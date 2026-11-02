package main

import (
	"errors"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"proxy/relay"
)

func TestRelayEnrollmentTOFU(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca")
	if err := relay.InitCA(ca); err != nil {
		t.Fatal(err)
	}
	mailSent := false
	es, err := relay.NewEnrollServer(relay.EnrollConfig{
		CADir:       ca,
		PublicRelay: "relay.example.com:8443",
		SendMail: func(to, subject, body string) error {
			mailSent = true
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewTLSServer(es.Handler())
	defer ts.Close()

	oldConfig := configuration
	configuration = Configuration{}
	t.Cleanup(func() {
		configuration = oldConfig
		enrollMu.Lock()
		enrollPending, trustPending = nil, nil
		enrollMu.Unlock()
	})

	email := "alice@example.com"
	err = relayEnroll(ts.URL, email, "", "")
	var untrusted *untrustedCertificateError
	if !errors.As(err, &untrusted) {
		t.Fatalf("expected an untrusted certificate prompt, got %v", err)
	}
	if untrusted.Info.Fingerprint == "" || untrusted.Info.Subject == "" {
		t.Fatalf("incomplete certificate info: %+v", untrusted.Info)
	}

	if err := relayEnroll(ts.URL, email, "", untrusted.Info.Fingerprint); err != nil {
		t.Fatalf("enrollment after accepting the fingerprint failed: %v", err)
	}
	if !mailSent {
		t.Fatal("the confirmation email was not sent")
	}
	enrollMu.Lock()
	p := enrollPending
	enrollMu.Unlock()
	if p == nil || p.ServerPin == "" || p.ID == "" {
		t.Fatalf("incomplete pending enrollment: %+v", p)
	}
}
