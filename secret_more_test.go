package main

import (
	"strings"
	"testing"
	"time"
)

func TestUnlockConfigStoredFromEnvironment(t *testing.T) {
	t.Setenv(noKeychainEnv, "1")
	t.Cleanup(clearConfigCrypto)
	data, err := encryptSecret("a long enough password", []byte("secret configuration"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(secretEnv, "")
	if _, err := unlockConfigStored(data); err != errConfigLocked {
		t.Errorf("nothing to unlock with: %v", err)
	}
	t.Setenv(secretEnv, "the wrong password")
	if _, err := unlockConfigStored(data); err == nil || !strings.Contains(err.Error(), "wrong master password") {
		t.Errorf("wrong password: %v", err)
	}
	t.Setenv(secretEnv, "a long enough password")
	plain, err := unlockConfigStored(data)
	if err != nil || string(plain) != "secret configuration" {
		t.Fatalf("unlock: %q %v", plain, err)
	}
	if _, _, ok := configCrypto(); !ok {
		t.Error("the key was not kept")
	}
	if _, err := unlockConfigStored([]byte("not an encrypted configuration")); err == nil {
		t.Error("garbage accepted")
	}
}

func TestNewMasterPasswordFromEnvironment(t *testing.T) {
	t.Setenv(secretEnv, "short")
	if _, err := newMasterPassword(); err == nil {
		t.Error("a short password was accepted")
	}
	t.Setenv(secretEnv, "a long enough password")
	if p, err := newMasterPassword(); err != nil || p != "a long enough password" {
		t.Errorf("newMasterPassword = %q %v", p, err)
	}
}

func TestEnrollConfirmRefusals(t *testing.T) {
	enrollMu.Lock()
	old := enrollPending
	enrollPending = nil
	enrollMu.Unlock()
	t.Cleanup(func() { enrollMu.Lock(); enrollPending = old; enrollMu.Unlock() })
	set := func(p *pendingEnrollment) { enrollMu.Lock(); enrollPending = p; enrollMu.Unlock() }

	if err := relayEnrollConfirm("123456"); err == nil {
		t.Error("confirming without an enrollment")
	}
	set(&pendingEnrollment{Method: "browser", Expires: time.Now().Add(time.Minute)})
	if err := relayEnrollConfirm("123456"); err == nil {
		t.Error("a browser sign-in was confirmed with a code")
	}
	set(&pendingEnrollment{Method: "code", Expires: time.Now().Add(-time.Minute)})
	if err := relayEnrollConfirm("123456"); err == nil {
		t.Error("an expired enrollment was confirmed")
	}
	set(&pendingEnrollment{Method: "code", Expires: time.Now().Add(time.Minute)})
	if err := relayEnrollConfirm("  "); err == nil {
		t.Error("an empty code was accepted")
	}
	set(&pendingEnrollment{Method: "code", Expires: time.Now().Add(time.Minute), BaseURL: "https://127.0.0.1:1", ServerCAPEM: "not a pem"})
	if err := relayEnrollConfirm("ab12cd"); err == nil {
		t.Error("a broken CA was accepted")
	}

	// the certificate the relay returns is checked before it is kept
	p := &pendingEnrollment{Name: "home", KeyPEM: []byte("key")}
	for name, res := range map[string]confirmResponse{
		"no certificate":  {},
		"no address":      {CertPEM: "x"},
		"bad address":     {CertPEM: "x", RelayAddress: "no-port"},
		"mismatched pair": {CertPEM: "x", RelayAddress: "relay.example.org:8443"},
	} {
		if err := completeEnrollment(p, res); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
