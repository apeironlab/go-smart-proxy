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

func TestEncryptionRefusesBadInput(t *testing.T) {
	salt := make([]byte, secretSaltSize)
	key := make([]byte, secretKeySize)
	if _, err := encryptWithKey(key[:5], salt, []byte("x")); err == nil {
		t.Error("a short key was accepted")
	}
	if _, err := encryptWithKey(key, salt[:5], []byte("x")); err == nil {
		t.Error("a short salt was accepted")
	}
	if _, err := decryptWithKey(key, []byte("short")); err == nil {
		t.Error("a short file was decrypted")
	}
	if _, err := decryptWithKey(key, append([]byte("NOTMAGIC"), make([]byte, 200)...)); err == nil {
		t.Error("a file with a bad header was decrypted")
	}
	enc, _ := encryptWithKey(key, salt, []byte("hello"))
	enc[len(enc)-1] ^= 0xff
	if _, err := decryptWithKey(key, enc); err == nil {
		t.Error("a tampered file was decrypted")
	}
	if _, err := secretSalt([]byte("short")); err == nil {
		t.Error("the salt of a short file")
	}
	if _, err := decryptSecret("pw", []byte("short")); err == nil {
		t.Error("decryptSecret of a short file")
	}
}

func TestInteractiveUnlockWithoutATerminal(t *testing.T) {
	t.Setenv(noKeychainEnv, "1")
	t.Cleanup(clearConfigCrypto)
	data, _ := encryptSecret("a long enough password", []byte("conf"))

	// the environment answers for the user
	t.Setenv(secretEnv, "a long enough password")
	if plain, err := unlockConfigInteractive(data); err != nil || string(plain) != "conf" {
		t.Errorf("unlock with the environment: %q %v", plain, err)
	}
	// nothing stored and no terminal: there is no one to ask, and it says so
	t.Setenv(secretEnv, "")
	clearConfigCrypto()
	if _, err := unlockConfigInteractive(data); err == nil {
		t.Error("unlocked without any password")
	}
	if _, err := newMasterPassword(); err == nil {
		t.Error("a master password out of nowhere")
	}
	if _, err := promptPassword("Master password"); err == nil {
		t.Error("a prompt without a terminal or a dialog tool")
	}
	if _, err := unlockConfigStored([]byte("not encrypted")); err == nil {
		t.Error("garbage was unlocked")
	}
	// a damaged password check via the wrong password
	if _, err := unlockConfigWithPassword(data, "the wrong password"); err != errWrongPassword {
		t.Errorf("wrong password: %v", err)
	}
	if _, err := unlockConfigWithPassword([]byte("junk"), "whatever password"); err == nil {
		t.Error("junk was unlocked")
	}
}
