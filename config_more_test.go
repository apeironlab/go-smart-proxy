package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/apeironlab/go-smart-proxy/relay"
)

// legacyRelayFiles writes a relay certificate, key and CA the way old
// configurations kept them, in files.
func legacyRelayFiles(t *testing.T, dir string) (cert, key, ca string) {
	t.Helper()
	caDir := filepath.Join(dir, "ca")
	if err := relay.InitCA(caDir); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "client")
	if err := relay.IssueClient(caDir, out, "ann@example.org"); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(out, "client.pem"), filepath.Join(out, "client-key.pem"), filepath.Join(caDir, "ca.pem")
}

func TestMigrationEmbedsTheLegacyRelayFiles(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv(noKeychainEnv, "1")
	old := configuration
	t.Cleanup(func() { configuration = old; clearConfigCrypto() })
	cert, key, ca := legacyRelayFiles(t, dir)

	if err := migrateToEncryptedWithPassword("short"); err == nil {
		t.Error("a short master password was accepted")
	}
	for name, cfg := range map[string]*RelayConfig{
		"no certificate": {Address: "r.example.org:8443"},
		"missing file":   {Address: "r.example.org:8443", Cert: filepath.Join(dir, "nope.pem"), Key: key},
		"missing key":    {Address: "r.example.org:8443", Cert: cert, Key: filepath.Join(dir, "nope-key.pem")},
		"missing CA":     {Address: "r.example.org:8443", Cert: cert, Key: key, CA: filepath.Join(dir, "nope-ca.pem")},
		"CA not a PEM":   {Address: "r.example.org:8443", Cert: cert, Key: key, CA: key},
		"mismatched":     {Address: "r.example.org:8443", Cert: cert, Key: ca},
	} {
		configuration = Configuration{Relays: []*RelayConfig{cfg}}
		if err := migrateToEncryptedWithPassword("a long enough password"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	configuration = Configuration{Relays: []*RelayConfig{{Address: "r.example.org:8443", Cert: cert, Key: key, CA: ca}, {}}}
	os.WriteFile(plainConfig, []byte("x"), 0o600)
	os.WriteFile(plainConfig+".tmp", []byte("x"), 0o600)
	if err := migrateToEncryptedWithPassword("a long enough password"); err != nil {
		t.Fatal(err)
	}
	r := configuration.Relays[0]
	if r.CertPEM == "" || r.KeyPEM == "" || r.CAPEM == "" {
		t.Errorf("not embedded: %+v", r)
	}
	for _, p := range []string{plainConfig, plainConfig + ".tmp", key} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s was not removed", p)
		}
	}
	if _, err := os.Stat(encryptedConfig); err != nil {
		t.Error("no encrypted configuration")
	}
	if _, err := relayCertificate(r); err != nil {
		t.Errorf("relayCertificate: %v", err)
	}
	if _, err := relayCertificate(&RelayConfig{}); err == nil {
		t.Error("relayCertificate without anything")
	}
}

func TestApplyConfigurationPlaintext(t *testing.T) {
	old := configuration
	t.Cleanup(func() { configuration = old })
	configuration = Configuration{}
	if err := applyConfigurationPlaintext([]byte("Address: [unterminated"), "config.yml"); err == nil || !strings.Contains(err.Error(), "config.yml") {
		t.Errorf("broken YAML: %v", err)
	}
	configuration = Configuration{}
	if err := applyConfigurationPlaintext([]byte("Address: 127.0.0.1:3128\nCredentials:\n  - Name: corp\n    User: ann\n"), "config.yml"); err != nil {
		t.Fatal(err)
	}
	if configuration.OnboardingDone == nil || !*configuration.OnboardingDone {
		t.Error("an existing configuration must not show the onboarding again")
	}
	if c := GetCredential("corp"); c == nil || c.User != "ann" {
		t.Errorf("GetCredential = %+v", c)
	}
	if GetCredential("none") != nil {
		t.Error("an unknown credential was found")
	}
	t.Chdir(t.TempDir())
	if d := GetCacheDir(); d == "" {
		t.Error("no cache directory")
	}
	if st, err := os.Stat("cache"); err != nil || !st.IsDir() {
		t.Error("the cache directory was not created")
	}
}

func TestRestrictConfigurationPermissions(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yml")
	os.WriteFile(p, []byte("x"), 0o644)
	secureConfigFile(p)
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", st.Mode().Perm())
	}
	secureConfigFile(filepath.Join(dir, "missing")) // nothing to fix, no panic
}
