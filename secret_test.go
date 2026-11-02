package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"proxy/relay"

	"gopkg.in/yaml.v3"
)

func TestSecretRoundtrip(t *testing.T) {
	plain := []byte("Address: 127.0.0.1:3128\nCredentials:\n  - Name: corp\n    Password: top-secret\n")
	enc1, err := encryptSecret("correct horse battery staple", plain)
	if err != nil {
		t.Fatal(err)
	}
	enc2, err := encryptSecret("correct horse battery staple", plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(enc1, enc2) {
		t.Fatal("two encryptions of the same plaintext must differ (random salt/nonce)")
	}

	got, err := decryptSecret("correct horse battery staple", enc1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("roundtrip mismatch: %q", got)
	}

	if _, err := decryptSecret("wrong password", enc1); err == nil {
		t.Fatal("decryption with a wrong password must fail")
	}
}

func TestEmbeddedRelayCertificate(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca")
	if err := relay.InitCA(ca); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "client")
	if err := relay.IssueClient(ca, out, "alice@example.com"); err != nil {
		t.Fatal(err)
	}
	certPEM, err := os.ReadFile(filepath.Join(out, "client.pem"))
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(out, "client-key.pem"))
	if err != nil {
		t.Fatal(err)
	}

	cfg := &RelayConfig{CertPEM: string(certPEM), KeyPEM: string(keyPEM)}
	if _, err := relayCertificate(cfg); err != nil {
		t.Fatalf("embedded certificate must load: %v", err)
	}

	cfg.KeyPEM = string(certPEM) // not a private key
	if _, err := relayCertificate(cfg); err == nil {
		t.Fatal("an invalid key pair must be rejected")
	}
}

func TestKeychainBridge(t *testing.T) {
	if os.Getenv("PROXY_TEST_KEYCHAIN") != "1" {
		t.Skip("set PROXY_TEST_KEYCHAIN=1 to exercise the system keychain")
	}
	service := "go-smart-proxy-test"
	account := "bridge"
	keychainDelete(service, account)
	if err := keychainStore(service, account, "test-secret"); err != nil {
		t.Fatal(err)
	}
	defer keychainDelete(service, account)
	if !keychainExists(service, account) {
		t.Fatal("keychain item not found after storing it")
	}
	got, err := keychainLoad(service, account)
	if err != nil {
		t.Fatal(err)
	}
	if got != "test-secret" {
		t.Fatalf("keychain returned %q", got)
	}
}

func TestLoadEncryptedConfiguration(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	oldConfig := configuration
	t.Cleanup(func() {
		configuration = oldConfig
		clearConfigCrypto()
	})
	t.Setenv(secretEnv, "test-master-password")
	t.Setenv(noKeychainEnv, "1")

	plain := []byte("Address: 127.0.0.1:9999\nRelay:\n  Address: relay.example.com:8443\nRoutes: []\n")
	enc, err := encryptSecret("test-master-password", plain)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSecretFileAtomic(encryptedConfig, enc); err != nil {
		t.Fatal(err)
	}

	loadConfiguration()
	if configuration.Address != "127.0.0.1:9999" {
		t.Fatalf("address = %q, want 127.0.0.1:9999", configuration.Address)
	}
	if configuration.Relay == nil || configuration.Relay.Device == "" {
		t.Fatal("the relay device code was not generated")
	}
	if _, _, ok := configCrypto(); !ok {
		t.Fatal("the configuration key was not cached after loading")
	}
}

func TestFirstRunDefaults(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	oldConfig := configuration
	t.Cleanup(func() {
		configuration = oldConfig
		clearConfigCrypto()
	})
	t.Setenv(secretEnv, "test-master-password")
	t.Setenv(noKeychainEnv, "1")

	loadConfiguration()
	if configuration.Address != "127.0.0.1:3128" {
		t.Fatalf("default address = %q", configuration.Address)
	}
	if configuration.Relay != nil {
		t.Fatalf("unexpected relay config: %+v", configuration.Relay)
	}
	if _, err := os.Stat(encryptedConfig); err != nil {
		t.Fatalf("the encrypted configuration was not created: %v", err)
	}
	if _, _, ok := configCrypto(); !ok {
		t.Fatal("the configuration key was not cached")
	}
}

func TestPersistReusesKeyAndSalt(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	oldConfig := configuration
	t.Cleanup(func() {
		configuration = oldConfig
		clearConfigCrypto()
	})
	t.Setenv(secretEnv, "test-master-password")
	t.Setenv(noKeychainEnv, "1")

	enc, err := encryptSecret("test-master-password", []byte("Address: 127.0.0.1:9998\nRoutes: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	saltBefore, err := secretSalt(enc)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSecretFileAtomic(encryptedConfig, enc); err != nil {
		t.Fatal(err)
	}

	loadConfiguration()
	configuration.Address = "127.0.0.1:9997"
	if err := persistConfigurationLocked(); err != nil {
		t.Fatal(err)
	}

	after, err := os.ReadFile(encryptedConfig)
	if err != nil {
		t.Fatal(err)
	}
	saltAfter, err := secretSalt(after)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(saltBefore, saltAfter) {
		t.Fatal("the salt must not change when saving, or the keychain key would be invalidated")
	}
	plain, err := decryptSecret("test-master-password", after)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(plain, []byte("127.0.0.1:9997")) {
		t.Fatalf("saved configuration does not contain the change: %s", plain)
	}
}

func TestMigrationToEncrypted(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca")
	if err := relay.InitCA(ca); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "client")
	if err := relay.IssueClient(ca, out, "alice@example.com"); err != nil {
		t.Fatal(err)
	}

	oldConfig := configuration
	t.Cleanup(func() {
		configuration = oldConfig
		clearConfigCrypto()
	})
	t.Chdir(dir)
	t.Setenv(secretEnv, "test-master-password")
	t.Setenv(noKeychainEnv, "1")

	configuration = Configuration{
		Address: "127.0.0.1:3128",
		Relay: &RelayConfig{
			Address: "relay.example.com:8443",
			Cert:    filepath.Join(out, "client.pem"),
			Key:     filepath.Join(out, "client-key.pem"),
			CA:      filepath.Join(ca, "ca.pem"),
		},
	}
	if err := os.WriteFile(plainConfig, []byte("Address: 127.0.0.1:3128\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := migrateToEncrypted(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(plainConfig); !os.IsNotExist(err) {
		t.Fatal("the plaintext configuration must be removed after migration")
	}
	if _, err := os.Stat(filepath.Join(out, "client-key.pem")); !os.IsNotExist(err) {
		t.Fatal("the plaintext relay key must be removed after migration")
	}
	if _, _, ok := configCrypto(); !ok {
		t.Fatal("the configuration key must remain available in memory")
	}

	enc, err := os.ReadFile(encryptedConfig)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := decryptSecret("test-master-password", enc)
	if err != nil {
		t.Fatal(err)
	}
	var got Configuration
	if err := yaml.Unmarshal(plain, &got); err != nil {
		t.Fatal(err)
	}
	if got.Relay == nil || got.Relay.CertPEM == "" || got.Relay.KeyPEM == "" || got.Relay.CAPEM == "" {
		t.Fatalf("relay material was not embedded: %+v", got.Relay)
	}
}
