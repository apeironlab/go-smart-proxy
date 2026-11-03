package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPlaintextConfigurationIsMigrated(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	oldConfig := configuration
	t.Cleanup(func() {
		configuration = oldConfig
		clearConfigCrypto()
	})
	t.Setenv(secretEnv, "test-master-password")
	t.Setenv(noKeychainEnv, "1")

	legacy := []byte("Address: 127.0.0.1:9999\nSocksAddress: 127.0.0.1:1088\nOnboardingDone: false\nRoutes: []\n")
	if err := os.WriteFile(plainConfig, legacy, 0o600); err != nil {
		t.Fatal(err)
	}

	loadConfigurationOrSetup()

	if configuration.Address != "127.0.0.1:9999" || configuration.SocksAddress != "127.0.0.1:1088" {
		t.Fatalf("the plaintext configuration was not loaded: %+v", configuration)
	}
	if _, err := os.Stat(plainConfig); !os.IsNotExist(err) {
		t.Fatal("the plaintext configuration must be removed after migration")
	}
	if _, err := os.Stat(encryptedConfig); err != nil {
		t.Fatalf("the encrypted configuration was not written: %v", err)
	}
	if _, _, ok := configCrypto(); !ok {
		t.Fatal("the configuration key was not cached after migration")
	}
}

func TestUnlockHandler(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	oldConfig := configuration
	t.Cleanup(func() {
		configuration = oldConfig
		clearConfigCrypto()
	})
	t.Setenv(noKeychainEnv, "1")
	t.Setenv(secretEnv, "")

	plain := []byte("Address: 127.0.0.1:9997\nRoutes: []\n")
	enc, err := encryptSecret("test-master-password", plain)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSecretFileAtomic(encryptedConfig, enc); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	var once bool
	finish := func() {
		if !once {
			once = true
			close(done)
		}
	}
	srv := httptest.NewServer(authHandler("test-token", "127.0.0.1:3128", "127.0.0.1:1080", setupModeUnlock, enc, finish))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/?token=test-token")
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unlock page: status %d", resp.StatusCode)
	}
	if !strings.Contains(string(page), `data-i18n="unlock_title"`) {
		t.Fatal("the unlock page is missing the unlock title")
	}
	if !strings.Contains(string(page), `const endpoint = '/api/unlock'`) {
		t.Fatal("the unlock page is missing the unlock endpoint")
	}

	resp, err = http.Post(srv.URL+"/api/unlock?token=test-token", "application/json",
		strings.NewReader(`{"password":"wrong-password"}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(string(body), `"wrong_password"`) {
		t.Fatalf("wrong password: status %d body %s", resp.StatusCode, body)
	}

	resp, err = http.Post(srv.URL+"/api/unlock?token=test-token", "application/json",
		strings.NewReader(`{"password":"test-master-password"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unlock: status %d", resp.StatusCode)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("unlock did not complete")
	}
	if configuration.Address != "127.0.0.1:9997" {
		t.Fatalf("unlocked configuration = %+v", configuration)
	}
	if _, _, ok := configCrypto(); !ok {
		t.Fatal("the configuration key was not cached after unlock")
	}
}
