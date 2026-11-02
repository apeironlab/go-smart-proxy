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

func TestSetupHandler(t *testing.T) {
	t.Chdir(t.TempDir())
	oldConfig := configuration
	t.Cleanup(func() {
		configuration = oldConfig
		clearConfigCrypto()
	})
	t.Setenv(noKeychainEnv, "1")

	done := make(chan struct{})
	var once bool
	finish := func() {
		if !once {
			once = true
			close(done)
		}
	}
	srv := httptest.NewServer(setupHandler("test-token", "127.0.0.1:3128", "127.0.0.1:1080", finish))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/?token=wrong")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong token: status %d", resp.StatusCode)
	}

	resp, err = http.Get(srv.URL + "/?token=test-token")
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(page), "Scegli la master password") {
		t.Fatalf("setup page: status %d", resp.StatusCode)
	}

	resp, err = http.Post(srv.URL+"/api/setup?token=test-token", "application/json",
		strings.NewReader(`{"password":"short","confirm":"short"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("short password: status %d", resp.StatusCode)
	}

	resp, err = http.Post(srv.URL+"/api/setup?token=test-token", "application/json",
		strings.NewReader(`{"password":"test-master-password","confirm":"test-master-password"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("setup: status %d", resp.StatusCode)
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("setup did not complete")
	}
	if configuration.Address != "127.0.0.1:3128" || configuration.SocksAddress != "127.0.0.1:1080" {
		t.Fatalf("unexpected configuration: %+v", configuration)
	}
	if configuration.OnboardingDone == nil || *configuration.OnboardingDone {
		t.Fatal("onboarding should be pending")
	}
	if _, err := os.Stat(encryptedConfig); err != nil {
		t.Fatalf("encrypted config missing: %v", err)
	}
	if _, _, ok := configCrypto(); !ok {
		t.Fatal("the configuration key was not cached")
	}
}
