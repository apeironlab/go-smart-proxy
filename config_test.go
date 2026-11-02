package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSecureConfigFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permissions are not meaningful on Windows")
	}
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte("Password: secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	secureConfigFile(path)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("permissions = %o, want 600", got)
	}
}

func TestCredentialsAPIDoesNotLeakPassword(t *testing.T) {
	configuration = Configuration{Credentials: []ConfigCredential{
		{Name: "corp", User: "alice", Password: "very-secret"},
	}}
	t.Cleanup(func() { configuration = Configuration{} })

	rr := httptest.NewRecorder()
	apiListCredentials(rr, httptest.NewRequest(http.MethodGet, "/api/credentials", nil))
	body := rr.Body.String()
	if strings.Contains(body, "very-secret") {
		t.Fatalf("the API leaked the password: %s", body)
	}
	if !strings.Contains(body, `"hasPassword": true`) {
		t.Fatalf("hasPassword missing: %s", body)
	}
}
