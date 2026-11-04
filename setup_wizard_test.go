package main

import (
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func postSetup(t *testing.T, base, path, body string) int {
	t.Helper()
	resp, err := http.Post(base+path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestSetupPagesRefuseBadRequests(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv(noKeychainEnv, "1")
	old := configuration
	t.Cleanup(func() { configuration = old; clearConfigCrypto() })

	for _, mode := range []setupMode{setupModeCreate, setupModeMigrate, setupModeUnlock} {
		srv := httptest.NewServer(authHandler("tok", "127.0.0.1:3128", "127.0.0.1:1080", mode, nil, func() {}))
		cfg := setupPageConfigFor(mode)
		ep := cfg.endpoint + "?token="
		if c := postSetup(t, srv.URL, ep+"nope", `{"password":"a long enough password","confirm":"a long enough password"}`); c != http.StatusForbidden {
			t.Errorf("%s: wrong token: %d", mode, c)
		}
		if c := postSetup(t, srv.URL, ep+"tok", `{`); c != http.StatusBadRequest {
			t.Errorf("%s: not json: %d", mode, c)
		}
		if mode == setupModeUnlock {
			if c := postSetup(t, srv.URL, ep+"tok", `{"password":""}`); c != http.StatusBadRequest {
				t.Errorf("%s: empty password: %d", mode, c)
			}
		} else {
			if c := postSetup(t, srv.URL, ep+"tok", `{"password":"short","confirm":"short"}`); c != http.StatusBadRequest {
				t.Errorf("%s: short password: %d", mode, c)
			}
			if c := postSetup(t, srv.URL, ep+"tok", `{"password":"a long enough password","confirm":"another long password"}`); c != http.StatusBadRequest {
				t.Errorf("%s: mismatch: %d", mode, c)
			}
		}
		if resp, err := http.Get(srv.URL + "/?token=tok"); err != nil || resp.StatusCode != http.StatusOK {
			t.Errorf("%s: page: %v", mode, err)
		} else {
			resp.Body.Close()
		}
		srv.Close()
	}
}

func TestMigrationThroughThePage(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv(noKeychainEnv, "1")
	old := configuration
	t.Cleanup(func() { configuration = old; clearConfigCrypto() })
	configuration = Configuration{Address: "127.0.0.1:3128"}

	done := make(chan struct{}, 1)
	srv := httptest.NewServer(authHandler("tok", "127.0.0.1:3128", "127.0.0.1:1080", setupModeMigrate, nil, func() { done <- struct{}{} }))
	defer srv.Close()
	body := `{"password":"a long enough password","confirm":"a long enough password"}`
	if c := postSetup(t, srv.URL, "/api/migrate?token=tok", body); c != http.StatusOK {
		t.Fatalf("migrate: %d", c)
	}
	if _, err := os.Stat(encryptedConfig); err != nil {
		t.Error("no encrypted configuration after the migration")
	}
	// the page works once
	if c := postSetup(t, srv.URL, "/api/migrate?token=tok", body); c != http.StatusConflict {
		t.Errorf("second time: %d", c)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("the page did not report completion")
	}
}

func TestUnlockThroughThePageWithTheWrongPassword(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv(noKeychainEnv, "1")
	old := configuration
	t.Cleanup(func() { configuration = old; clearConfigCrypto() })
	data, _ := encryptSecret("the right password", []byte("Address: 127.0.0.1:3128\n"))
	srv := httptest.NewServer(authHandler("tok", "127.0.0.1:3128", "127.0.0.1:1080", setupModeUnlock, data, func() {}))
	defer srv.Close()
	if c := postSetup(t, srv.URL, "/api/unlock?token=tok", `{"password":"not the right one"}`); c != http.StatusUnauthorized {
		t.Errorf("wrong password: %d", c)
	}
	// a configuration that cannot be read at all is an internal error
	bad := httptest.NewServer(authHandler("tok", "127.0.0.1:3128", "127.0.0.1:1080", setupModeUnlock, []byte("junk"), func() {}))
	defer bad.Close()
	if c := postSetup(t, bad.URL, "/api/unlock?token=tok", `{"password":"whatever"}`); c != http.StatusInternalServerError {
		t.Errorf("damaged configuration: %d", c)
	}
}

func TestSetupFromTheEnvironmentRefusesAShortPassword(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv(noKeychainEnv, "1")
	if err := createInitialConfig("short", "127.0.0.1:3128", "127.0.0.1:1080"); err == nil {
		t.Error("a short master password was accepted")
	}
	if configExists() {
		t.Error("a configuration exists after a refusal")
	}
	old := configuration
	t.Cleanup(func() { configuration = old; clearConfigCrypto() })
	if err := createInitialConfig("a long enough password", "127.0.0.1:3128", "127.0.0.1:1080"); err != nil {
		t.Fatal(err)
	}
	if !configExists() {
		t.Error("no configuration after creating one")
	}
}

// A log writer that lets the test read the address the wizard announces.
type logTap struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (l *logTap) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logTap) wizardURL() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, f := range strings.Fields(l.buf.String()) {
		if strings.HasPrefix(f, "http://127.0.0.1:") && strings.Contains(f, "?token=") {
			return f
		}
	}
	return ""
}

func TestWizardsRunToCompletion(t *testing.T) {
	t.Setenv(noKeychainEnv, "1")
	t.Setenv(secretEnv, "")
	old := configuration
	oldOut := log.Writer()
	t.Cleanup(func() { configuration = old; clearConfigCrypto(); log.SetOutput(oldOut) })

	run := func(name string, wizard func() error, endpoint, body string) {
		t.Helper()
		tap := &logTap{}
		log.SetOutput(tap)
		errc := make(chan error, 1)
		go func() { errc <- wizard() }()
		var url string
		for end := time.Now().Add(5 * time.Second); time.Now().Before(end) && url == ""; time.Sleep(20 * time.Millisecond) {
			url = tap.wizardURL()
		}
		if url == "" {
			t.Fatalf("%s: the wizard did not announce its address", name)
		}
		base, token, _ := strings.Cut(url, "/?token=")
		resp, err := http.Post(base+endpoint+"?token="+token, "application/json", strings.NewReader(body))
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %v %v", name, err, resp)
		}
		resp.Body.Close()
		select {
		case err := <-errc:
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: the wizard did not finish", name)
		}
	}

	t.Chdir(t.TempDir())
	configuration = Configuration{}
	run("setup", runSetupWizard, "/api/setup", `{"password":"a long enough password","confirm":"a long enough password"}`)

	data, _ := encryptSecret("a long enough password", []byte("Address: 127.0.0.1:3128\n"))
	run("unlock", func() error { return runUnlockWizard(data) }, "/api/unlock", `{"password":"a long enough password"}`)

	t.Chdir(t.TempDir())
	configuration = Configuration{Address: "127.0.0.1:3128"}
	run("migration", runMigrationWizard, "/api/migrate", `{"password":"a long enough password","confirm":"a long enough password"}`)
}
