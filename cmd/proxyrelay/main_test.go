package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestHelpers(t *testing.T) {
	t.Setenv("PRX_TEST_ENV", "")
	if env("PRX_TEST_ENV", "def") != "def" {
		t.Error("env default")
	}
	t.Setenv("PRX_TEST_ENV", "x")
	if env("PRX_TEST_ENV", "def") != "x" {
		t.Error("env value")
	}
	if got := splitList(" a, b ,,c "); strings.Join(got, "|") != "a|b|c" {
		t.Errorf("splitList = %v", got)
	}
	if len(splitList("")) != 0 {
		t.Error("splitList empty")
	}
	if d, err := parseTTL("90d"); err != nil || d != 90*24*time.Hour {
		t.Errorf("parseTTL 90d = %v %v", d, err)
	}
	if d, err := parseTTL("36h"); err != nil || d != 36*time.Hour {
		t.Errorf("parseTTL 36h = %v %v", d, err)
	}
	for _, bad := range []string{"0d", "-3d", "xd", "soon"} {
		if _, err := parseTTL(bad); err == nil {
			t.Errorf("parseTTL(%q) accepted", bad)
		}
	}
	if firstNonEmpty("", "b") != "b" || firstNonEmpty("a", "b") != "a" {
		t.Error("firstNonEmpty")
	}
	if id := hostID(); len(id) > 29 || strings.ContainsAny(id, " .A-Z") {
		t.Errorf("hostID = %q", id)
	}
	for addr, want := range map[string]bool{"127.0.0.1:9": true, "localhost:9": true, "[::1]:9": true, "0.0.0.0:9": false, "example.org:9": false, "nope": false} {
		if isLoopbackAddr(addr) != want {
			t.Errorf("isLoopbackAddr(%q) != %v", addr, want)
		}
	}
	if buildVersion() == "" {
		t.Error("buildVersion empty")
	}
}

func TestLogging(t *testing.T) {
	if err := setupLogging("nonsense"); err == nil {
		t.Error("an unknown format was accepted")
	}
	if err := setupLogging("text"); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	_ = buf
	// jsonLog writes records with a level guessed from the text.
	var out bytes.Buffer
	l := newTestLogger(&out)
	for _, msg := range []string{"WARNING: careful", "connection failed", "all fine\n"} {
		if _, err := l.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
	}
	got := out.String()
	for _, want := range []string{`"level":"WARN"`, `"msg":"careful"`, `"msg":"connection failed"`, `"level":"INFO"`} {
		if !strings.Contains(got, want) {
			t.Errorf("log output lacks %s:\n%s", want, got)
		}
	}
	// Switch the process to JSON logging, then back.
	oldOut, oldFlags := log.Writer(), log.Flags()
	defer func() { log.SetOutput(oldOut); log.SetFlags(oldFlags) }()
	if err := setupLogging("json"); err != nil {
		t.Fatal(err)
	}
}

func TestRevokeAndUsers(t *testing.T) {
	dir := t.TempDir()
	list := filepath.Join(dir, "revoked.txt")
	if err := runRevoke([]string{"-file", list}, true); err == nil {
		t.Error("revoking nothing is not an error")
	}
	if err := runRevoke([]string{"-file", list, "Ann@Example.org", "serial:ABC"}, true); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(list)
	if !strings.Contains(string(b), "ann@example.org") || !strings.Contains(string(b), "serial:abc") {
		t.Errorf("list = %q", b)
	}
	if err := runRevoke([]string{"-file", list, "ann@example.org"}, false); err != nil {
		t.Fatal(err)
	}
	if b, _ = os.ReadFile(list); strings.Contains(string(b), "ann@") {
		t.Errorf("unrevoke left %q", b)
	}
	if err := runRevoke([]string{"-file", list, "not an address"}, true); err == nil {
		t.Error("an invalid entry was accepted")
	}

	t.Setenv("PROXYRELAY_PASSWORD", "correct horse battery")
	users := filepath.Join(dir, "users.yml")
	for _, args := range [][]string{nil, {"remove"}, {"add"}, {"add", "-file", users}} {
		if err := runUser(args); err == nil {
			t.Errorf("runUser(%v) accepted", args)
		}
	}
	if err := runUser([]string{"add", "-file", users, "-name", "ann", "-email", "ann@example.org", "-groups", "staff, devops"}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(users); !strings.Contains(string(b), "ann") {
		t.Errorf("users file = %q", b)
	}
	db := filepath.Join(dir, "admin.db")
	for _, args := range [][]string{nil, {"group"}, {"user"}, {"user", "-db", db}} {
		if err := runAdminUser(args); err == nil {
			t.Errorf("runAdminUser(%v) accepted", args)
		}
	}
	if err := runAdminUser([]string{"user", "-db", db, "-name", "root", "-email", "root@example.org", "-groups", "admins"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(db); err != nil {
		t.Error(err)
	}
}

func TestReadPasswordFromInput(t *testing.T) {
	t.Setenv("PROXYRELAY_PASSWORD", "")
	r, w, _ := os.Pipe()
	old := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = old }()
	go func() { fmt.Fprint(w, "from stdin\r\nignored"); w.Close() }()
	pw, err := readPassword()
	if err != nil || pw != "from stdin" {
		t.Errorf("readPassword = %q, %v", pw, err)
	}
	t.Setenv("PROXYRELAY_PASSWORD", "from env")
	if pw, _ := readPassword(); pw != "from env" {
		t.Errorf("readPassword = %q", pw)
	}
}

func TestInviteArguments(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"-email", "a@example.org"},
		{"-email", "a@example.org", "-public-url", "https://relay.example.org"},
	} {
		if err := runInvite(args); err == nil {
			t.Errorf("runInvite(%v) accepted", args)
		}
	}
	// Unreachable SMTP server: the error comes from sending, not from the arguments.
	err := runInvite([]string{"-email", "a@example.org", "-public-url", "https://relay.example.org",
		"-smtp-addr", "127.0.0.1:1", "-smtp-from", "relay@example.org", "-smtp-tls", "none"})
	if err == nil {
		t.Error("an unreachable SMTP server went unnoticed")
	}
}

func TestSMTPFlagsEnvironmentWins(t *testing.T) {
	t.Setenv("PROXYRELAY_SMTP_TLS", "tls")
	t.Setenv("PROXYRELAY_SMTP_AUTH", "plain")
	t.Setenv("PROXYRELAY_SMTP_ADDR", "mail.example.org:465")
	fsf := flagSetForTest()
	f := addSMTPFlags(fsf)
	_ = fsf.Parse(nil)
	var cfgTLS, cfgAuth, cfgAddr string
	c := configForTest()
	f.apply(c)
	cfgTLS, cfgAuth, cfgAddr = c.SMTPTLS, c.SMTPAuth, c.SMTPAddr
	if cfgTLS != "tls" || cfgAuth != "plain" || cfgAddr != "mail.example.org:465" {
		t.Errorf("smtp = %q %q %q", cfgTLS, cfgAuth, cfgAddr)
	}
}

func TestCAAndServe(t *testing.T) {
	dir := t.TempDir()
	ca, srvDir := filepath.Join(dir, "ca"), filepath.Join(dir, "server")
	for _, args := range [][]string{nil, {"bogus"}, {"server", "-dir", ca}, {"client", "-dir", ca}, {"gateway", "-dir", ca}} {
		if err := runCA(args); err == nil {
			t.Errorf("runCA(%v) accepted", args)
		}
	}
	if err := runCA([]string{"init", "-dir", ca}); err != nil {
		t.Fatal(err)
	}
	if err := runCA([]string{"server", "-dir", ca, "-out", srvDir, "-host", "127.0.0.1,localhost"}); err != nil {
		t.Fatal(err)
	}
	if err := runCA([]string{"client", "-dir", ca, "-out", filepath.Join(dir, "c"), "-email", "a@example.org"}); err != nil {
		t.Fatal(err)
	}
	if err := runCA([]string{"gateway", "-dir", ca, "-out", filepath.Join(dir, "g"), "-id", "gw1"}); err != nil {
		t.Fatal(err)
	}

	relayAddr, enrollAddr, metricsAddr := freeAddr(t), freeAddr(t), freeAddr(t)
	t.Setenv("PROXYRELAY_SMTP_TLS", "none")
	errc := make(chan error, 1)
	go func() {
		errc <- runServe([]string{
			"-listen", relayAddr, "-public-relay", relayAddr, "-public-url", "http://" + enrollAddr,
			"-enroll-listen", enrollAddr, "-enroll-plain",
			"-cert", filepath.Join(srvDir, "server.pem"), "-key", filepath.Join(srvDir, "server-key.pem"),
			"-ca", filepath.Join(ca, "ca.pem"), "-state", filepath.Join(dir, "state.json"),
			"-enroll-state", filepath.Join(dir, "enroll.json"),
			"-admin-db", filepath.Join(dir, "admin.db"), "-admin-emails", "admin@example.org",
			"-smtp-addr", "127.0.0.1:1", "-smtp-from", "relay@example.org",
			"-metrics-listen", metricsAddr, "-metrics-token", "s3cret",
			"-cert-ttl", "30d", "-max-renew-age", "90d", "-admin-session", "1h",
		})
	}()
	waitHTTP(t, "http://"+metricsAddr+"/healthz", "")
	waitHTTP(t, "http://"+enrollAddr+"/admin/api/session", "")
	if resp, err := http.Get("http://" + metricsAddr + "/metrics"); err == nil {
		if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
			t.Errorf("/metrics without the token answered %d", resp.StatusCode)
		}
		resp.Body.Close()
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		if err != nil {
			t.Errorf("runServe: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("runServe did not stop")
	}
}

func TestServeSharedSQLiteAndFiles(t *testing.T) {
	dir := t.TempDir()
	ca, srvDir := filepath.Join(dir, "ca"), filepath.Join(dir, "server")
	if err := runCA([]string{"init", "-dir", ca}); err != nil {
		t.Fatal(err)
	}
	if err := runCA([]string{"server", "-dir", ca, "-out", srvDir, "-host", "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	apps := filepath.Join(dir, "apps.yml")
	policy := filepath.Join(dir, "policy.yml")
	os.WriteFile(apps, []byte("apps: []\n"), 0o600)
	os.WriteFile(policy, []byte("rules: []\nlists: []\nallow: []\n"), 0o600)
	base := []string{
		"-cert", filepath.Join(srvDir, "server.pem"), "-key", filepath.Join(srvDir, "server-key.pem"),
		"-ca", filepath.Join(ca, "ca.pem"), "-state", filepath.Join(dir, "state.json"),
	}
	// Mistakes in the arguments are reported, not ignored.
	for name, extra := range map[string][]string{
		"log format":   {"-log-format", "yaml"},
		"cert ttl":     {"-cert-ttl", "soon"},
		"renew age":    {"-max-renew-age", "soon"},
		"missing cert": {"-cert", ""},
		"bad apps":     {"-apps", filepath.Join(dir, "missing.yml")},
		"bad policy":   {"-policy", filepath.Join(dir, "missing.yml")},
		"peer on file": {"-db", filepath.Join(dir, "shared.db"), "-peer-addr", "127.0.0.1:1"},
	} {
		if err := runServe(append(append([]string{}, base...), extra...)); err == nil {
			t.Errorf("%s: runServe accepted it", name)
		}
	}

	relayAddr, metricsAddr := freeAddr(t), freeAddr(t)
	errc := make(chan error, 1)
	go func() {
		errc <- runServe(append(append([]string{}, base...),
			"-listen", relayAddr, "-db", filepath.Join(dir, "shared.db"), "-replica-id", "r1",
			"-public-relay", relayAddr, "-apps", apps, "-policy", policy, "-policy-dir", filepath.Join(dir, "lists"),
			"-admin-emails", "admin@example.org", "-metrics-listen", metricsAddr, "-log-format", "json"))
	}()
	waitHTTP(t, "http://"+metricsAddr+"/readyz", "")
	syscall.Kill(os.Getpid(), syscall.SIGTERM)
	select {
	case err := <-errc:
		if err != nil {
			t.Errorf("runServe: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("runServe did not stop")
	}
	log.SetOutput(os.Stderr)
	log.SetFlags(log.LstdFlags)
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func waitHTTP(t *testing.T, url, _ string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(url); err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s did not come up", url)
}
