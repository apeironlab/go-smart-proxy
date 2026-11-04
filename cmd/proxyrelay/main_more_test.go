package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// runMain runs the program itself as a child process, with args, and returns
// its exit status and output.
func runMain(t *testing.T, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], append([]string{"-test.run=TestMainHelper"}, args...)...)
	cmd.Env = append(os.Environ(), "PROXYRELAY_TEST_MAIN=1")
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return code, string(out)
}

// TestMainHelper is the child process: it becomes the program.
func TestMainHelper(t *testing.T) {
	if os.Getenv("PROXYRELAY_TEST_MAIN") != "1" {
		t.Skip("only as a child process")
	}
	var args []string
	for i, a := range os.Args {
		if a == "-test.run=TestMainHelper" {
			args = os.Args[i+1:]
		}
	}
	os.Args = append([]string{"proxyrelay"}, args...)
	main()
	os.Exit(0)
}

func TestMainDispatch(t *testing.T) {
	if code, out := runMain(t); code != 2 || !strings.Contains(out, "usage") {
		t.Errorf("no arguments: %d %s", code, out)
	}
	if code, out := runMain(t, "help"); code != 0 || !strings.Contains(out, "commands:") {
		t.Errorf("help: %d %s", code, out)
	}
	if code, out := runMain(t, "frobnicate"); code != 2 || !strings.Contains(out, "unknown command") {
		t.Errorf("unknown: %d %s", code, out)
	}
	dir := t.TempDir()
	if code, out := runMain(t, "ca"); code != 1 || !strings.Contains(out, "proxyrelay:") {
		t.Errorf("ca without a subcommand: %d %s", code, out)
	}
	if code, _ := runMain(t, "ca", "init", "-dir", filepath.Join(dir, "ca")); code != 0 {
		t.Error("ca init failed")
	}
	if code, _ := runMain(t, "revoke", "-file", filepath.Join(dir, "r.txt"), "a@example.org"); code != 0 {
		t.Error("revoke failed")
	}
	if code, _ := runMain(t, "unrevoke", "-file", filepath.Join(dir, "r.txt"), "a@example.org"); code != 0 {
		t.Error("unrevoke failed")
	}
	if code, _ := runMain(t, "user"); code != 1 {
		t.Error("user without arguments")
	}
	if code, _ := runMain(t, "admin"); code != 1 {
		t.Error("admin without arguments")
	}
	if code, _ := runMain(t, "invite"); code != 1 {
		t.Error("invite without arguments")
	}
	if code, _ := runMain(t, "serve", "-cert", "", "-key", "", "-ca", ""); code != 1 {
		t.Error("serve without certificates")
	}
}

// A small SMTP server that accepts everything.
func startSink(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				fmt.Fprint(c, "220 sink\r\n")
				for {
					l, err := br.ReadString('\n')
					if err != nil {
						return
					}
					switch up := strings.ToUpper(strings.TrimSpace(l)); {
					case strings.HasPrefix(up, "EHLO"), strings.HasPrefix(up, "HELO"):
						fmt.Fprint(c, "250 sink\r\n")
					case up == "DATA":
						fmt.Fprint(c, "354 go\r\n")
						for {
							d, err := br.ReadString('\n')
							if err != nil || d == ".\r\n" {
								break
							}
						}
						fmt.Fprint(c, "250 ok\r\n")
					case up == "QUIT":
						fmt.Fprint(c, "221 bye\r\n")
						return
					default:
						fmt.Fprint(c, "250 ok\r\n")
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func TestInviteSendsTheMail(t *testing.T) {
	smtp := startSink(t)
	t.Setenv("PROXYRELAY_SMTP_TLS", "none")
	err := runInvite([]string{"-email", "ann@example.org", "-public-url", "https://relay.example.org", "-download-url", "https://example.org/dl",
		"-smtp-addr", smtp, "-smtp-from", "relay@example.org"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestServeWithTLSEnrollmentAndAuthConfig(t *testing.T) {
	dir := t.TempDir()
	ca, srvDir := filepath.Join(dir, "ca"), filepath.Join(dir, "server")
	for _, a := range [][]string{{"init", "-dir", ca}, {"server", "-dir", ca, "-out", srvDir, "-host", "127.0.0.1"}} {
		if err := runCA(a); err != nil {
			t.Fatal(err)
		}
	}
	authFile := filepath.Join(dir, "auth.yml")
	os.WriteFile(authFile, []byte("methods:\n  - id: local\n    type: password\n    password:\n      database: true\n"), 0o600)
	smtp := startSink(t)
	t.Setenv("PROXYRELAY_SMTP_TLS", "none")
	relayAddr, enrollAddr := freeAddr(t), freeAddr(t)
	errc := make(chan error, 1)
	go func() {
		errc <- runServe([]string{
			"-listen", relayAddr, "-public-relay", relayAddr, "-public-url", "https://" + enrollAddr,
			"-enroll-listen", enrollAddr, // TLS, with the server's own certificate
			"-cert", filepath.Join(srvDir, "server.pem"), "-key", filepath.Join(srvDir, "server-key.pem"),
			"-ca", filepath.Join(ca, "ca.pem"), "-state", filepath.Join(dir, "state.json"),
			"-enroll-state", filepath.Join(dir, "enroll.json"), "-auth-config", authFile,
			"-admin-db", filepath.Join(dir, "admin.db"), "-admin-emails", "admin@example.org",
			"-smtp-addr", smtp, "-smtp-from", "relay@example.org", "-allow-domains", "example.org",
			"-trust-forwarded-for", "-admin-methods", "local",
		})
	}()
	pool := x509.NewCertPool()
	pem, _ := os.ReadFile(filepath.Join(ca, "ca.pem"))
	pool.AppendCertsFromPEM(pem)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}, Timeout: 3 * time.Second}
	var up bool
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		if resp, err := client.Get("https://" + enrollAddr + "/admin/api/session"); err == nil {
			resp.Body.Close()
			up = true
			break
		}
	}
	if !up {
		t.Fatal("the enrollment listener (TLS) did not come up")
	}
	syscall.Kill(os.Getpid(), syscall.SIGTERM)
	select {
	case err := <-errc:
		if err != nil {
			t.Errorf("runServe: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("runServe did not stop")
	}
}

func TestServeRejectsBrokenInputs(t *testing.T) {
	dir := t.TempDir()
	ca, srvDir := filepath.Join(dir, "ca"), filepath.Join(dir, "server")
	runCA([]string{"init", "-dir", ca})
	runCA([]string{"server", "-dir", ca, "-out", srvDir, "-host", "127.0.0.1"})
	base := []string{
		"-cert", filepath.Join(srvDir, "server.pem"), "-key", filepath.Join(srvDir, "server-key.pem"),
		"-ca", filepath.Join(ca, "ca.pem"), "-state", filepath.Join(dir, "state.json"), "-listen", "127.0.0.1:0",
	}
	badAuth := filepath.Join(dir, "bad-auth.yml")
	os.WriteFile(badAuth, []byte("methods: [this is not valid"), 0o600)
	for name, extra := range map[string][]string{
		"admin session": {"-admin-db", filepath.Join(dir, "a.db"), "-admin-emails", "a@example.org", "-admin-session", "forever"},
		"listen":        {"-listen", "256.0.0.1:99999"},
		"auth config":   {"-enroll-listen", "127.0.0.1:0", "-enroll-plain", "-public-relay", "127.0.0.1:1", "-auth-config", badAuth, "-smtp-addr", "127.0.0.1:1", "-smtp-from", "r@example.org"},
	} {
		if err := runServe(append(append([]string{}, base...), extra...)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// an enrollment that cannot start does not take the relay down: serve() runs until signalled
	_ = hostID()
}
