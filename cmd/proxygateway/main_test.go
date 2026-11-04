package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The program refuses to start without a usable configuration: run it as a
// child process and look at the exit status.
func TestGatewayRefusesToStartWithoutCertificate(t *testing.T) {
	if os.Getenv("PROXYGATEWAY_TEST_CHILD") == "1" {
		os.Args = []string{"proxygateway", "-relay", "127.0.0.1:1", "-cert", "/nonexistent.pem", "-key", "/nonexistent-key.pem", "-ca", "/nonexistent-ca.pem"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestGatewayRefusesToStartWithoutCertificate")
	cmd.Env = append(os.Environ(), "PROXYGATEWAY_TEST_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("the gateway started without a certificate: %s", out)
	}
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 1 {
		t.Errorf("exit = %v", err)
	}
	if !strings.Contains(string(out), "nonexistent") {
		t.Errorf("the error does not name the file: %s", out)
	}
}
