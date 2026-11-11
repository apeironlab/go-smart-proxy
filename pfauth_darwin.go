//go:build darwin

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Starting the privileged helper: when the transparent routing is needed and
// the helper is not running, the user is asked (a dialog, unless the mode is
// "auto") and then macOS asks for the fingerprint or the password.

const helperInstallPath = "/Library/PrivilegedHelperTools/proxyroute-helper"

var (
	authMu       sync.Mutex
	authBusy     bool
	authDeclined = map[string]bool{} // by interfaces: said "not now" in this run
	authFailedAt time.Time
)

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// describeTargets names the services and interfaces for the user.
func describeTargets(targets []activeService) string {
	var parts []string
	for _, t := range targets {
		parts = append(parts, fmt.Sprintf("«%s» (interfaccia %s)", t.Name, t.Iface))
	}
	return strings.Join(parts, ", ")
}

// requestHelper starts, in the background, whatever is needed to get the
// helper: the question to the user and the authentication.
func requestHelper(targets []activeService, key string) {
	mode := transparentMode()
	authMu.Lock()
	if authBusy || authDeclined[key] || time.Since(authFailedAt) < 2*time.Minute {
		authMu.Unlock()
		return
	}
	authBusy = true
	authMu.Unlock()

	go func() {
		defer func() { authMu.Lock(); authBusy = false; authMu.Unlock() }()
		desc := describeTargets(targets)
		ok := false
		switch mode {
		case "never":
			authMu.Lock()
			authDeclined[key] = true
			authMu.Unlock()
			return
		case "auto":
			ok = true
		default:
			switch askTransparent(desc) {
			case "yes":
				ok = true
			case "never":
				configMu.Lock()
				configuration.TransparentMode = "never"
				persistConfigurationLocked()
				configMu.Unlock()
				fallthrough
			default:
				authMu.Lock()
				authDeclined[key] = true
				authMu.Unlock()
			}
		}
		if !ok {
			return
		}
		if err := startHelper(desc); err != nil {
			log.Printf("Transparent routing: %v", err)
			authMu.Lock()
			authFailedAt = time.Now()
			authMu.Unlock()
			return
		}
		go applyTransparentRouting()
	}()
}

// authorizeTransparent is the "Authorize" button of the UI: it skips the
// question and goes straight to the authentication.
func authorizeTransparent() {
	configMu.Lock()
	selectors := append([]string(nil), configuration.TransparentRoute...)
	configMu.Unlock()
	targets := transparentTargets(selectors)
	authMu.Lock()
	if authBusy {
		authMu.Unlock()
		return
	}
	authBusy = true
	authDeclined = map[string]bool{}
	authFailedAt = time.Time{}
	authMu.Unlock()
	go func() {
		defer func() { authMu.Lock(); authBusy = false; authMu.Unlock() }()
		if helperAlive() {
			return
		}
		if err := startHelper(describeTargets(targets)); err != nil {
			log.Printf("Transparent routing: %v", err)
			return
		}
		applyTransparentRouting()
	}()
}

// askTransparent asks whether to enable the transparent routing: "yes",
// "no" or "never".
func askTransparent(desc string) string {
	msg := fmt.Sprintf("Il servizio %s è attivo.\\n\\nVuoi instradare il suo traffico TCP attraverso il proxy, senza modificare il proxy di sistema?\\n\\nmacOS chiederà l'autenticazione per caricare le regole del firewall.", desc)
	script := fmt.Sprintf(`display dialog "%s" with title "Proxy: instradamento trasparente" buttons {"Non chiedere più", "Non ora", "Attiva"} default button "Attiva" cancel button "Non ora" giving up after 120`,
		strings.ReplaceAll(escapeAppleScript(msg), `\\n`, `\n`))
	out, err := exec.Command("osascript", "-e", script).Output()
	if err != nil {
		return "no" // cancelled
	}
	s := string(out)
	switch {
	case strings.Contains(s, "gave up:true"):
		return "no"
	case strings.Contains(s, "button returned:Attiva"):
		return "yes"
	case strings.Contains(s, "Non chiedere"):
		return "never"
	}
	return "no"
}

// startHelper installs a root-owned copy of the program and runs it as the
// helper, asking macOS to authenticate the user. It returns when the helper
// answers.
func startHelper(desc string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	sock := pfSocket()
	shell := fmt.Sprintf(
		"mkdir -p /Library/PrivilegedHelperTools && cp -f %[1]s %[2]s && chown root:wheel %[2]s && chmod 755 %[2]s && (%[2]s --pf-helper %[3]s %[4]d %[5]d >/dev/null 2>&1 &)",
		shellQuote(exe), shellQuote(helperInstallPath), shellQuote(sock), os.Getuid(), os.Getpid())
	prompt := "Proxy vuole attivare l'instradamento trasparente su " + desc + "."
	script := fmt.Sprintf(`do shell script "%s" with prompt "%s" with administrator privileges`,
		escapeAppleScript(shell), escapeAppleScript(prompt))
	if out, err := exec.Command("osascript", "-e", script).CombinedOutput(); err != nil {
		msg := strings.TrimSpace(string(out))
		if strings.Contains(msg, "-128") || strings.Contains(strings.ToLower(msg), "cancel") {
			return fmt.Errorf("authorization cancelled")
		}
		return fmt.Errorf("authorization failed: %v (%s)", err, msg)
	}
	for i := 0; i < 50; i++ {
		if helperAlive() {
			log.Printf("Transparent routing: privileged helper started")
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("the privileged helper did not start")
}
