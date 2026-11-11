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

// Transparent routing for macOS: a packet filter anchor redirects the
// HTTP/HTTPS connections that leave through the interfaces selected in
// TransparentRoute to the transparent listener (transparent.go). It does not
// touch the system proxy, so VPN clients that monitor it (Pulse/Ivanti) do
// not react.
//
// The rules live in an anchor under "com.apple/", which the stock
// /etc/pf.conf already evaluates, so the main ruleset is never modified.
// Loading them needs root: the program runs pfctl through `sudo -n`, which
// works once the user has allowed it (see pfSudoersHint).
const pfAnchor = "com.apple/250.ProxyRoute"

var (
	pfMu      sync.Mutex
	pfApplied string // rules currently loaded ("" = none)
	pfWarned  time.Time
)

// pfSudoersHint is the line to put in /etc/sudoers.d/proxyroute (with
// visudo) so that pfctl can be run for this anchor without a password.
func pfSudoersHint() string {
	return fmt.Sprintf("%s ALL=(root) NOPASSWD: /sbin/pfctl -a %s -f -, /sbin/pfctl -a %s -F all, /sbin/pfctl -E",
		os.Getenv("USER"), pfAnchor, pfAnchor)
}

// transparentInterfaces resolves the configured selectors (substring of the
// service name, of the service identifier or of the interface name) to the
// interfaces of the active services.
func transparentInterfaces(selectors []string) []string {
	var ifaces []string
	seen := map[string]bool{}
	for _, svc := range activeServices() {
		for _, sel := range selectors {
			sel = strings.ToLower(strings.TrimSpace(sel))
			if sel == "" || !safeConfigToken(svc.Iface) {
				continue
			}
			if strings.Contains(strings.ToLower(svc.Name), sel) ||
				strings.Contains(strings.ToLower(svc.ID), sel) ||
				strings.Contains(strings.ToLower(svc.Iface), sel) {
				if !seen[svc.Iface] {
					seen[svc.Iface] = true
					ifaces = append(ifaces, svc.Iface)
				}
				break
			}
		}
	}
	return ifaces
}

// pfRules builds the anchor rules for the given interfaces: the connections
// leaving through them are sent to lo0 and redirected to the transparent
// listener; the ones marked as this program's own (egressTOS) go through.
func pfRules(ifaces []string, listen string) string {
	host, port, _ := strings.Cut(listen, ":")
	var b strings.Builder
	fmt.Fprintf(&b, "rdr on lo0 inet proto tcp from any to any port { 80, 443 } -> %s port %s\n", host, port)
	// The answers of the proxy go to the address of the client, which is the
	// address of the interface the connection left from. A tunnel's own
	// address is routed through the tunnel (a host route on utunN), so the
	// answers would be lost in it: reply-to forces them back on lo0.
	fmt.Fprintf(&b, "pass in quick on lo0 reply-to (lo0 127.0.0.1) inet proto tcp from any to %s port %s keep state\n", host, port)
	for _, i := range ifaces {
		fmt.Fprintf(&b, "pass out quick on %s inet proto tcp from any to any port { 80, 443 } tos 0x%x no state\n", i, egressTOS)
		fmt.Fprintf(&b, "pass out on %s route-to (lo0 127.0.0.1) inet proto tcp from any to any port { 80, 443 } keep state\n", i)
	}
	return b.String()
}

func pfctl(stdin string, args ...string) error {
	name, full := "/sbin/pfctl", args
	if os.Geteuid() != 0 {
		name, full = "/usr/bin/sudo", append([]string{"-n", "/sbin/pfctl"}, args...)
	}
	cmd := exec.Command(name, full...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func pfWarn(format string, args ...any) {
	if time.Since(pfWarned) > time.Minute {
		pfWarned = time.Now()
		log.Printf(format, args...)
	}
}

// pfReloadEvery reloads the rules even when nothing changed: somebody may
// have flushed the anchor (pfctl -F, a reboot of pf...).
const pfReloadEvery = time.Minute

var (
	pfStatus   transparentStatusJSON
	pfLoadedAt time.Time
	pfLoggedNo bool
)

func transparentStatus() transparentStatusJSON {
	pfMu.Lock()
	defer pfMu.Unlock()
	st := pfStatus
	if st.Configured == nil {
		st.Configured = []string{}
	}
	if st.Interfaces == nil {
		st.Interfaces = []string{}
	}
	return st
}

// applyTransparentRouting loads (or removes) the anchor rules according to
// the configuration and to the interfaces that are up now. It is cheap when
// nothing changed.
func applyTransparentRouting() {
	configMu.Lock()
	selectors := append([]string(nil), configuration.TransparentRoute...)
	configMu.Unlock()

	var ifaces []string
	var rules string
	if len(selectors) > 0 {
		if ifaces = transparentInterfaces(selectors); len(ifaces) > 0 {
			rules = pfRules(ifaces, transparentAddr)
		}
	}

	pfMu.Lock()
	defer pfMu.Unlock()
	pfStatus.Configured = selectors
	pfStatus.Interfaces = ifaces
	if rules == pfApplied && (rules == "" || time.Since(pfLoadedAt) < pfReloadEvery) {
		if rules == "" && len(selectors) > 0 {
			pfStatus.Loaded = false
			pfStatus.Error = ""
			pfStatus.Hint = "No active service or interface matches yet: the rules are loaded as soon as one is up."
		}
		return
	}
	pfStatus.Hint = ""
	if rules == "" {
		if pfApplied != "" {
			if err := pfctl("", "-a", pfAnchor, "-F", "all"); err != nil {
				pfFail("cannot remove the rules", err)
				return
			}
			pfApplied = ""
			log.Printf("Transparent routing: rules removed")
		}
		pfStatus.Loaded = false
		pfStatus.Error = ""
		if len(selectors) > 0 {
			pfStatus.Hint = "No active service or interface matches yet: the rules are loaded as soon as one is up."
			if !pfLoggedNo {
				pfLoggedNo = true
				log.Printf("Transparent routing: nothing matches %v among the active services, waiting", selectors)
			}
		} else {
			pfLoggedNo = false
		}
		return
	}
	pfLoggedNo = false
	if pfApplied == "" {
		if err := pfctl("", "-E"); err != nil {
			pfFail("cannot enable pf", err)
			return
		}
	}
	if err := pfctl(rules, "-a", pfAnchor, "-f", "-"); err != nil {
		pfFail("cannot load the rules", err)
		return
	}
	pfLoadedAt = time.Now()
	pfStatus.Loaded = true
	pfStatus.Error = ""
	if rules != pfApplied {
		log.Printf("Transparent routing: rules loaded on %v:\n%s", ifaces, strings.TrimSpace(rules))
	}
	pfApplied = rules
}

func pfFail(what string, err error) {
	pfStatus.Loaded = false
	pfStatus.Error = fmt.Sprintf("%s: %v", what, err)
	pfStatus.Hint = "Allow pfctl without a password with: sudo visudo -f /etc/sudoers.d/proxyroute  and the line:  " + pfSudoersHint()
	pfWarn("Transparent routing: %s: %v (allow it with: %s)", what, err, pfSudoersHint())
}

// removeTransparentRouting takes the rules away (at quit): leaving a
// redirect towards a listener that is gone would cut the web.
func removeTransparentRouting() {
	pfMu.Lock()
	defer pfMu.Unlock()
	if pfApplied == "" {
		return
	}
	if err := pfctl("", "-a", pfAnchor, "-F", "all"); err != nil {
		log.Printf("Transparent routing: cannot remove the rules at exit: %v", err)
		return
	}
	pfApplied = ""
}
