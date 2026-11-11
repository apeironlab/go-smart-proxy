//go:build darwin

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Transparent routing for macOS: a packet filter anchor redirects the TCP
// connections that leave through the interfaces selected in TransparentRoute
// to the transparent listener (transparent.go). It does not touch the system
// proxy, so VPN clients that monitor it (Pulse/Ivanti) do not react.
//
// Loading the rules and reading the original destination of a redirected
// connection need root. They are done by a privileged helper (pfhelper_darwin.go)
// that the user starts by authenticating once (pfauth_darwin.go) and that
// ends with the program.
//
// The rules live in an anchor under "com.apple/", which the stock
// /etc/pf.conf already evaluates, so the main ruleset is never modified.
const pfAnchor = "com.apple/250.ProxyRoute"

// pfSocket is the socket of the helper of this user.
func pfSocket() string { return fmt.Sprintf("/var/run/proxyroute-%d.sock", os.Getuid()) }

var (
	pfMu      sync.Mutex
	pfApplied string // interfaces whose rules are loaded ("" = none)
	pfLoaded  time.Time
	pfStatus  transparentStatusJSON
	pfLogged  string
)

// transparentTargets resolves the configured selectors (substring of the
// service name, of the service identifier or of the interface name) to the
// active services.
func transparentTargets(selectors []string) []activeService {
	var out []activeService
	for _, svc := range activeServices() {
		if !ifaceNameRE.MatchString(svc.Iface) {
			continue
		}
		for _, sel := range selectors {
			sel = strings.ToLower(strings.TrimSpace(sel))
			if sel == "" {
				continue
			}
			if strings.Contains(strings.ToLower(svc.Name), sel) ||
				strings.Contains(strings.ToLower(svc.ID), sel) ||
				strings.Contains(strings.ToLower(svc.Iface), sel) {
				out = append(out, svc)
				break
			}
		}
	}
	return out
}

// pfRules builds the anchor rules for the given interfaces: the connections
// leaving through them are sent to lo0 and redirected to the transparent
// listener; the ones marked as this program's own (egressTOS) go through, and
// so do the local and multicast destinations.
func pfRules(ifaces []string, listen string) string {
	host, port, _ := strings.Cut(listen, ":")
	var b strings.Builder
	// What is really addressed to the loopback is never redirected.
	b.WriteString("no rdr on lo0 inet proto tcp from any to 127.0.0.0/8\n")
	fmt.Fprintf(&b, "rdr on lo0 inet proto tcp from any to any -> %s port %s\n", host, port)
	// The answers of the proxy go to the address of the client, which is the
	// address of the interface the connection left from. A tunnel's own
	// address is routed through the tunnel (a host route on utunN), so the
	// answers would be lost in it: reply-to forces them back on lo0.
	fmt.Fprintf(&b, "pass in quick on lo0 reply-to (lo0 127.0.0.1) inet proto tcp from any to %s port %s keep state\n", host, port)
	for _, i := range ifaces {
		fmt.Fprintf(&b, "pass out quick on %s inet proto tcp from any to any tos 0x%x no state\n", i, egressTOS)
		fmt.Fprintf(&b, "pass out quick on %s inet proto tcp from any to { 127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/4 } no state\n", i)
		fmt.Fprintf(&b, "pass out on %s route-to (lo0 127.0.0.1) inet proto tcp from any to any keep state\n", i)
	}
	return b.String()
}

// ---- client of the helper -------------------------------------------------

var (
	helperMu   sync.Mutex
	helperConn net.Conn
	helperRd   *bufio.Reader
)

func helperCall(req helperRequest) (helperResponse, error) {
	helperMu.Lock()
	defer helperMu.Unlock()
	var lastErr error
	for try := 0; try < 2; try++ {
		if helperConn == nil {
			c, err := net.DialTimeout("unix", pfSocket(), 2*time.Second)
			if err != nil {
				return helperResponse{}, err
			}
			helperConn, helperRd = c, bufio.NewReader(c)
		}
		helperConn.SetDeadline(time.Now().Add(10 * time.Second))
		b, _ := json.Marshal(req)
		_, err := helperConn.Write(append(b, '\n'))
		var resp helperResponse
		if err == nil {
			var line []byte
			if line, err = helperRd.ReadBytes('\n'); err == nil {
				err = json.Unmarshal(line, &resp)
			}
		}
		if err == nil {
			return resp, nil
		}
		lastErr = err
		helperConn.Close()
		helperConn, helperRd = nil, nil
	}
	return helperResponse{}, lastErr
}

func helperAlive() bool {
	resp, err := helperCall(helperRequest{Op: "ping"})
	return err == nil && resp.OK
}

// lookupOriginalDst asks the helper for the destination a connection was
// redirected from.
func lookupOriginalDst(client string) (host, port string, err error) {
	resp, err := helperCall(helperRequest{Op: "lookup", Src: client})
	if err != nil {
		return "", "", err
	}
	if !resp.OK {
		return "", "", fmt.Errorf("%s", resp.Error)
	}
	return net.SplitHostPort(resp.Dst)
}

// ---- state machine ----------------------------------------------------------

const pfReloadEvery = time.Minute

func transparentStatus() transparentStatusJSON {
	pfMu.Lock()
	defer pfMu.Unlock()
	st := pfStatus
	st.Mode = transparentMode()
	if st.Configured == nil {
		st.Configured = []string{}
	}
	if st.Interfaces == nil {
		st.Interfaces = []string{}
	}
	return st
}

func transparentMode() string {
	configMu.Lock()
	defer configMu.Unlock()
	switch configuration.TransparentMode {
	case "auto", "never":
		return configuration.TransparentMode
	}
	return "ask"
}

// applyTransparentRouting loads (or removes) the anchor rules according to
// the configuration and to the interfaces that are up now. It is cheap when
// nothing changed. When the helper is needed and not running, it asks the
// user (see pfauth_darwin.go).
func applyTransparentRouting() {
	configMu.Lock()
	selectors := append([]string(nil), configuration.TransparentRoute...)
	configMu.Unlock()

	var targets []activeService
	if len(selectors) > 0 {
		targets = transparentTargets(selectors)
	}
	var ifaces []string
	for _, t := range targets {
		ifaces = append(ifaces, t.Iface)
	}
	key := strings.Join(ifaces, ",")

	pfMu.Lock()
	defer pfMu.Unlock()
	pfStatus.Configured = selectors
	pfStatus.Interfaces = ifaces
	pfStatus.Hint = ""

	if len(selectors) == 0 { // disabled: the privileges end here
		if helperAlive() {
			helperCall(helperRequest{Op: "quit"})
			helperMu.Lock()
			if helperConn != nil {
				helperConn.Close()
				helperConn, helperRd = nil, nil
			}
			helperMu.Unlock()
			log.Printf("Transparent routing: disabled, rules removed")
		}
		pfApplied = ""
		pfStatus.Loaded, pfStatus.NeedsAuth, pfStatus.Error = false, false, ""
		return
	}
	if len(ifaces) == 0 {
		if pfApplied != "" && helperAlive() {
			helperCall(helperRequest{Op: "flush"})
			log.Printf("Transparent routing: rules removed")
		}
		pfApplied = ""
		pfStatus.Loaded, pfStatus.NeedsAuth, pfStatus.Error = false, false, ""
		pfStatus.Hint = "No active service or interface matches yet: the rules are loaded as soon as one is up."
		if pfLogged != "none" {
			pfLogged = "none"
			log.Printf("Transparent routing: nothing matches %v among the active services, waiting", selectors)
		}
		return
	}
	pfLogged = ""

	if !helperAlive() {
		pfApplied = ""
		pfStatus.Loaded = false
		pfStatus.NeedsAuth = true
		pfStatus.Hint = "Authorization is needed to load the firewall rules."
		requestHelper(targets, key)
		return
	}
	pfStatus.NeedsAuth = false

	if key == pfApplied && time.Since(pfLoaded) < pfReloadEvery {
		return
	}
	resp, err := helperCall(helperRequest{Op: "load", Ifaces: ifaces})
	if err == nil && !resp.OK {
		err = fmt.Errorf("%s", resp.Error)
	}
	if err != nil {
		pfStatus.Loaded = false
		pfStatus.Error = "cannot load the rules: " + err.Error()
		log.Printf("Transparent routing: %s", pfStatus.Error)
		return
	}
	pfLoaded = time.Now()
	pfStatus.Loaded, pfStatus.Error = true, ""
	if key != pfApplied {
		log.Printf("Transparent routing: rules loaded on %v", ifaces)
	}
	pfApplied = key
}

// removeTransparentRouting ends the helper (and the rules) at quit.
func removeTransparentRouting() {
	if helperAlive() {
		helperCall(helperRequest{Op: "quit"})
	}
}
