package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// validateListenAddress checks a "host:port" listen address before it is saved
// or used to build commands. Besides catching typos, it keeps control
// characters out of values that end up in scripts and policy files.
func validateListenAddress(addr string, allowEmpty bool) error {
	if addr == "" {
		if allowEmpty {
			return nil
		}
		return errors.New("address is required")
	}
	if len(addr) > 255 {
		return errors.New("address too long")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("address must be host:port: %w", err)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("invalid port")
	}
	if host == "" {
		return nil
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	for _, r := range host {
		ok := r == '.' || r == '-' || r == '_' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		if !ok {
			return errors.New("invalid host name")
		}
	}
	return nil
}

// listenHostIsLoopback reports whether binding host only exposes the listener
// to this machine. An empty host means every interface.
func listenHostIsLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// addressIsLoopbackOnly reports whether a listen address is reachable only
// from this machine. An empty address (listener disabled) counts as safe.
func addressIsLoopbackOnly(addr string) bool {
	if addr == "" {
		return true
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	return listenHostIsLoopback(host)
}

// remoteClientsAllowed reports whether the listeners may serve clients that
// are not on this machine.
func remoteClientsAllowed() bool {
	configMu.Lock()
	defer configMu.Unlock()
	return configuration.AllowRemoteClients
}

// connFromLoopback reports whether a connection comes from this machine.
func connFromLoopback(c net.Conn) bool {
	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// acceptClient decides whether a newly accepted connection may be served. The
// proxy has no client authentication and uses the user's upstream credentials,
// so by default only local clients are served, even when the listener is bound
// to a non-loopback address.
func acceptClient(c net.Conn) bool {
	if connFromLoopback(c) || remoteClientsAllowed() {
		return true
	}
	log.Printf("Refused connection from %s: remote clients are not allowed (AllowRemoteClients)", c.RemoteAddr())
	return false
}

// enforceRemotePolicy keeps configurations that already listened on a
// non-loopback address working after the upgrade (it records the explicit
// choice and warns), and otherwise leaves the safe default in place.
func enforceRemotePolicy() {
	if configuration.AllowRemoteClients {
		return
	}
	if !addressIsLoopbackOnly(configuration.Address) || !addressIsLoopbackOnly(configuration.SocksAddress) {
		configuration.AllowRemoteClients = true
		log.Printf("WARNING: the proxy listens on a non-loopback address: remote clients are allowed and can use your upstream credentials without authentication. Bind to 127.0.0.1 to prevent it.")
		if err := persistConfigurationLocked(); err != nil {
			log.Printf("WARNING: cannot persist AllowRemoteClients: %v", err)
		}
	}
}

// isSelfTarget reports whether host:port designates one of this proxy's own
// listeners. Forwarding such a request would make the connection arrive from
// the loopback interface, which would bypass the checks that protect the web
// UI and the API.
func isSelfTarget(host, port string) bool {
	n, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	configMu.Lock()
	addrs := []string{configuration.Address, configuration.SocksAddress}
	configMu.Unlock()

	var own []string
	for _, a := range addrs {
		if a == "" {
			continue
		}
		if _, p, err := net.SplitHostPort(a); err == nil {
			if pn, err := strconv.Atoi(p); err == nil && pn == n {
				own = append(own, a)
			}
		}
	}
	if len(own) == 0 {
		return false
	}

	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		if strings.EqualFold(host, "localhost") {
			return true
		}
		if resolved := resolveHost(host); resolved != "" {
			ip = net.ParseIP(resolved)
		}
	}
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsUnspecified() {
		return true
	}
	for _, a := range own {
		h, _, _ := net.SplitHostPort(a)
		if lip := net.ParseIP(h); lip != nil && lip.Equal(ip) {
			return true
		}
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.Equal(ip) {
				return true
			}
		}
	}
	return false
}

// safeConfigToken reports whether s is made only of characters that are safe
// to embed in generated scripts and preference values (letters, digits and
// . : - _), i.e. no whitespace, quotes or line breaks.
func safeConfigToken(s string) bool {
	if s == "" || len(s) > 255 {
		return false
	}
	for _, r := range s {
		ok := r == '.' || r == ':' || r == '-' || r == '_' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		if !ok {
			return false
		}
	}
	return true
}

// hostHeaderIsLocal reports whether the Host header names this machine by a
// loopback address. Rejecting any other name stops DNS-rebinding pages, which
// reach the proxy through an attacker-controlled host name.
func hostHeaderIsLocal(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// checkLocalUIRequest validates a request addressed to the web UI or the API.
// It returns a non-empty reason when the request must be refused.
//
// The UI and API listen on the same port as the proxy, and browsers will send
// cross-site requests to 127.0.0.1 on behalf of any web page: without these
// checks a malicious page could reconfigure the proxy (CSRF) or read from it
// (DNS rebinding).
func checkLocalUIRequest(r *http.Request) string {
	if !hostHeaderIsLocal(r.Host) {
		return "invalid Host header"
	}
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		return ""
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return "cross-site request refused"
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || !strings.EqualFold(u.Host, r.Host) {
			return "cross-origin request refused"
		}
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
	default:
		if r.ContentLength != 0 {
			mt := strings.ToLower(strings.TrimSpace(strings.SplitN(r.Header.Get("Content-Type"), ";", 2)[0]))
			if mt != "application/json" {
				return "Content-Type must be application/json"
			}
		}
	}
	return ""
}
