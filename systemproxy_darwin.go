//go:build darwin

package main

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	proxyApplyMu   sync.Mutex
	lastProxyApply time.Time
)

// networkServices returns the services configured in System Settings, as
// listed by networksetup.
func networkServices() []string {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil
	}
	var services []string
	for _, line := range strings.Split(string(out), "\n") {
		service := strings.TrimSpace(line)
		if service == "" || strings.HasPrefix(service, "An asterisk") || strings.HasPrefix(service, "*") {
			continue
		}
		services = append(services, service)
	}
	return services
}

// vpnService returns the primary service key when it is a dynamic VPN
// service (i.e. not configured in System Settings): for those services the
// effective proxy comes from the service runtime state, which VPN clients
// re-apply on connect but do not continuously monitor.
func vpnService() (string, bool) {
	primary := primaryServiceName()
	if primary == "" {
		return "", false
	}
	for _, s := range networkServices() {
		if s == primary {
			return "", false
		}
	}
	return primary, true
}

// serviceProxies reads the runtime proxy dict of a network service.
func serviceProxies(serviceKey string) (httpEnable, httpsEnable, pacEnable bool, httpProxy, httpsProxy, httpPort, httpsPort string) {
	out, err := exec.Command("scutil", "show", "State:/Network/Service/"+serviceKey+"/Proxies").Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		k, v, ok := strings.Cut(trimmed, " : ")
		if !ok {
			continue
		}
		switch k {
		case "HTTPEnable":
			httpEnable = v == "1"
		case "HTTPProxy":
			httpProxy = v
		case "HTTPPort":
			httpPort = v
		case "HTTPSEnable":
			httpsEnable = v == "1"
		case "HTTPSProxy":
			httpsProxy = v
		case "HTTPSPort":
			httpsPort = v
		case "ProxyAutoConfigEnable":
			pacEnable = v == "1"
		}
	}
	return
}

// applyServiceProxyOverride rewrites the runtime proxy state of a dynamic
// VPN service so that the effective system proxy points at this proxy while
// the VPN is up. The service configuration the VPN client monitors is never
// touched, so the tunnel does not restart.
func applyServiceProxyOverride(serviceKey, host, port string) {
	he, hse, pac, hp, hsp, hport, hsport := serviceProxies(serviceKey)
	if he && hse && !pac && hp == host && hport == port && hsp == host && hsport == port {
		return // already correct
	}

	script := fmt.Sprintf(`d.init
d.add HTTPEnable 1
d.add HTTPPort %s
d.add HTTPProxy %s
d.add HTTPSEnable 1
d.add HTTPSPort %s
d.add HTTPSProxy %s
d.add ProxyAutoConfigEnable 0
d.add ProxyAutoDiscoveryEnable 0
set State:/Network/Service/%s/Proxies
quit
`, port, host, port, host, serviceKey)

	cmd := exec.Command("scutil")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("VPN proxy override failed: %v (%s)", err, strings.TrimSpace(string(out)))
		return
	}
	log.Printf("VPN proxy override applied on %s: %s:%s", serviceKey, host, port)
}

// applySystemProxy re-sets the macOS system HTTP/HTTPS proxy to this proxy
// on every network service. Corporate VPN clients overwrite the system proxy
// when they connect; re-applying it on network changes keeps browsers
// pointing at the local proxy.
//
// While a dynamic VPN service is primary, the underlying services are left
// alone and only the VPN service runtime proxy state is rewritten (via
// scutil): that is the effective proxy the system uses, and the VPN client
// does not watch it.
//
// Services listed in SystemProxyExclude are never touched; the work is
// skipped when the effective configuration is already correct; writes are
// throttled.
func applySystemProxy() {
	configMu.Lock()
	enabled := configuration.SystemProxy
	exclude := append([]string(nil), configuration.SystemProxyExclude...)
	address := configuration.Address
	configMu.Unlock()

	if !enabled {
		return
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
		port = "3128"
	}

	ifaceName := strings.ToLower(getNetState().iface.Name)
	for _, e := range exclude {
		if e != "" && strings.Contains(ifaceName, strings.ToLower(e)) {
			log.Printf("System proxy: default interface %q is excluded, skipping", getNetState().iface.Name)
			return
		}
	}

	// Dynamic VPN service is primary: only rewrite its runtime proxy state.
	if key, ok := vpnService(); ok {
		applyServiceProxyOverride(key, host, port)
		return
	}

	// Idempotency: if the effective configuration already points here and the
	// PAC is off, there is nothing to do (and nothing for the VPN to react to).
	st := systemProxyState()
	portNum, _ := strconv.Atoi(port)
	if st.HTTPEnable && st.HTTPProxy == host && st.HTTPPort == portNum &&
		st.HTTPSEnable && st.HTTPSProxy == host && st.HTTPSPort == portNum &&
		!st.PACEnable {
		return
	}

	proxyApplyMu.Lock()
	if time.Since(lastProxyApply) < 30*time.Second {
		proxyApplyMu.Unlock()
		return
	}
	lastProxyApply = time.Now()
	proxyApplyMu.Unlock()

	for _, service := range networkServices() {
		skip := false
		for _, e := range exclude {
			if e != "" && strings.Contains(strings.ToLower(service), strings.ToLower(e)) {
				skip = true
				break
			}
		}
		if skip {
			log.Printf("System proxy: service %q excluded, not touching it", service)
			continue
		}
		commands := [][]string{
			{"-setwebproxy", service, host, port},
			{"-setsecurewebproxy", service, host, port},
			{"-setwebproxystate", service, "on"},
			{"-setsecurewebproxystate", service, "on"},
			// A PAC (auto-config) takes precedence over the manual proxy on
			// macOS: disable it, otherwise browsers would keep using the PAC
			// (e.g. the corporate wpad.dat) instead of this proxy.
			{"-setautoproxystate", service, "off"},
			{"-setproxyautodiscovery", service, "off"},
		}
		for _, args := range commands {
			if out, err := exec.Command("networksetup", args...).CombinedOutput(); err != nil {
				log.Printf("networksetup %v failed: %v (%s)", args, err, strings.TrimSpace(string(out)))
			}
		}
	}
	log.Printf("System proxy set to %s:%s", host, port)
}

// primaryServiceName returns the network service currently marked primary
// (the one whose proxy configuration the system actually uses).
func primaryServiceName() string {
	out, err := exec.Command("scutil", "--get", "State:/Network/Global/IPv4").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		k, v, ok := strings.Cut(trimmed, " : ")
		if ok && k == "PrimaryService" {
			return v
		}
	}
	return ""
}

// systemProxyState reads the effective system proxy configuration, the very
// same configuration Chrome (and all CFNetwork clients) actually use.
func systemProxyState() systemProxyStateJSON {
	st := systemProxyStateJSON{}
	out, err := exec.Command("scutil", "--proxy").Output()
	if err != nil {
		st.Raw = err.Error()
		return st
	}
	st.Raw = string(out)

	inExceptions := false
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if inExceptions {
			if trimmed == "}" {
				inExceptions = false
				continue
			}
			if _, v, ok := strings.Cut(trimmed, " : "); ok {
				st.Exceptions = append(st.Exceptions, v)
			}
			continue
		}
		k, v, ok := strings.Cut(trimmed, " : ")
		if !ok {
			continue
		}
		switch k {
		case "HTTPEnable":
			st.HTTPEnable = v == "1"
		case "HTTPProxy":
			st.HTTPProxy = v
		case "HTTPPort":
			st.HTTPPort, _ = strconv.Atoi(v)
		case "HTTPSEnable":
			st.HTTPSEnable = v == "1"
		case "HTTPSProxy":
			st.HTTPSProxy = v
		case "HTTPSPort":
			st.HTTPSPort, _ = strconv.Atoi(v)
		case "ProxyAutoConfigEnable":
			st.PACEnable = v == "1"
		case "ProxyAutoConfigURLString":
			st.PACURL = v
		case "ExceptionsList":
			if strings.HasPrefix(v, "<array>") {
				inExceptions = true
			}
		}
	}

	st.PrimaryService = primaryServiceName()
	if key, ok := vpnService(); ok {
		st.VPNService = key
		he, hse, pac, hp, hsp, hport, hsport := serviceProxies(key)
		st.VPNHTTPProxy = hp
		st.VPNHTTPPort = hport
		st.VPNHTTPSProxy = hsp
		st.VPNHTTPSPort = hsport
		st.VPNHTTPEnable = he
		st.VPNHTTPSEnable = hse
		st.VPNPACEnable = pac
	}
	return st
}
