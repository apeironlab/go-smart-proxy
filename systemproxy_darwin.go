//go:build darwin

package main

import (
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
	lastVPNSkipLog time.Time
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

// scutilRun feeds a script to scutil and returns its output.
func scutilRun(script string) string {
	cmd := exec.Command("scutil")
	cmd.Stdin = strings.NewReader(script)
	out, _ := cmd.CombinedOutput()
	return string(out)
}

// activeService is a network service that currently has an address.
type activeService struct {
	ID      string // key in the dynamic store
	Name    string // name shown in System Settings (the ID for dynamic VPN services)
	Iface   string // BSD interface (en0, utun4...)
	Dynamic bool   // not configured in System Settings (VPN clients): no networksetup
}

// activeServices lists the services that have an IPv4/IPv6 address, i.e. the
// active interfaces.
func activeServices() []activeService {
	out := scutilRun("list State:/Network/Service/[^/]+/IPv[46]\n")
	seen := map[string]bool{}
	var services []activeService
	for _, line := range strings.Split(out, "\n") {
		_, key, ok := strings.Cut(line, " = ")
		if !ok {
			continue
		}
		parts := strings.Split(strings.TrimSpace(key), "/")
		// State: / Network / Service / <ID> / IPv4
		if len(parts) < 5 || parts[3] == "" || seen[parts[3]] {
			continue
		}
		id := parts[3]
		seen[id] = true
		svc := activeService{ID: id, Name: id, Dynamic: true}
		for _, l := range strings.Split(scutilRun("show "+strings.TrimSpace(key)+"\n"), "\n") {
			if k, v, ok := strings.Cut(strings.TrimSpace(l), " : "); ok && k == "InterfaceName" {
				svc.Iface = v
			}
		}
		if svc.Iface == "" {
			continue
		}
		for _, l := range strings.Split(scutilRun("show Setup:/Network/Service/"+id+"\n"), "\n") {
			if k, v, ok := strings.Cut(strings.TrimSpace(l), " : "); ok && k == "UserDefinedName" {
				svc.Name = v
				svc.Dynamic = false
			}
		}
		services = append(services, svc)
	}

	// The primary service is always included: VPN clients (Pulse/Ivanti) do
	// not necessarily publish an IPv4 key under their own service id.
	if id, iface := primaryService(); id != "" && !seen[id] {
		svc := activeService{ID: id, Name: id, Iface: iface, Dynamic: true}
		for _, l := range strings.Split(scutilRun("show Setup:/Network/Service/"+id+"\n"), "\n") {
			if k, v, ok := strings.Cut(strings.TrimSpace(l), " : "); ok && k == "UserDefinedName" {
				svc.Name = v
				svc.Dynamic = false
			}
		}
		services = append(services, svc)
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
	for _, s := range activeServices() {
		if s.ID == primary {
			return primary, s.Dynamic
		}
	}
	return "", false
}

func serviceExcluded(svc activeService, exclude []string) bool {
	for _, e := range exclude {
		e = strings.ToLower(e)
		if e != "" && (strings.Contains(strings.ToLower(svc.Name), e) || strings.Contains(strings.ToLower(svc.Iface), e)) {
			return true
		}
	}
	return false
}

// serviceProxies reads the proxy dict of a network service.
func serviceProxies(serviceKey string) (httpEnable, httpsEnable, pacEnable bool, httpProxy, httpsProxy, httpPort, httpsPort string) {
	// Dynamic services (VPN) keep their proxies in the runtime state; the
	// services configured in System Settings only in the setup (the global
	// "effective" proxy that Chrome sees is then derived from the primary one).
	out := scutilRun("show State:/Network/Service/" + serviceKey + "/Proxies\n")
	if strings.Contains(out, "No such key") {
		out = scutilRun("show Setup:/Network/Service/" + serviceKey + "/Proxies\n")
	}
	for _, line := range strings.Split(out, "\n") {
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

// serviceCorrect reports whether the runtime proxy state of a service already
// points at host:port with the PAC off.
func serviceCorrect(id, host, port string) bool {
	he, hse, pac, hp, hsp, hport, hsport := serviceProxies(id)
	return he && hse && !pac && hp == host && hport == port && hsp == host && hsport == port
}

// applySystemProxy sets the macOS system HTTP/HTTPS proxy to this proxy on
// every active interface (every network service that has an address).
// Corporate VPN clients overwrite the system proxy when they connect;
// re-applying it on network changes keeps browsers pointing at the local
// proxy.
//
// Dynamic VPN services (not configured in System Settings) only get their
// runtime proxy state rewritten (via scutil): the VPN client does not watch
// it, so the tunnel does not restart. The other services are set with
// networksetup.
//
// Interfaces matching SystemProxyExclude (by service or interface name) are
// never touched; a service already correct is left alone; networksetup
// writes are throttled.
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

	primary := primaryServiceName()
	services := activeServices()

	// With a dynamic VPN service primary nothing is written at all: the
	// effective proxy comes from that service, and clients such as
	// Pulse/Ivanti monitor it and drop the tunnel as soon as it is modified
	// (the global proxy key is owned by configd and cannot be written). The
	// same goes for the other services: networksetup changes make the VPN
	// client re-establish the tunnel in a loop.
	for _, svc := range services {
		if svc.Dynamic && svc.ID == primary {
			if time.Since(lastVPNSkipLog) > 10*time.Minute {
				lastVPNSkipLog = time.Now()
				log.Printf("System proxy: VPN service %s (%s) is primary, leaving the system proxy alone", svc.Name, svc.Iface)
			}
			return
		}
	}

	var pending []activeService
	for _, svc := range services {
		if serviceExcluded(svc, exclude) {
			continue
		}
		if svc.Dynamic {
			continue // dynamic services belong to their VPN client: never written
		}
		if !serviceCorrect(svc.ID, host, port) {
			pending = append(pending, svc)
		}
	}
	if len(pending) == 0 {
		return
	}

	proxyApplyMu.Lock()
	if time.Since(lastProxyApply) < 30*time.Second {
		proxyApplyMu.Unlock()
		return
	}
	lastProxyApply = time.Now()
	proxyApplyMu.Unlock()

	for _, svc := range pending {
		commands := [][]string{
			{"-setwebproxy", svc.Name, host, port},
			{"-setsecurewebproxy", svc.Name, host, port},
			{"-setwebproxystate", svc.Name, "on"},
			{"-setsecurewebproxystate", svc.Name, "on"},
			// A PAC (auto-config) takes precedence over the manual proxy on
			// macOS: disable it, otherwise browsers would keep using the PAC
			// (e.g. the corporate wpad.dat) instead of this proxy.
			{"-setautoproxystate", svc.Name, "off"},
			{"-setproxyautodiscovery", svc.Name, "off"},
		}
		for _, args := range commands {
			if out, err := exec.Command("networksetup", args...).CombinedOutput(); err != nil {
				log.Printf("networksetup %v failed: %v (%s)", args, err, strings.TrimSpace(string(out)))
			}
		}
		log.Printf("System proxy set to %s:%s on %s (%s)", host, port, svc.Name, svc.Iface)
	}
}

// primaryServiceName returns the network service currently marked primary
// (the one whose proxy configuration the system actually uses).
func primaryServiceName() string {
	id, _ := primaryService()
	return id
}

// primaryService returns the primary service and its interface.
func primaryService() (id, iface string) {
	out := scutilRun("show State:/Network/Global/IPv4\n")
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), " : ")
		if !ok {
			continue
		}
		switch k {
		case "PrimaryService":
			id = v
		case "PrimaryInterface":
			iface = v
		}
	}
	return
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
	configMu.Lock()
	exclude := append([]string(nil), configuration.SystemProxyExclude...)
	configMu.Unlock()
	for _, svc := range activeServices() {
		he, hse, pac, hp, hsp, hport, hsport := serviceProxies(svc.ID)
		hn, _ := strconv.Atoi(hport)
		hsn, _ := strconv.Atoi(hsport)
		st.Interfaces = append(st.Interfaces, ifaceProxyJSON{
			Service: svc.Name, Iface: svc.Iface, Primary: svc.ID == st.PrimaryService,
			Dynamic: svc.Dynamic, Excluded: serviceExcluded(svc, exclude),
			HTTPEnable: he, HTTPProxy: hp, HTTPPort: hn,
			HTTPSEnable: hse, HTTPSProxy: hsp, HTTPSPort: hsn, PACEnable: pac,
		})
	}
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
