package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

var apiMux = newAPIMux()

var startedAt = time.Now()

type systemProxyStateJSON struct {
	Raw         string   `json:"raw"`
	HTTPEnable  bool     `json:"httpEnabled"`
	HTTPProxy   string   `json:"httpProxy"`
	HTTPPort    int      `json:"httpPort"`
	HTTPSEnable bool     `json:"httpsEnabled"`
	HTTPSProxy  string   `json:"httpsProxy"`
	HTTPSPort   int      `json:"httpsPort"`
	PACEnable   bool     `json:"pacEnabled"`
	PACURL      string   `json:"pacUrl"`
	Exceptions  []string `json:"exceptions"`

	PrimaryService string `json:"primaryService"`
	VPNService     string `json:"vpnService"`
	VPNHTTPEnable  bool   `json:"vpnHttpEnabled"`
	VPNHTTPProxy   string `json:"vpnHttpProxy"`
	VPNHTTPPort    string `json:"vpnHttpPort"`
	VPNHTTPSEnable bool   `json:"vpnHttpsEnabled"`
	VPNHTTPSProxy  string `json:"vpnHttpsProxy"`
	VPNHTTPSPort   string `json:"vpnHttpsPort"`
	VPNPACEnable   bool   `json:"vpnPacEnabled"`
}

func newAPIMux() *http.ServeMux {
	m := http.NewServeMux()
	registerRelayRoutes(m)
	registerRuleRoutes(m)
	m.HandleFunc("GET /api/state", apiState)
	m.HandleFunc("GET /api/routes", apiListRoutes)
	m.HandleFunc("POST /api/routes", apiSaveRoute)
	m.HandleFunc("POST /api/routes/order", apiReorderRoutes)
	m.HandleFunc("DELETE /api/routes/{name}", apiDeleteRoute)
	m.HandleFunc("GET /api/credentials", apiListCredentials)
	m.HandleFunc("POST /api/credentials", apiSaveCredential)
	m.HandleFunc("DELETE /api/credentials/{name}", apiDeleteCredential)
	m.HandleFunc("GET /api/connections", apiListConnections)
	m.HandleFunc("POST /api/connections/{id}/close", apiCloseConnection)
	m.HandleFunc("POST /api/force-route", apiForceRoute)
	m.HandleFunc("POST /api/pac/refresh", apiRefreshPAC)
	m.HandleFunc("GET /api/config", apiGetConfig)
	m.HandleFunc("POST /api/config", apiSaveConfig)
	m.HandleFunc("POST /api/onboarding", apiFinishOnboarding)
	m.HandleFunc("GET /api/system-proxy", apiSystemProxy)
	return m
}

func apiSystemProxy(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, systemProxyState())
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		log.Printf("Error encoding JSON response: %+v", err)
	}
}

func readJSON(r *http.Request, v interface{}) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

func writeAPIError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error": %q}`, msg)
}

func isLoopbackRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

type routeInfoJSON struct {
	Name       string      `json:"name"`
	Gateway    string      `json:"gateway"`
	IFace      string      `json:"iface"`
	Net        string      `json:"net"`
	PacUrl     string      `json:"pacUrl"`
	ProxyUrl   string      `json:"proxyUrl"`
	Credential string      `json:"credential"`
	Chain      []string    `json:"chain"`
	Hops       []ConfigHop `json:"hops"`
	RulesOnly  bool        `json:"rulesOnly"`
	Applicable bool        `json:"applicable"`
	WhyNot     string      `json:"whyNot,omitempty"`
	PacStatus  string      `json:"pacStatus"`
	PacError   string      `json:"pacError,omitempty"`
}

type dnsEntryJSON struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
}

type stateJSON struct {
	Address            string            `json:"address"`
	SocksAddress       string            `json:"socksAddress"`
	Onboarding         bool              `json:"onboarding"`
	Iface              string            `json:"iface"`
	Gateway            string            `json:"gateway"`
	Network            string            `json:"network"`
	ForceRoute         string            `json:"forceRoute"`
	SystemProxy        bool              `json:"systemProxy"`
	SystemProxyExclude []string          `json:"systemProxyExclude"`
	PacHijack          bool              `json:"pacHijack"`
	PacHijackHost      string            `json:"pacHijackHost"`
	ForceChrome        bool              `json:"forceChrome"`
	Hosts              map[string]string `json:"hosts"`
	UptimeSeconds      int64             `json:"uptimeSeconds"`
	ActiveConns        int               `json:"activeConns"`
	Routes             []routeInfoJSON   `json:"routes"`
	DNS                []dnsEntryJSON    `json:"dns"`
}

func apiState(w http.ResponseWriter, r *http.Request) {
	st := getNetState()

	configMu.Lock()
	address := configuration.Address
	socksAddress := configuration.SocksAddress
	systemProxy := configuration.SystemProxy
	systemProxyExclude := append([]string(nil), configuration.SystemProxyExclude...)
	pacHijack := configuration.PacHijack
	pacHijackHost := configuration.PacHijackHost
	forceChrome := configuration.ForceChrome
	onboarding := configuration.OnboardingDone != nil && !*configuration.OnboardingDone
	configMu.Unlock()

	hosts := map[string]string{}
	hostsMu.RLock()
	for host, address := range configuration.Hosts {
		hosts[host] = address
	}
	hostsMu.RUnlock()

	state := stateJSON{
		Address:            address,
		SocksAddress:       socksAddress,
		Onboarding:         onboarding,
		Iface:              st.iface.Name,
		Gateway:            fmt.Sprintf("%v", st.defaultGw),
		Network:            netString(st.network),
		SystemProxy:        systemProxy,
		SystemProxyExclude: systemProxyExclude,
		PacHijack:          pacHijack,
		PacHijackHost:      pacHijackHost,
		ForceChrome:        forceChrome,
		Hosts:              hosts,
		UptimeSeconds:      int64(time.Since(startedAt).Seconds()),
		ActiveConns:        connReg.activeCount(),
		Routes:             make([]routeInfoJSON, 0),
		DNS:                make([]dnsEntryJSON, 0),
	}
	if fr := getForceRoute(); fr != nil {
		state.ForceRoute = fr.name
	}
	for _, rt := range getRoutes() {
		state.Routes = append(state.Routes, rt.info(st))
	}
	if dnsCache != nil {
		for _, k := range dnsCache.Keys() {
			key, ok := k.(string)
			if !ok {
				continue
			}
			if v, ok := dnsCache.Get(key); ok {
				ip, _ := v.(string)
				state.DNS = append(state.DNS, dnsEntryJSON{Host: key, IP: ip})
			}
		}
	}
	writeJSON(w, state)
}

func netString(n *net.IPNet) string {
	if n == nil {
		return ""
	}
	return n.String()
}

func apiListRoutes(w http.ResponseWriter, r *http.Request) {
	st := getNetState()
	infos := make([]routeInfoJSON, 0)
	for _, rt := range getRoutes() {
		infos = append(infos, rt.info(st))
	}
	writeJSON(w, infos)
}

type routeFormJSON struct {
	Name       string      `json:"name"`
	Gateway    string      `json:"gateway"`
	IFace      string      `json:"iface"`
	Net        string      `json:"net"`
	PacUrl     string      `json:"pacUrl"`
	ProxyUrl   string      `json:"proxyUrl"`
	Credential string      `json:"credential"`
	Hops       []ConfigHop `json:"hops"`
	RulesOnly  bool        `json:"rulesOnly"`
}

// validateHops checks a chain before it is saved; credentials are looked up under the lock.
func validateHops(hops []ConfigHop) error {
	configMu.Lock()
	defer configMu.Unlock()
	_, err := buildChain(hops)
	return err
}

func apiSaveRoute(w http.ResponseWriter, r *http.Request) {
	var form routeFormJSON
	if err := readJSON(r, &form); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if form.Name == "" {
		writeAPIError(w, http.StatusBadRequest, "name is required")
		return
	}

	if err := validateHops(form.Hops); err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}

	configMu.Lock()
	found := false
	for i := range configuration.Routes {
		if configuration.Routes[i].Name == form.Name {
			configuration.Routes[i] = ConfigRoute{
				Chain:      form.Hops,
				Name:       form.Name,
				Gateway:    form.Gateway,
				IFace:      form.IFace,
				Net:        form.Net,
				PacUrl:     form.PacUrl,
				ProxyUrl:   form.ProxyUrl,
				Credential: form.Credential,
				RulesOnly:  form.RulesOnly,
			}
			found = true
			break
		}
	}
	if !found {
		configuration.Routes = append(configuration.Routes, ConfigRoute{
			Chain:      form.Hops,
			Name:       form.Name,
			Gateway:    form.Gateway,
			IFace:      form.IFace,
			Net:        form.Net,
			PacUrl:     form.PacUrl,
			ProxyUrl:   form.ProxyUrl,
			Credential: form.Credential,
			RulesOnly:  form.RulesOnly,
		})
	}
	if err := persistConfigurationLocked(); err != nil {
		configMu.Unlock()
		log.Printf("Error saving configuration: %+v", err)
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	reapplyRoutesLocked()
	configMu.Unlock()

	writeJSON(w, map[string]string{"status": "ok"})
}

func apiReorderRoutes(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Names []string `json:"names"`
	}
	if err := readJSON(r, &body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid body")
		return
	}
	configMu.Lock()
	if len(body.Names) != len(configuration.Routes) {
		configMu.Unlock()
		writeAPIError(w, http.StatusBadRequest, "the order must contain every route exactly once")
		return
	}
	byName := make(map[string]ConfigRoute, len(configuration.Routes))
	for _, rt := range configuration.Routes {
		byName[rt.Name] = rt
	}
	ordered := make([]ConfigRoute, 0, len(body.Names))
	for _, name := range body.Names {
		rt, ok := byName[name]
		if !ok {
			configMu.Unlock()
			writeAPIError(w, http.StatusBadRequest, "unknown route "+name)
			return
		}
		delete(byName, name)
		ordered = append(ordered, rt)
	}
	if len(byName) != 0 {
		configMu.Unlock()
		writeAPIError(w, http.StatusBadRequest, "the order must contain every route exactly once")
		return
	}
	configuration.Routes = ordered
	if err := persistConfigurationLocked(); err != nil {
		configMu.Unlock()
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	reapplyRoutesLocked()
	configMu.Unlock()
	writeJSON(w, map[string]string{"status": "ok"})
}

func apiDeleteRoute(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	configMu.Lock()
	kept := configuration.Routes[:0]
	for _, rt := range configuration.Routes {
		if rt.Name != name {
			kept = append(kept, rt)
		}
	}
	configuration.Routes = kept
	if err := persistConfigurationLocked(); err != nil {
		configMu.Unlock()
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	reapplyRoutesLocked()
	configMu.Unlock()

	writeJSON(w, map[string]string{"status": "ok"})
}

type credentialInfoJSON struct {
	Name        string `json:"name"`
	User        string `json:"user"`
	HasPassword bool   `json:"hasPassword"`
}

func apiListCredentials(w http.ResponseWriter, r *http.Request) {
	configMu.Lock()
	creds := make([]credentialInfoJSON, 0, len(configuration.Credentials))
	for _, c := range configuration.Credentials {
		// Never send the password: the UI only needs to know whether it is set.
		creds = append(creds, credentialInfoJSON{Name: c.Name, User: c.User, HasPassword: c.Password != ""})
	}
	configMu.Unlock()
	writeJSON(w, creds)
}

type credentialFormJSON struct {
	Name     string `json:"name"`
	User     string `json:"user"`
	Password string `json:"password"`
}

func apiSaveCredential(w http.ResponseWriter, r *http.Request) {
	var form credentialFormJSON
	if err := readJSON(r, &form); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if form.Name == "" {
		writeAPIError(w, http.StatusBadRequest, "name is required")
		return
	}

	configMu.Lock()
	found := false
	for i := range configuration.Credentials {
		if configuration.Credentials[i].Name == form.Name {
			// An empty password means "keep the current one": the API never
			// sends it back to the UI.
			password := form.Password
			if password == "" {
				password = configuration.Credentials[i].Password
			}
			configuration.Credentials[i] = ConfigCredential{
				Name:     form.Name,
				User:     form.User,
				Password: password,
			}
			found = true
			break
		}
	}
	if !found {
		configuration.Credentials = append(configuration.Credentials, ConfigCredential{
			Name:     form.Name,
			User:     form.User,
			Password: form.Password,
		})
	}
	if err := persistConfigurationLocked(); err != nil {
		configMu.Unlock()
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	reapplyRoutesLocked()
	configMu.Unlock()

	writeJSON(w, map[string]string{"status": "ok"})
}

func apiDeleteCredential(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	configMu.Lock()
	kept := configuration.Credentials[:0]
	for _, c := range configuration.Credentials {
		if c.Name != name {
			kept = append(kept, c)
		}
	}
	configuration.Credentials = kept
	if err := persistConfigurationLocked(); err != nil {
		configMu.Unlock()
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	reapplyRoutesLocked()
	configMu.Unlock()

	writeJSON(w, map[string]string{"status": "ok"})
}

func apiListConnections(w http.ResponseWriter, r *http.Request) {
	includeClosed := r.URL.Query().Get("closed") == "1"
	writeJSON(w, connReg.list(includeClosed))
}

func apiCloseConnection(w http.ResponseWriter, r *http.Request) {
	id, ok := parseConnID(r.PathValue("id"))
	if !ok {
		writeAPIError(w, http.StatusBadRequest, "invalid id")
		return
	}
	writeJSON(w, map[string]bool{"closed": connReg.close(id)})
}

type forceRouteJSON struct {
	Name string `json:"name"`
}

func apiForceRoute(w http.ResponseWriter, r *http.Request) {
	var form forceRouteJSON
	if err := readJSON(r, &form); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if form.Name == "" {
		setForceRoute(nil)
		writeJSON(w, map[string]string{"status": "ok", "forceRoute": ""})
		return
	}
	for _, rt := range getRoutes() {
		if rt.name == form.Name {
			setForceRoute(rt)
			writeJSON(w, map[string]string{"status": "ok", "forceRoute": rt.name})
			return
		}
	}
	writeAPIError(w, http.StatusNotFound, "route not found")
}

func apiRefreshPAC(w http.ResponseWriter, r *http.Request) {
	var form forceRouteJSON
	if err := readJSON(r, &form); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid body")
		return
	}
	for _, rt := range getRoutes() {
		if rt.name == form.Name {
			rt.forceRefreshPAC()
			writeJSON(w, map[string]string{"status": "ok"})
			return
		}
	}
	writeAPIError(w, http.StatusNotFound, "route not found")
}

func apiGetConfig(w http.ResponseWriter, r *http.Request) {
	configMu.Lock()
	address := configuration.Address
	socksAddress := configuration.SocksAddress
	systemProxy := configuration.SystemProxy
	systemProxyExclude := append([]string(nil), configuration.SystemProxyExclude...)
	pacHijack := configuration.PacHijack
	pacHijackHost := configuration.PacHijackHost
	forceChrome := configuration.ForceChrome
	configMu.Unlock()
	hosts := map[string]string{}
	hostsMu.RLock()
	for host, address := range configuration.Hosts {
		hosts[host] = address
	}
	hostsMu.RUnlock()
	writeJSON(w, map[string]interface{}{
		"address":            address,
		"socksAddress":       socksAddress,
		"hosts":              hosts,
		"systemProxy":        systemProxy,
		"systemProxyExclude": systemProxyExclude,
		"pacHijack":          pacHijack,
		"pacHijackHost":      pacHijackHost,
		"forceChrome":        forceChrome,
	})
}

type configFormJSON struct {
	Address            string             `json:"address"`
	SocksAddress       *string            `json:"socksAddress"`
	Hosts              *map[string]string `json:"hosts"`
	SystemProxy        *bool              `json:"systemProxy"`
	SystemProxyExclude *[]string          `json:"systemProxyExclude"`
	PacHijack          *bool              `json:"pacHijack"`
	PacHijackHost      string             `json:"pacHijackHost"`
	ForceChrome        *bool              `json:"forceChrome"`
}

func apiSaveConfig(w http.ResponseWriter, r *http.Request) {
	var form configFormJSON
	if err := readJSON(r, &form); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid body")
		return
	}

	configMu.Lock()
	restart := false
	socksRestart := false
	if form.Address != "" && form.Address != configuration.Address {
		restart = true
		configuration.Address = form.Address
	}
	if form.SocksAddress != nil && *form.SocksAddress != configuration.SocksAddress {
		socksRestart = true
		configuration.SocksAddress = *form.SocksAddress
	}
	if form.Hosts != nil {
		hosts := map[string]string{}
		for host, address := range *form.Hosts {
			host = strings.ToLower(strings.TrimSpace(host))
			address = strings.TrimSpace(address)
			if host == "" && address == "" {
				continue
			}
			if host == "" || net.ParseIP(address) == nil {
				configMu.Unlock()
				writeAPIError(w, http.StatusBadRequest, fmt.Sprintf("invalid Hosts entry %q: %q is not an IP address", host, address))
				return
			}
			hosts[host] = address
		}
		hostsMu.Lock()
		configuration.Hosts = hosts
		hostsMu.Unlock()
		if dnsCache != nil {
			dnsCache.Purge()
		}
	}
	if form.SystemProxy != nil {
		configuration.SystemProxy = *form.SystemProxy
	}
	if form.SystemProxyExclude != nil {
		configuration.SystemProxyExclude = append([]string(nil), (*form.SystemProxyExclude)...)
	}
	pacHijackChanged := false
	if form.PacHijack != nil && *form.PacHijack != configuration.PacHijack {
		configuration.PacHijack = *form.PacHijack
		pacHijackChanged = true
	}
	if form.PacHijackHost != "" {
		configuration.PacHijackHost = form.PacHijackHost
	}
	forceChromeChanged := false
	if form.ForceChrome != nil && *form.ForceChrome != configuration.ForceChrome {
		configuration.ForceChrome = *form.ForceChrome
		forceChromeChanged = true
	}
	if err := persistConfigurationLocked(); err != nil {
		configMu.Unlock()
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	pacHijackEnabled := configuration.PacHijack
	pacHijackHost := configuration.PacHijackHost
	if pacHijackHost == "" {
		pacHijackHost = "wpad"
	}
	forceChromeEnabled := configuration.ForceChrome
	socksAddress := configuration.SocksAddress
	configMu.Unlock()

	if restart {
		log.Printf("Listen address changed to %s, restarting listener", configuration.Address)
		restartListener()
	}
	if socksRestart {
		log.Printf("SOCKS5 listen address changed to %q, restarting listener", socksAddress)
		restartSocksListener()
	}
	if pacHijackChanged {
		if pacHijackEnabled {
			if err := ensureHostsEntry(pacHijackHost); err != nil {
				log.Printf("PAC hijack: cannot update %s: %+v (sudo needed?)", hostsFile, err)
			}
		} else {
			if err := removeHostsEntry(pacHijackHost); err != nil {
				log.Printf("PAC hijack: cannot update %s: %+v", hostsFile, err)
			}
		}
		restartPacListener()
	}
	if forceChromeChanged {
		if forceChromeEnabled {
			applyChromePolicy()
		} else {
			removeChromePolicy()
		}
	}
	if configuration.SystemProxy {
		go applySystemProxy()
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

func apiFinishOnboarding(w http.ResponseWriter, r *http.Request) {
	configMu.Lock()
	configuration.OnboardingDone = boolPtr(true)
	err := persistConfigurationLocked()
	configMu.Unlock()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

var configMu sync.Mutex

func persistConfigurationLocked() error {
	data, err := yaml.Marshal(configuration)
	if err != nil {
		return err
	}
	key, salt, ok := configCrypto()
	if !ok {
		return errors.New("configuration key is locked: restart the proxy and unlock it")
	}
	enc, err := encryptWithKey(key, salt, data)
	if err != nil {
		return err
	}
	if err := writeSecretFileAtomic(encryptedConfig, enc); err != nil {
		return err
	}
	// The legacy plaintext file must not survive next to the encrypted one.
	if err := os.Remove(plainConfig); err != nil && !os.IsNotExist(err) {
		log.Printf("WARNING: cannot remove %s: %v", plainConfig, err)
	}
	return nil
}

func reapplyRoutesLocked() {
	loadRoutes()
	if fr := getForceRoute(); fr != nil {
		name := fr.name
		setForceRoute(nil)
		for _, rt := range getRoutes() {
			if rt.name == name {
				setForceRoute(rt)
				break
			}
		}
	}
}
