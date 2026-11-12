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
	"path"
	"strconv"
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

	// Interfaces is the proxy configuration of every active interface.
	Interfaces []ifaceProxyJSON `json:"interfaces"`

	// Transparent is the state of the transparent routing (macOS).
	Transparent transparentStatusJSON `json:"transparent"`
}

type transparentStatusJSON struct {
	Configured []string `json:"configured"` // selectors in the configuration
	Interfaces []string `json:"interfaces"` // interfaces they resolve to now
	Loaded     bool     `json:"loaded"`     // the packet filter rules are loaded
	Error      string   `json:"error"`      // last problem
	Hint       string   `json:"hint"`       // what to do about it
	NeedsAuth  bool     `json:"needsAuth"`  // the user has to authorize the privileged helper
	Mode       string   `json:"mode"`       // ask, auto or never
}

type ifaceProxyJSON struct {
	Service     string `json:"service"`
	Iface       string `json:"iface"`
	Primary     bool   `json:"primary"`
	Dynamic     bool   `json:"dynamic"`
	Excluded    bool   `json:"excluded"`
	HTTPEnable  bool   `json:"httpEnabled"`
	HTTPProxy   string `json:"httpProxy"`
	HTTPPort    int    `json:"httpPort"`
	HTTPSEnable bool   `json:"httpsEnabled"`
	HTTPSProxy  string `json:"httpsProxy"`
	HTTPSPort   int    `json:"httpsPort"`
	PACEnable   bool   `json:"pacEnabled"`
}

func newAPIMux() *http.ServeMux {
	m := http.NewServeMux()
	registerRelayRoutes(m)
	registerRuleRoutes(m)
	registerBlockingRoutes(m)
	registerSecurityRoutes(m)
	registerLocalAuthRoutes(m)
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
	m.HandleFunc("POST /api/transparent/authorize", apiTransparentAuthorize)
	return m
}

func apiTransparentAuthorize(w http.ResponseWriter, r *http.Request) {
	go authorizeTransparent()
	writeJSON(w, map[string]string{"status": "ok"})
}

func apiSystemProxy(w http.ResponseWriter, r *http.Request) {
	st := systemProxyState()
	st.Transparent = transparentStatus()
	writeJSON(w, st)
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
	IFaceUp    string      `json:"ifaceUp,omitempty"`
	VPN        string      `json:"vpn,omitempty"`
	ExitVPN    string      `json:"exitVpn,omitempty"`
	ExitLabel  string      `json:"exitLabel,omitempty"`
	Chain      []string    `json:"chain"`
	Hops       []ConfigHop `json:"hops"`
	RulesOnly  bool        `json:"rulesOnly"`
	Applicable bool        `json:"applicable"`
	WhyNot     string      `json:"whyNot,omitempty"`
	PacStatus  string      `json:"pacStatus"`
	PacError   string      `json:"pacError,omitempty"`
}

// vpnStateJSON describes what the network detection currently sees, so the UI
// can explain why a route was or was not chosen.
type vpnStateJSON struct {
	Active       bool          `json:"active"`
	Interfaces   []string      `json:"interfaces"`
	DefaultIface string        `json:"defaultIface"`
	All          []ifaceStatus `json:"all"`
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
	TransparentRoute   []string          `json:"transparentRoute"`
	TransparentMode    string            `json:"transparentMode"`
	AllowRemoteClients bool              `json:"allowRemoteClients"`
	Hosts              map[string]string `json:"hosts"`
	UptimeSeconds      int64             `json:"uptimeSeconds"`
	ActiveConns        int               `json:"activeConns"`
	Routes             []routeInfoJSON   `json:"routes"`
	VPN                vpnStateJSON      `json:"vpn"`
	DNS                []dnsEntryJSON    `json:"dns"`
}

func apiState(w http.ResponseWriter, r *http.Request) {
	st := getNetState()

	configMu.Lock()
	address := configuration.Address
	socksAddress := configuration.SocksAddress
	systemProxy := configuration.SystemProxy
	systemProxyExclude := append([]string(nil), configuration.SystemProxyExclude...)
	transparentRoute := append([]string{}, configuration.TransparentRoute...)
	transparentMode := configuration.TransparentMode
	if transparentMode == "" {
		transparentMode = "ask"
	}
	allowRemote := configuration.AllowRemoteClients
	onboarding := configuration.OnboardingDone != nil && !*configuration.OnboardingDone
	configMu.Unlock()

	hosts := map[string]string{}
	hostsMu.RLock()
	for host, address := range configuration.Hosts {
		hosts[host] = address
	}
	hostsMu.RUnlock()

	state := stateJSON{
		Address:      address,
		SocksAddress: socksAddress,
		Onboarding:   onboarding,
		Iface:        st.iface.Name,
		Gateway:      fmt.Sprintf("%v", st.defaultGw),
		Network:      netString(st.network),
		VPN: vpnStateJSON{
			Active:       len(st.analysis.VPN) > 0,
			Interfaces:   append([]string{}, st.analysis.VPN...),
			DefaultIface: st.analysis.DefaultIface,
			All:          append([]ifaceStatus{}, st.analysis.Ifaces...),
		},
		SystemProxy:        systemProxy,
		SystemProxyExclude: systemProxyExclude,
		TransparentRoute:   transparentRoute,
		TransparentMode:    transparentMode,
		AllowRemoteClients: allowRemote,
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
	Name      string      `json:"name"`
	Gateway   string      `json:"gateway"`
	IFace     string      `json:"iface"`
	Net       string      `json:"net"`
	IFaceUp   string      `json:"ifaceUp"`
	VPN       string      `json:"vpn"`
	ExitVPN   string      `json:"exitVpn"`
	ExitLabel string      `json:"exitLabel"`
	Hops      []ConfigHop `json:"hops"`
	RulesOnly bool        `json:"rulesOnly"`
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
	if v := strings.ToLower(strings.TrimSpace(form.VPN)); v != "" && v != "up" && v != "down" {
		writeAPIError(w, http.StatusBadRequest, `vpn must be empty, "up" or "down"`)
		return
	}
	if !validExitVPN(strings.ToLower(strings.TrimSpace(form.ExitVPN))) {
		writeAPIError(w, http.StatusBadRequest, `exitVpn must be empty, "up" or "down"`)
		return
	}
	if !validLabelPattern(form.ExitLabel) {
		writeAPIError(w, http.StatusBadRequest, "invalid exit label pattern")
		return
	}
	for _, pat := range strings.Split(form.IFaceUp+","+form.IFace, ",") {
		if _, err := path.Match(strings.ToLower(strings.TrimSpace(pat)), ""); err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid interface pattern "+strconv.Quote(strings.TrimSpace(pat)))
			return
		}
	}

	configMu.Lock()
	route := ConfigRoute{
		Chain:     form.Hops,
		Name:      form.Name,
		Gateway:   form.Gateway,
		IFace:     form.IFace,
		Net:       form.Net,
		IFaceUp:   strings.TrimSpace(form.IFaceUp),
		VPN:       strings.ToLower(strings.TrimSpace(form.VPN)),
		ExitVPN:   strings.ToLower(strings.TrimSpace(form.ExitVPN)),
		ExitLabel: strings.TrimSpace(form.ExitLabel),
		RulesOnly: form.RulesOnly,
	}
	found := false
	for i := range configuration.Routes {
		if configuration.Routes[i].Name == form.Name {
			configuration.Routes[i] = route
			found = true
			break
		}
	}
	if !found {
		configuration.Routes = append(configuration.Routes, route)
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
	// ClearPassword removes the stored password (an empty Password otherwise
	// means "keep the current one").
	ClearPassword bool `json:"clearPassword"`
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
			if password == "" && !form.ClearPassword {
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
			if rt.rulesOnly {
				writeAPIError(w, http.StatusBadRequest, "a rules-only route cannot be forced; use a destination rule")
				return
			}
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
	transparentRoute := append([]string{}, configuration.TransparentRoute...)
	transparentMode := configuration.TransparentMode
	if transparentMode == "" {
		transparentMode = "ask"
	}
	allowRemote := configuration.AllowRemoteClients
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
		"transparentRoute":   transparentRoute,
		"transparentMode":    transparentMode,
		"allowRemoteClients": allowRemote,
	})
}

type configFormJSON struct {
	Address            string             `json:"address"`
	SocksAddress       *string            `json:"socksAddress"`
	Hosts              *map[string]string `json:"hosts"`
	SystemProxy        *bool              `json:"systemProxy"`
	SystemProxyExclude *[]string          `json:"systemProxyExclude"`
	TransparentRoute   *[]string          `json:"transparentRoute"`
	TransparentMode    *string            `json:"transparentMode"`
	AllowRemoteClients *bool              `json:"allowRemoteClients"`
}

func apiSaveConfig(w http.ResponseWriter, r *http.Request) {
	var form configFormJSON
	if err := readJSON(r, &form); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid body")
		return
	}

	if form.Address != "" {
		if err := validateListenAddress(form.Address, false); err != nil {
			writeAPIError(w, http.StatusBadRequest, "address: "+err.Error())
			return
		}
	}
	if form.SocksAddress != nil {
		if err := validateListenAddress(*form.SocksAddress, true); err != nil {
			writeAPIError(w, http.StatusBadRequest, "socksAddress: "+err.Error())
			return
		}
	}
	// The listeners have no client authentication: binding anything but
	// loopback is only accepted together with an explicit opt-in.
	configMu.Lock()
	allowRemote := configuration.AllowRemoteClients
	if form.AllowRemoteClients != nil {
		allowRemote = *form.AllowRemoteClients
	}
	wantAddr, wantSocks := configuration.Address, configuration.SocksAddress
	if form.Address != "" {
		wantAddr = form.Address
	}
	if form.SocksAddress != nil {
		wantSocks = *form.SocksAddress
	}
	configMu.Unlock()
	if !allowRemote && (!addressIsLoopbackOnly(wantAddr) || !addressIsLoopbackOnly(wantSocks)) {
		writeAPIError(w, http.StatusBadRequest, "listening on a non-loopback address requires allowRemoteClients: anyone who can reach it could use your upstream credentials")
		return
	}

	configMu.Lock()
	restart := false
	socksRestart := false
	if form.AllowRemoteClients != nil {
		configuration.AllowRemoteClients = *form.AllowRemoteClients
	}
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
	if form.TransparentRoute != nil {
		configuration.TransparentRoute = append([]string(nil), (*form.TransparentRoute)...)
	}
	if form.TransparentMode != nil {
		switch *form.TransparentMode {
		case "ask":
			configuration.TransparentMode = ""
		case "auto", "never":
			configuration.TransparentMode = *form.TransparentMode
		}
	}
	if err := persistConfigurationLocked(); err != nil {
		configMu.Unlock()
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
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
	if configuration.SystemProxy {
		go applySystemProxy()
	} else {
		go restoreSystemProxy()
	}
	go applyTransparentRouting()
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
			if rt.name == name && !rt.rulesOnly {
				setForceRoute(rt)
				break
			}
		}
	}
}
