package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
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
	Address            string          `json:"address"`
	Iface              string          `json:"iface"`
	Gateway            string          `json:"gateway"`
	Network            string          `json:"network"`
	ForceRoute         string          `json:"forceRoute"`
	SystemProxy        bool            `json:"systemProxy"`
	SystemProxyExclude []string        `json:"systemProxyExclude"`
	PacHijack          bool            `json:"pacHijack"`
	PacHijackHost      string          `json:"pacHijackHost"`
	ForceChrome        bool            `json:"forceChrome"`
	UptimeSeconds      int64           `json:"uptimeSeconds"`
	ActiveConns        int             `json:"activeConns"`
	Routes             []routeInfoJSON `json:"routes"`
	DNS                []dnsEntryJSON  `json:"dns"`
}

func apiState(w http.ResponseWriter, r *http.Request) {
	st := getNetState()

	configMu.Lock()
	address := configuration.Address
	systemProxy := configuration.SystemProxy
	systemProxyExclude := append([]string(nil), configuration.SystemProxyExclude...)
	pacHijack := configuration.PacHijack
	pacHijackHost := configuration.PacHijackHost
	forceChrome := configuration.ForceChrome
	configMu.Unlock()

	state := stateJSON{
		Address:            address,
		Iface:              st.iface.Name,
		Gateway:            fmt.Sprintf("%v", st.defaultGw),
		Network:            netString(st.network),
		SystemProxy:        systemProxy,
		SystemProxyExclude: systemProxyExclude,
		PacHijack:          pacHijack,
		PacHijackHost:      pacHijackHost,
		ForceChrome:        forceChrome,
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

func apiListCredentials(w http.ResponseWriter, r *http.Request) {
	configMu.Lock()
	creds := append([]ConfigCredential(nil), configuration.Credentials...)
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
			configuration.Credentials[i] = ConfigCredential{
				Name:     form.Name,
				User:     form.User,
				Password: form.Password,
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
	systemProxy := configuration.SystemProxy
	systemProxyExclude := append([]string(nil), configuration.SystemProxyExclude...)
	pacHijack := configuration.PacHijack
	pacHijackHost := configuration.PacHijackHost
	forceChrome := configuration.ForceChrome
	configMu.Unlock()
	writeJSON(w, map[string]interface{}{
		"address":            address,
		"systemProxy":        systemProxy,
		"systemProxyExclude": systemProxyExclude,
		"pacHijack":          pacHijack,
		"pacHijackHost":      pacHijackHost,
		"forceChrome":        forceChrome,
	})
}

type configFormJSON struct {
	Address            string    `json:"address"`
	SystemProxy        *bool     `json:"systemProxy"`
	SystemProxyExclude *[]string `json:"systemProxyExclude"`
	PacHijack          *bool     `json:"pacHijack"`
	PacHijackHost      string    `json:"pacHijackHost"`
	ForceChrome        *bool     `json:"forceChrome"`
}

func apiSaveConfig(w http.ResponseWriter, r *http.Request) {
	var form configFormJSON
	if err := readJSON(r, &form); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid body")
		return
	}

	configMu.Lock()
	restart := false
	if form.Address != "" && form.Address != configuration.Address {
		restart = true
		configuration.Address = form.Address
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
	configMu.Unlock()

	if restart {
		log.Printf("Listen address changed to %s, restarting listener", configuration.Address)
		restartListener()
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

var configMu sync.Mutex

func persistConfigurationLocked() error {
	data, err := yaml.Marshal(configuration)
	if err != nil {
		return err
	}
	tmp := "config.yml.tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, "config.yml")
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
