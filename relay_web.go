package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"proxy/relay"
)

type relayConfigJSON struct {
	Name           string `json:"name"`
	Address        string `json:"address"`
	Route          string `json:"route"`
	AllowLocal     bool   `json:"allowLocal"`
	Device         string `json:"device"`
	EnrollURL      string `json:"enrollUrl,omitempty"`
	HasCertificate bool   `json:"hasCertificate"`
	HasCA          bool   `json:"hasCA"`
	// NetworkLabel and ShareContext control what contacts learn about the
	// network this device is on (a label you choose and whether a VPN is up).
	NetworkLabel  string         `json:"networkLabel"`
	NetworkLabels []NetworkLabel `json:"networkLabels"`
	ShareContext  bool           `json:"shareContext"`
	// SharedNow is what contacts see at this moment, to check the table.
	SharedNow sharedNowJSON `json:"sharedNow"`
}

type sharedNowJSON struct {
	Sharing bool   `json:"sharing"`
	Label   string `json:"label"`
	VPN     bool   `json:"vpn"`
	// Rule is the index of the matching NetworkLabels entry, or -1 when the
	// default label applies.
	Rule int `json:"rule"`
}

func sharedNowFor(cfg *RelayConfig) sharedNowJSON {
	ctx, matched := sharedContextFor(cfg)
	if ctx == nil {
		return sharedNowJSON{Rule: -1}
	}
	return sharedNowJSON{Sharing: true, Label: ctx.Label, VPN: ctx.VPN, Rule: matched}
}

// relayConfigInfoLocked describes one relay's configuration; the caller holds
// configMu. A nil cfg describes the empty configuration of a relay to add.
func relayConfigInfoLocked(cfg *RelayConfig) relayConfigJSON {
	if cfg == nil {
		return relayConfigJSON{ShareContext: true, NetworkLabels: []NetworkLabel{}, SharedNow: sharedNowJSON{Rule: -1}}
	}
	return relayConfigJSON{
		Name:           cfg.Name,
		Address:        cfg.Address,
		Route:          cfg.Route,
		AllowLocal:     cfg.AllowLocal,
		NetworkLabel:   cfg.NetworkLabel,
		NetworkLabels:  append([]NetworkLabel{}, cfg.NetworkLabels...),
		ShareContext:   cfg.ShareContext == nil || *cfg.ShareContext,
		SharedNow:      sharedNowFor(cfg),
		Device:         cfg.Device,
		EnrollURL:      cfg.EnrollURL,
		HasCertificate: cfg.CertPEM != "" || (cfg.Cert != "" && cfg.Key != ""),
		HasCA:          cfg.CAPEM != "" || cfg.CA != "",
	}
}

// maxRelays bounds how many relays an installation connects to.
const maxRelays = 8

// relayQuery is the relay a request is about (?relay=name); empty means the
// first one.
func relayQuery(r *http.Request) string {
	return strings.ToLower(strings.TrimSpace(r.URL.Query().Get("relay")))
}

// relayFor returns the relay the request is about, or answers 404.
func relayFor(w http.ResponseWriter, r *http.Request) (*relayClient, bool) {
	c, ok := relayHub.pick(relayQuery(r))
	if !ok {
		writeAPIError(w, http.StatusNotFound, "relay not found")
		return nil, false
	}
	return c, true
}

// emptyRelayStatus is what the page gets before any relay is configured.
func emptyRelayStatus() relayStatusJSON {
	return relayStatusJSON{
		Contacts: []relay.Contact{}, MyDevices: []relay.DeviceInfo{}, Incoming: []string{}, Outgoing: []string{},
		Approvals: []*relayApproval{}, Rules: []relayRule{},
	}
}

func registerRelayRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/relay", func(w http.ResponseWriter, r *http.Request) {
		if relayQuery(r) == "" && len(relayHub.list()) == 0 {
			writeJSON(w, emptyRelayStatus())
			return
		}
		if c, ok := relayFor(w, r); ok {
			writeJSON(w, c.Status())
		}
	})
	// Every configured relay at once: the page shows them side by side and the
	// header counts what is waiting across all of them.
	m.HandleFunc("GET /api/relays", func(w http.ResponseWriter, r *http.Request) {
		out := []relayStatusJSON{}
		for _, c := range relayHub.list() {
			out = append(out, c.Status())
		}
		writeJSON(w, out)
	})
	m.HandleFunc("GET /api/relay/config", func(w http.ResponseWriter, r *http.Request) {
		configMu.Lock()
		var cfg *RelayConfig
		if name := relayQuery(r); name != "" {
			cfg = findRelayConfigLocked(name)
		} else if len(configuration.Relays) > 0 {
			cfg = configuration.Relays[0]
		}
		info := relayConfigInfoLocked(cfg)
		configMu.Unlock()
		writeJSON(w, info)
	})
	m.HandleFunc("GET /api/relays/config", func(w http.ResponseWriter, r *http.Request) {
		configMu.Lock()
		out := []relayConfigJSON{}
		for _, cfg := range configuration.Relays {
			out = append(out, relayConfigInfoLocked(cfg))
		}
		configMu.Unlock()
		writeJSON(w, out)
	})
	m.HandleFunc("DELETE /api/relay/config", func(w http.ResponseWriter, r *http.Request) {
		name := relayQuery(r)
		if name == "" {
			writeAPIError(w, http.StatusBadRequest, "name the relay to remove (?relay=name)")
			return
		}
		configMu.Lock()
		kept := configuration.Relays[:0:0]
		found := false
		for _, cfg := range configuration.Relays {
			if cfg.Name == name {
				found = true
				continue
			}
			kept = append(kept, cfg)
		}
		if !found {
			configMu.Unlock()
			writeAPIError(w, http.StatusNotFound, "relay not found")
			return
		}
		configuration.Relays = kept
		err := persistConfigurationLocked()
		configMu.Unlock()
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if c := relayHub.get(name); c != nil {
			file := c.stateFile()
			relayHub.remove(name)
			os.Remove(file) // the address book of a relay you left is not kept
		}
		writeJSON(w, map[string]string{"status": "ok"})
	})
	m.HandleFunc("POST /api/relay/config", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Name             string          `json:"name"`
			Address          string          `json:"address"`
			Route            string          `json:"route"`
			AllowLocal       bool            `json:"allowLocal"`
			CertPEM          string          `json:"certPem"`
			KeyPEM           string          `json:"keyPem"`
			CAPEM            string          `json:"caPem"`
			ClearCertificate bool            `json:"clearCertificate"`
			NetworkLabel     *string         `json:"networkLabel"`
			NetworkLabels    *[]NetworkLabel `json:"networkLabels"`
			ShareContext     *bool           `json:"shareContext"`
		}
		if err := readJSON(r, &body); err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid body")
			return
		}
		address := strings.TrimSpace(body.Address)
		if address == "" {
			writeAPIError(w, http.StatusBadRequest, "relay address is required")
			return
		}
		if strings.Contains(address, ":") {
			if _, _, err := net.SplitHostPort(address); err != nil {
				writeAPIError(w, http.StatusBadRequest, "relay address must be host:port")
				return
			}
		}
		route := strings.TrimSpace(body.Route)
		if route != "" {
			found := false
			for _, rt := range getRoutes() {
				if rt.name == route {
					found = true
					break
				}
			}
			if !found {
				writeAPIError(w, http.StatusBadRequest, "route does not exist")
				return
			}
		}
		if (body.CertPEM == "") != (body.KeyPEM == "") {
			writeAPIError(w, http.StatusBadRequest, "both certificate and private key are required")
			return
		}
		if body.CertPEM != "" {
			if _, err := tls.X509KeyPair([]byte(body.CertPEM), []byte(body.KeyPEM)); err != nil {
				writeAPIError(w, http.StatusBadRequest, "invalid certificate/key pair: "+err.Error())
				return
			}
		}
		if strings.TrimSpace(body.CAPEM) != "" {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM([]byte(body.CAPEM)) {
				writeAPIError(w, http.StatusBadRequest, "invalid CA PEM")
				return
			}
		}

		var labels []NetworkLabel
		if body.NetworkLabels != nil {
			var err error
			if labels, err = validateNetworkLabels(*body.NetworkLabels); err != nil {
				writeAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
		}

		// Which relay: the one named in the body or the query, else the first, else
		// a new one called "default". An unknown name adds a relay.
		name := strings.ToLower(strings.TrimSpace(body.Name))
		if name == "" {
			name = relayQuery(r)
		}
		configMu.Lock()
		if name == "" {
			if len(configuration.Relays) > 0 {
				name = configuration.Relays[0].Name
			} else {
				name = defaultRelayName
			}
		}
		if !validRelayName(name) {
			configMu.Unlock()
			writeAPIError(w, http.StatusBadRequest, "invalid relay name (lowercase letters, digits, - and _, at most 30)")
			return
		}
		cfg := findRelayConfigLocked(name)
		if cfg == nil {
			if len(configuration.Relays) >= maxRelays {
				configMu.Unlock()
				writeAPIError(w, http.StatusBadRequest, "too many relays")
				return
			}
			cfg = &RelayConfig{Name: name}
			if len(configuration.Relays) > 0 {
				// your devices keep the same name on every relay
				cfg.Device = configuration.Relays[0].Device
			}
			configuration.Relays = append(configuration.Relays, cfg)
		}
		cfg.Address = address
		cfg.Route = route
		cfg.AllowLocal = body.AllowLocal
		if body.NetworkLabel != nil {
			if sc := relay.SanitizeContext(&relay.NetContext{Label: *body.NetworkLabel}); sc != nil {
				cfg.NetworkLabel = sc.Label
			}
		}
		if body.NetworkLabels != nil {
			cfg.NetworkLabels = labels
		}
		if body.ShareContext != nil {
			share := *body.ShareContext
			cfg.ShareContext = &share
		}
		if cfg.Device == "" {
			cfg.Device = randomDeviceID()
		}
		if body.ClearCertificate {
			cfg.CertPEM, cfg.KeyPEM, cfg.CAPEM = "", "", ""
			cfg.Cert, cfg.Key, cfg.CA = "", "", ""
		} else {
			if body.CertPEM != "" {
				cfg.CertPEM, cfg.KeyPEM = body.CertPEM, body.KeyPEM
				cfg.Cert, cfg.Key = "", ""
			}
			if strings.TrimSpace(body.CAPEM) != "" {
				cfg.CAPEM = body.CAPEM
				cfg.CA = ""
			}
		}
		err := persistConfigurationLocked()
		info := relayConfigInfoLocked(cfg)
		configMu.Unlock()
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		relayHub.apply(cfg)
		writeJSON(w, info)
	})
	m.HandleFunc("POST /api/relay/ping", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Email  string `json:"email"`
			Device string `json:"device"`
		}
		if err := readJSON(r, &body); err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid body")
			return
		}
		email := strings.TrimSpace(body.Email)
		if email != "" {
			if _, ok := relay.NormalizeEmail(email); !ok {
				writeAPIError(w, http.StatusBadRequest, "invalid e-mail address")
				return
			}
		}
		device, ok := relay.NormalizeDevice(body.Device)
		if !ok {
			writeAPIError(w, http.StatusBadRequest, "invalid device")
			return
		}
		// A failed probe is a result, not a server error: the page shows why.
		if relayQuery(r) == "" && len(relayHub.list()) == 0 {
			writeJSON(w, map[string]any{"ok": false, "error": "not connected to any relay"})
			return
		}
		c, ok := relayFor(w, r)
		if !ok {
			return
		}
		rtt, err := c.Ping(email, device)
		res := map[string]any{"ok": err == nil}
		if err != nil {
			res["error"] = err.Error()
		} else {
			res["rttMs"] = float64(rtt.Microseconds()) / 1000
		}
		writeJSON(w, res)
	})
	m.HandleFunc("POST /api/relay/contacts", func(w http.ResponseWriter, r *http.Request) {
		relayCommand(w, r, relay.TContactRequest)
	})
	m.HandleFunc("POST /api/relay/contacts/respond", func(w http.ResponseWriter, r *http.Request) {
		relayCommand(w, r, relay.TContactRespond)
	})
	m.HandleFunc("POST /api/relay/contacts/remove", func(w http.ResponseWriter, r *http.Request) {
		relayCommand(w, r, relay.TContactRemove)
	})
	m.HandleFunc("POST /api/relay/approvals/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		var dec relayDecision
		if err != nil || readJSON(r, &dec) != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid request")
			return
		}
		c, ok := relayFor(w, r)
		if !ok {
			return
		}
		if !c.Decide(id, dec) {
			writeAPIError(w, http.StatusNotFound, "request expired")
			return
		}
		writeJSON(w, map[string]string{"status": "ok"})
	})
	m.HandleFunc("DELETE /api/relay/rules/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid id")
			return
		}
		c, ok := relayFor(w, r)
		if !ok {
			return
		}
		c.RemoveRule(id)
		writeJSON(w, map[string]string{"status": "ok"})
	})
	m.HandleFunc("POST /api/relay/device", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Device string `json:"device"`
		}
		if err := readJSON(r, &body); err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid body")
			return
		}
		device, ok := relay.NormalizeDevice(body.Device)
		if !ok || device == "" {
			writeAPIError(w, http.StatusBadRequest, "invalid device code")
			return
		}
		c, ok := relayFor(w, r)
		if !ok {
			writeAPIError(w, http.StatusBadRequest, "relay not configured")
			return
		}
		configMu.Lock()
		cfg := findRelayConfigLocked(c.name)
		if cfg == nil {
			configMu.Unlock()
			writeAPIError(w, http.StatusBadRequest, "relay not configured")
			return
		}
		cfg.Device = device
		err := persistConfigurationLocked()
		configMu.Unlock()
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		c.SetDevice(device)
		writeJSON(w, map[string]string{"status": "ok", "device": device})
	})
	// Enrollment: the e-mail code, or one of the sign-in methods the relay
	// offers. All of them end with a certificate and a configured relay.
	m.HandleFunc("POST /api/relay/enroll", func(w http.ResponseWriter, r *http.Request) {
		body, ok := readEnrollBody(w, r)
		if !ok {
			return
		}
		// The first request. The relay either sends an e-mail code or, when it
		// offers several ways to sign in, answers 401 with the list: that is not
		// an error for the page, it is the next step.
		begin, err := relayEnroll(body.name(r), body.Address, body.Email, body.CAPEM, body.AcceptFingerprint, body.Method)
		if err != nil {
			writeEnrollError(w, err)
			return
		}
		if begin.CodeSent {
			writeJSON(w, map[string]string{"status": "code_sent"})
			return
		}
		writeJSON(w, map[string]any{"status": "auth_required", "methods": begin.Methods})
	})
	// User name and password typed in the proxy (methods password and ldap).
	m.HandleFunc("POST /api/relay/enroll/login", func(w http.ResponseWriter, r *http.Request) {
		body, ok := readEnrollBody(w, r)
		if !ok {
			return
		}
		if err := relayEnrollLogin(body.name(r), body.Address, body.Email, body.CAPEM, body.AcceptFingerprint, body.Method, body.Username, body.Password); err != nil {
			writeEnrollError(w, err)
			return
		}
		writeJSON(w, map[string]string{"status": "ok"})
	})
	// Sign-in on the provider's page (methods oidc and saml): returns the
	// address to open; GET /api/relay/enroll then reports when it is done.
	m.HandleFunc("POST /api/relay/enroll/start", func(w http.ResponseWriter, r *http.Request) {
		body, ok := readEnrollBody(w, r)
		if !ok {
			return
		}
		authURL, err := relayEnrollStart(body.name(r), body.Address, body.Email, body.CAPEM, body.AcceptFingerprint, body.Method)
		if err != nil {
			writeEnrollError(w, err)
			return
		}
		writeJSON(w, map[string]string{"status": "started", "authUrl": authURL})
	})
	m.HandleFunc("GET /api/relay/enroll", func(w http.ResponseWriter, r *http.Request) {
		pollBrowserEnrollment() // a sign-in in the browser may have finished
		writeJSON(w, enrollPendingInfo())
	})
	m.HandleFunc("DELETE /api/relay/enroll", func(w http.ResponseWriter, r *http.Request) {
		relayEnrollCancel()
		writeJSON(w, map[string]string{"status": "ok"})
	})
	m.HandleFunc("POST /api/relay/enroll/confirm", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Code string `json:"code"`
		}
		if err := readJSON(r, &body); err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid body")
			return
		}
		if err := relayEnrollConfirm(body.Code); err != nil {
			writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, map[string]string{"status": "ok"})
	})
}

// enrollBody is what the pages send to start or continue an enrollment.
type enrollBody struct {
	Name              string `json:"name"`
	Address           string `json:"address"`
	Email             string `json:"email"`
	CAPEM             string `json:"caPem"`
	AcceptFingerprint string `json:"acceptFingerprint"`
	Method            string `json:"method"`
	Username          string `json:"username"`
	Password          string `json:"password"`
}

// name is the relay being enrolled: the body's, else the query's.
func (b enrollBody) name(r *http.Request) string {
	if n := strings.ToLower(strings.TrimSpace(b.Name)); n != "" {
		return n
	}
	return relayQuery(r)
}

func readEnrollBody(w http.ResponseWriter, r *http.Request) (enrollBody, bool) {
	var body enrollBody
	if err := readJSON(r, &body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid body")
		return body, false
	}
	return body, true
}

// writeEnrollError answers a failed enrollment step. An untrusted server
// certificate is not an error to show but a question to ask: its details are
// sent so that the user can check the fingerprint.
func writeEnrollError(w http.ResponseWriter, err error) {
	var untrusted *untrustedCertificateError
	if errors.As(err, &untrusted) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		writeJSON(w, map[string]any{
			"error":       untrusted.Error(),
			"certificate": untrusted.Info,
		})
		return
	}
	writeAPIError(w, http.StatusBadGateway, err.Error())
}

func relayCommand(w http.ResponseWriter, r *http.Request, typ string) {
	var m relay.ClientMsg
	if err := readJSON(r, &m); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid body")
		return
	}
	email, ok := relay.NormalizeEmail(m.Email)
	if !ok {
		writeAPIError(w, http.StatusBadRequest, "invalid e-mail address")
		return
	}
	m.T, m.Email = typ, email
	c, ok := relayFor(w, r)
	if !ok {
		return
	}
	if err := c.send(m); err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}
