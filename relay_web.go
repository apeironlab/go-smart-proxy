package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"

	"proxy/relay"
)

type relayConfigJSON struct {
	Address        string `json:"address"`
	Route          string `json:"route"`
	AllowLocal     bool   `json:"allowLocal"`
	Device         string `json:"device"`
	EnrollURL      string `json:"enrollUrl,omitempty"`
	HasCertificate bool   `json:"hasCertificate"`
	HasCA          bool   `json:"hasCA"`
	// NetworkLabel and ShareContext control what contacts learn about the
	// network this device is on (a label you choose and whether a VPN is up).
	NetworkLabel string `json:"networkLabel"`
	ShareContext bool   `json:"shareContext"`
}

func relayConfigInfoLocked() relayConfigJSON {
	if configuration.Relay == nil {
		return relayConfigJSON{ShareContext: true}
	}
	cfg := configuration.Relay
	return relayConfigJSON{
		Address:        cfg.Address,
		Route:          cfg.Route,
		AllowLocal:     cfg.AllowLocal,
		NetworkLabel:   cfg.NetworkLabel,
		ShareContext:   cfg.ShareContext == nil || *cfg.ShareContext,
		Device:         cfg.Device,
		EnrollURL:      cfg.EnrollURL,
		HasCertificate: cfg.CertPEM != "" || (cfg.Cert != "" && cfg.Key != ""),
		HasCA:          cfg.CAPEM != "" || cfg.CA != "",
	}
}

func registerRelayRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/relay", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, relayMgr.Status())
	})
	m.HandleFunc("GET /api/relay/config", func(w http.ResponseWriter, r *http.Request) {
		configMu.Lock()
		info := relayConfigInfoLocked()
		configMu.Unlock()
		writeJSON(w, info)
	})
	m.HandleFunc("POST /api/relay/config", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Address          string  `json:"address"`
			Route            string  `json:"route"`
			AllowLocal       bool    `json:"allowLocal"`
			CertPEM          string  `json:"certPem"`
			KeyPEM           string  `json:"keyPem"`
			CAPEM            string  `json:"caPem"`
			ClearCertificate bool    `json:"clearCertificate"`
			NetworkLabel     *string `json:"networkLabel"`
			ShareContext     *bool   `json:"shareContext"`
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

		configMu.Lock()
		if configuration.Relay == nil {
			configuration.Relay = &RelayConfig{}
		}
		cfg := configuration.Relay
		cfg.Address = address
		cfg.Route = route
		cfg.AllowLocal = body.AllowLocal
		if body.NetworkLabel != nil {
			if sc := relay.SanitizeContext(&relay.NetContext{Label: *body.NetworkLabel}); sc != nil {
				cfg.NetworkLabel = sc.Label
			}
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
		info := relayConfigInfoLocked()
		configMu.Unlock()
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		relayMgr.start(cfg)
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
		rtt, err := relayMgr.Ping(email, device)
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
		if !relayMgr.Decide(id, dec) {
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
		relayMgr.RemoveRule(id)
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
		configMu.Lock()
		if configuration.Relay == nil {
			configMu.Unlock()
			writeAPIError(w, http.StatusBadRequest, "relay not configured")
			return
		}
		configuration.Relay.Device = device
		err := persistConfigurationLocked()
		configMu.Unlock()
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		relayMgr.SetDevice(device)
		writeJSON(w, map[string]string{"status": "ok", "device": device})
	})
	m.HandleFunc("POST /api/relay/enroll", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Address           string `json:"address"`
			Email             string `json:"email"`
			CAPEM             string `json:"caPem"`
			AcceptFingerprint string `json:"acceptFingerprint"`
		}
		if err := readJSON(r, &body); err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid body")
			return
		}
		if err := relayEnroll(body.Address, body.Email, body.CAPEM, body.AcceptFingerprint); err != nil {
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
			return
		}
		writeJSON(w, map[string]string{"status": "code_sent"})
	})
	m.HandleFunc("GET /api/relay/enroll", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, enrollPendingInfo())
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
	if err := relayMgr.send(m); err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}
