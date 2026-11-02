package main

import (
	"errors"
	"net/http"
	"strconv"

	"proxy/relay"
)

func registerRelayRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/relay", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, relayMgr.Status())
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
