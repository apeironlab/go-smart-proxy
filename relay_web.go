package main

import (
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
