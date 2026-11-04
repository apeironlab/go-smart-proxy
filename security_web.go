package main

import (
	"errors"
	"net/http"
	"sync"
	"time"
)

// The Security section of the configuration: change the master password and
// manage the recovery key. Both ask for the current password (the local API has
// no other proof that the person at the keyboard is the owner), and failures
// are rate-limited.

var pwTries struct {
	mu    sync.Mutex
	times []time.Time
}

// pwAllowed says whether another password attempt is allowed now.
func pwAllowed() bool {
	pwTries.mu.Lock()
	defer pwTries.mu.Unlock()
	cut := time.Now().Add(-time.Minute)
	kept := pwTries.times[:0]
	for _, t := range pwTries.times {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	pwTries.times = kept
	return len(kept) < 5
}

func pwFailed() {
	pwTries.mu.Lock()
	pwTries.times = append(pwTries.times, time.Now())
	pwTries.mu.Unlock()
}

// authorizeSecurity checks the master password for an operation on the
// secrets, unless the session was unlocked with the recovery key.
func authorizeSecurity(w http.ResponseWriter, password string) bool {
	if isRecoveredSession() {
		return true
	}
	if !pwAllowed() {
		writeAPIError(w, http.StatusTooManyRequests, "too many attempts: wait a minute")
		return false
	}
	if !verifyMasterPassword(password) {
		pwFailed()
		writeAPIError(w, http.StatusForbidden, errWrongPassword.Error())
		return false
	}
	return true
}

func registerSecurityRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/security", func(w http.ResponseWriter, r *http.Request) {
		enabled, created := recoveryInfo()
		out := map[string]any{"recoveryEnabled": enabled, "recovered": isRecoveredSession(), "keychain": keychainEnabled()}
		if enabled {
			out["recoveryCreated"] = created
		}
		writeJSON(w, out)
	})
	m.HandleFunc("POST /api/security/password", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Old string `json:"old"`
			New string `json:"new"`
		}
		if err := readJSON(r, &body); err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid body")
			return
		}
		if !authorizeSecurity(w, body.Old) {
			return
		}
		if err := changeMasterPassword(body.Old, body.New); err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, errPasswordTooShort) {
				status = http.StatusBadRequest
			}
			writeAPIError(w, status, err.Error())
			return
		}
		writeJSON(w, map[string]string{"status": "ok"})
	})
	m.HandleFunc("POST /api/security/recovery", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Password string `json:"password"`
		}
		if err := readJSON(r, &body); err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid body")
			return
		}
		if !authorizeSecurity(w, body.Password) {
			return
		}
		key, err := createRecoveryKey()
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, map[string]string{"key": key})
	})
	m.HandleFunc("POST /api/security/recovery/remove", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Password string `json:"password"`
		}
		if err := readJSON(r, &body); err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid body")
			return
		}
		if !authorizeSecurity(w, body.Password) {
			return
		}
		if err := removeRecoveryKey(); err != nil {
			writeAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, map[string]string{"status": "ok"})
	})
}
