package main

import (
	"context"
	"net/http"
	"sort"
	"strings"

	"github.com/apeironlab/go-smart-proxy/blocklist"
)

type presetJSON struct {
	blockPreset
	Enabled bool `json:"enabled"`
}

type relayRuleJSON struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

// relayBlockJSON tells the user what a relay blocks without saying what:
// how many mandatory rules there are, and the recommended ones in full.
type relayBlockJSON struct {
	Relay       string          `json:"relay"`
	Mandatory   int             `json:"mandatory"`
	Recommended []relayRuleJSON `json:"recommended"`
}

func registerBlockingRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/blocking", apiGetBlocking)
	m.HandleFunc("PUT /api/blocking", apiSaveBlocking)
	m.HandleFunc("POST /api/blocking/refresh", func(w http.ResponseWriter, r *http.Request) {
		go blocker.update(context.Background())
		writeJSON(w, map[string]string{"status": "ok"})
	})
	m.HandleFunc("GET /api/blocking/test", apiTestBlocking)
	m.HandleFunc("GET /api/blocking/stats", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, blocker.stats()) })
	m.HandleFunc("POST /api/blocking/stats/reset", func(w http.ResponseWriter, r *http.Request) {
		blocker.resetStats()
		writeJSON(w, map[string]string{"status": "ok"})
	})
}

func apiGetBlocking(w http.ResponseWriter, r *http.Request) {
	c := blocker.config()
	presets := []presetJSON{}
	for _, p := range blockPresets {
		presets = append(presets, presetJSON{blockPreset: p, Enabled: inList(c.Presets, p.ID)})
	}
	relays := []relayBlockJSON{}
	pols := relayPolicies()
	names := make([]string, 0, len(pols))
	for n := range pols {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		p := pols[n]
		rb := relayBlockJSON{Relay: n, Recommended: []relayRuleJSON{}}
		for _, ru := range p.Rules {
			if ru.Mandatory {
				rb.Mandatory++
			} else {
				rb.Recommended = append(rb.Recommended, relayRuleJSON{ID: ru.ID, Name: ru.Name, Enabled: !inList(c.RelayOff, n+"/"+ru.ID)})
			}
		}
		for _, l := range p.Lists {
			if l.Mandatory {
				rb.Mandatory++
			} else {
				rb.Recommended = append(rb.Recommended, relayRuleJSON{ID: l.ID, Name: l.Name, Enabled: !inList(c.RelayOff, n+"/"+l.ID)})
			}
		}
		if rb.Mandatory > 0 || len(rb.Recommended) > 0 {
			relays = append(relays, rb)
		}
	}
	blocker.mu.Lock()
	status := append([]blockStatus{}, blocker.status...)
	blocker.mu.Unlock()
	if c.Lists == nil {
		c.Lists = []BlockList{}
	}
	if c.Presets == nil {
		c.Presets = []string{}
	}
	if c.Block == nil {
		c.Block = []string{}
	}
	if c.Allow == nil {
		c.Allow = []string{}
	}
	if c.RelayOff == nil {
		c.RelayOff = []string{}
	}
	writeJSON(w, map[string]any{
		"config": c, "presets": presets, "lists": status, "relays": relays,
		"updating": blocker.updating.Load(),
	})
}

func apiSaveBlocking(w http.ResponseWriter, r *http.Request) {
	var c BlockingConfig
	if err := readJSON(r, &c); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := c.Normalize(); err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	configMu.Lock()
	old := configuration.Blocking
	configuration.Blocking = c
	err := persistConfigurationLocked()
	if err != nil {
		configuration.Blocking = old
	}
	configMu.Unlock()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	blocker.setConfig(c)
	blocker.reload()
	go blocker.update(context.Background()) // fetch what was just added
	apiGetBlocking(w, r)
}

func apiTestBlocking(w http.ResponseWriter, r *http.Request) {
	host := blocklist.CleanHost(strings.TrimSpace(r.URL.Query().Get("host")))
	if host == "" {
		writeAPIError(w, http.StatusBadRequest, "host is required")
		return
	}
	d := blocker.check(host)
	out := map[string]any{"host": host, "blocked": d.Blocked, "mandatory": d.Mandatory}
	if d.Blocked {
		if d.Mandatory {
			out["source"] = orgSource // not what the rule is
		} else {
			out["source"], out["rule"] = d.Hit.Source, d.Hit.Rule
		}
	}
	writeJSON(w, out)
}
