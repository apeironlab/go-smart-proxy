package relay

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// gatewayTTL is how long a gateway certificate lasts.
const gatewayTTL = 365 * 24 * time.Hour

func (a *Admin) handleApps(w http.ResponseWriter, r *http.Request, _ *adminSession) {
	c := a.cat()
	if c == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "apps": []App{}})
		return
	}
	apps := c.Apps()
	if apps == nil {
		apps = []App{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "readOnly": c.ReadOnly(), "apps": apps})
}

func (a *Admin) handleAppsPut(w http.ResponseWriter, r *http.Request, sess *adminSession) {
	c := a.cat()
	if c == nil {
		writeError(w, http.StatusNotFound, "applications are not enabled on this relay")
		return
	}
	var req struct {
		Apps []App `json:"apps"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	old := map[string]bool{}
	for _, x := range c.Apps() {
		old[x.ID] = true
	}
	if err := c.Set(req.Apps); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ids := make([]string, 0, len(req.Apps))
	for _, x := range req.Apps {
		ids = append(ids, x.ID)
	}
	a.Record("admin.app.save", sess.email, "", strings.Join(ids, ", "))
	a.handleApps(w, r, sess)
}

// GatewayInfo describes a gateway for the interface.
type GatewayInfo struct {
	ID      string        `json:"id"`
	Online  bool          `json:"online"`
	Apps    int           `json:"apps"`
	Certs   []GatewayCert `json:"certs"`
	Unknown bool          `json:"unknown,omitempty"` // connected or used by an application, but no certificate was issued here
}

func (a *Admin) handleGateways(w http.ResponseWriter, r *http.Request, _ *adminSession) {
	certs, err := a.db.gatewayCerts()
	if err != nil {
		a.fail(w, err)
		return
	}
	_, serials := a.cfg.Revoked.List()
	revoked := map[string]bool{}
	for _, s := range serials {
		revoked[s] = true
	}
	byID := map[string]*GatewayInfo{}
	get := func(id string) *GatewayInfo {
		g := byID[id]
		if g == nil {
			g = &GatewayInfo{ID: id, Certs: []GatewayCert{}}
			byID[id] = g
		}
		return g
	}
	for _, c := range certs {
		if revoked[c.Serial] {
			c.Revoked = true
		}
		g := get(c.ID)
		g.Certs = append(g.Certs, c)
	}
	if srv := a.srv(); srv != nil {
		for _, id := range srv.OnlineGateways() {
			get(id).Online = true
		}
	}
	if c := a.cat(); c != nil {
		for _, app := range c.Apps() {
			get(app.Gateway).Apps++
		}
	}
	out := []*GatewayInfo{}
	for _, g := range byID {
		out = append(out, g)
	}
	sortGateways(out)
	writeJSON(w, http.StatusOK, out)
}

func (a *Admin) handleGatewayIssue(w http.ResponseWriter, r *http.Request, sess *adminSession) {
	var req struct {
		ID string `json:"id"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	creds, err := NewGatewayCredentials(a.enroll.cfg.CADir, req.ID, gatewayTTL)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.db.recordGateway(GatewayCert{Serial: creds.Serial, ID: req.ID, Issued: time.Now(), Expires: creds.NotAfter}); err != nil {
		a.fail(w, err)
		return
	}
	a.Record("admin.gateway.issue", sess.email, req.ID, creds.Serial)
	noStore(w)
	// The private key is shown once: it is not kept here.
	writeJSON(w, http.StatusOK, map[string]any{
		"id": req.ID, "serial": creds.Serial, "expires": creds.NotAfter,
		"certPem": string(creds.CertPEM), "keyPem": string(creds.KeyPEM), "caPem": string(creds.CAPEM),
	})
}

func (a *Admin) handleGatewayRevoke(w http.ResponseWriter, r *http.Request, sess *adminSession) {
	id := r.PathValue("id")
	if !authIDRe.MatchString(id) {
		writeError(w, http.StatusBadRequest, "invalid gateway id")
		return
	}
	certs, err := a.db.gatewayCerts()
	if err != nil {
		a.fail(w, err)
		return
	}
	n := 0
	for _, c := range certs {
		if c.ID != id || c.Revoked {
			continue
		}
		if err := a.cfg.Revoked.Add("serial:" + c.Serial); err != nil {
			a.fail(w, err)
			return
		}
		a.db.markGateway(c.Serial, sess.email)
		n++
	}
	if srv := a.srv(); srv != nil {
		srv.KickGateway(id)
	}
	a.Record("admin.gateway.revoke", sess.email, id, "certificates: "+itoaInt(n))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "revoked": n})
}

func itoaInt(n int) string { return strconv.Itoa(n) }

func sortGateways(g []*GatewayInfo) {
	sort.Slice(g, func(i, j int) bool { return g[i].ID < g[j].ID })
}
