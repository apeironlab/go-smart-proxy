package relay

import (
	"context"
	"net/http"
	"strings"
	"time"
)

func (a *Admin) handlePolicy(w http.ResponseWriter, r *http.Request, _ *adminSession) {
	p := a.pol()
	if p == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	lists, counts, recent := p.Status()
	if lists == nil {
		lists = []ListStatus{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": true, "readOnly": p.ReadOnly(), "config": p.Config(),
		"lists": lists, "counts": counts, "recent": recent,
	})
}

func (a *Admin) handlePolicyPut(w http.ResponseWriter, r *http.Request, sess *adminSession) {
	p := a.pol()
	if p == nil {
		writeError(w, http.StatusNotFound, "blocking is not enabled on this relay")
		return
	}
	var req struct {
		Config PolicyConfig `json:"config"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if err := p.Set(req.Config); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var names []string
	for _, x := range req.Config.Rules {
		names = append(names, x.ID)
	}
	for _, x := range req.Config.Lists {
		names = append(names, x.ID)
	}
	a.Record("admin.policy.save", sess.email, "", strings.Join(names, ", "))
	a.handlePolicy(w, r, sess)
}

func (a *Admin) handlePolicyRefresh(w http.ResponseWriter, r *http.Request, sess *adminSession) {
	p := a.pol()
	if p == nil {
		writeError(w, http.StatusNotFound, "blocking is not enabled on this relay")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	p.Refresh(ctx)
	a.Record("admin.policy.refresh", sess.email, "", "")
	a.handlePolicy(w, r, sess)
}
