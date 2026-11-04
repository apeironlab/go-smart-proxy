package relay

import (
	"database/sql"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// pendingCount is the number of certificate requests waiting for the user.
func (s *EnrollServer) pendingCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	n := 0
	for _, it := range s.items {
		if !it.Admin && !it.Approved && now.Before(it.Expires) {
			n++
		}
	}
	return n
}

func (a *Admin) handleOverview(w http.ResponseWriter, r *http.Request, _ *adminSession) {
	certs, err := a.db.allCerts()
	if err != nil {
		a.fail(w, err)
		return
	}
	_, serials := a.cfg.Revoked.List()
	revokedSerial := map[string]bool{}
	for _, s := range serials {
		revokedSerial[s] = true
	}
	now := time.Now()
	active, revoked, expiring := 0, 0, 0
	for _, c := range certs {
		switch {
		case c.Revoked || revokedSerial[c.Serial]:
			revoked++
		case c.Expires.After(now):
			active++
			if c.Expires.Before(now.Add(14 * 24 * time.Hour)) {
				expiring++
			}
		}
	}
	online := []OnlineDevice{}
	if srv := a.srv(); srv != nil {
		online = srv.Online()
		sort.Slice(online, func(i, j int) bool {
			if online[i].Email != online[j].Email {
				return online[i].Email < online[j].Email
			}
			return online[i].Device < online[j].Device
		})
	}
	appCount, gwOnline := 0, 0
	if c := a.cat(); c != nil {
		appCount = len(c.Apps())
	}
	if srv := a.srv(); srv != nil {
		gwOnline = len(srv.OnlineGateways())
	}
	people := map[string]bool{}
	for _, d := range online {
		people[d.Email] = true
	}
	locals, _ := a.db.listUsers()
	emails, _ := a.cfg.Revoked.List()
	recent, _ := a.db.events(EventFilter{Limit: 12})
	writeJSON(w, http.StatusOK, map[string]any{
		"now":    now,
		"uptime": int64(now.Sub(a.started).Seconds()),
		"counts": map[string]int{
			"devices": len(online), "users": len(people), "certs": active, "revokedCerts": revoked,
			"expiring": expiring, "pending": a.enroll.pendingCount(), "localUsers": len(locals), "revokedUsers": len(emails),
			"apps": appCount, "gateways": gwOnline,
		},
		"online": online,
		"recent": recent,
	})
}

// UserInfo is a person known to the relay.
type UserInfo struct {
	Email    string `json:"email"`
	Certs    int    `json:"certs"`   // valid ones
	Revoked  bool   `json:"revoked"` // the whole identity is refused
	Devices  int    `json:"devices"` // online now
	LastSeen int64  `json:"lastSeen"`
	Local    string `json:"local,omitempty"` // user name in the database
	LastCert int64  `json:"lastCert,omitempty"`
}

func (a *Admin) handleUsers(w http.ResponseWriter, r *http.Request, _ *adminSession) {
	certs, err := a.db.allCerts()
	if err != nil {
		a.fail(w, err)
		return
	}
	locals, err := a.db.listUsers()
	if err != nil {
		a.fail(w, err)
		return
	}
	emails, serials := a.cfg.Revoked.List()
	revokedSerial := map[string]bool{}
	for _, s := range serials {
		revokedSerial[s] = true
	}
	users := map[string]*UserInfo{}
	get := func(e string) *UserInfo {
		u := users[e]
		if u == nil {
			u = &UserInfo{Email: e}
			users[e] = u
		}
		return u
	}
	now := time.Now()
	for _, c := range certs {
		u := get(c.Email)
		if !c.Revoked && !revokedSerial[c.Serial] && c.Expires.After(now) {
			u.Certs++
		}
		if c.Issued.Unix() > u.LastCert {
			u.LastCert = c.Issued.Unix()
		}
	}
	for _, l := range locals {
		get(l.Email).Local = l.Username
	}
	for _, e := range emails {
		get(e).Revoked = true
	}
	if srv := a.srv(); srv != nil {
		for _, d := range srv.Online() {
			get(d.Email).Devices++
		}
		for _, u := range users {
			u.LastSeen = srv.Store.LastSeen(u.Email)
		}
	}
	out := make([]*UserInfo, 0, len(users))
	for _, u := range users {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Email < out[j].Email })
	writeJSON(w, http.StatusOK, out)
}

func (a *Admin) handleCerts(w http.ResponseWriter, r *http.Request, _ *adminSession) {
	email, ok := NormalizeEmail(r.URL.Query().Get("email"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid e-mail address")
		return
	}
	certs, err := a.db.certs(email)
	if err != nil {
		a.fail(w, err)
		return
	}
	_, serials := a.cfg.Revoked.List()
	revoked := map[string]bool{}
	for _, s := range serials {
		revoked[s] = true
	}
	for i := range certs {
		if revoked[certs[i].Serial] {
			certs[i].Revoked = true
		}
	}
	writeJSON(w, http.StatusOK, certs)
}

type revokeReq struct {
	Email  string `json:"email"`
	Serial string `json:"serial"`
}

// revokeTarget resolves the request into the deny-list entry.
func (a *Admin) revokeTarget(req revokeReq) (entry, email, serial string, err error) {
	switch {
	case req.Serial != "":
		serial = strings.ToLower(strings.TrimSpace(req.Serial))
		c, ok, derr := a.db.cert(serial)
		if derr != nil {
			return "", "", "", derr
		}
		if !ok {
			return "", "", "", errors.New("unknown certificate")
		}
		return "serial:" + serial, c.Email, serial, nil
	case req.Email != "":
		e, ok := NormalizeEmail(req.Email)
		if !ok {
			return "", "", "", errors.New("invalid e-mail address")
		}
		return e, e, "", nil
	}
	return "", "", "", errors.New("give an e-mail address or a certificate serial")
}

func (a *Admin) handleRevoke(w http.ResponseWriter, r *http.Request, sess *adminSession) {
	var req revokeReq
	if !readJSON(w, r, &req) {
		return
	}
	entry, email, serial, err := a.revokeTarget(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if email == sess.email && serial == "" {
		writeError(w, http.StatusBadRequest, "you cannot revoke your own identity")
		return
	}
	if err := a.cfg.Revoked.Add(entry); err != nil {
		a.fail(w, err)
		return
	}
	if serial != "" {
		a.db.markCert(serial, true, sess.email)
	}
	kicked := 0
	if srv := a.srv(); srv != nil {
		kicked = srv.Kick(email, serial)
	}
	a.Record("admin.revoke", sess.email, entry, "disconnected: "+strconv.Itoa(kicked))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "disconnected": kicked})
}

func (a *Admin) handleUnrevoke(w http.ResponseWriter, r *http.Request, sess *adminSession) {
	var req revokeReq
	if !readJSON(w, r, &req) {
		return
	}
	entry, _, serial, err := a.revokeTarget(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.cfg.Revoked.Remove(entry); err != nil {
		a.fail(w, err)
		return
	}
	if serial != "" {
		a.db.markCert(serial, false, "")
	}
	a.Record("admin.unrevoke", sess.email, entry, "")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *Admin) handleKick(w http.ResponseWriter, r *http.Request, sess *adminSession) {
	var req struct {
		Email string `json:"email"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	email, ok := NormalizeEmail(req.Email)
	srv := a.srv()
	if !ok || srv == nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	n := srv.Kick(email, "")
	a.Record("admin.kick", sess.email, email, "disconnected: "+strconv.Itoa(n))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "disconnected": n})
}

// ---- local users ------------------------------------------------------

func (a *Admin) localUsersEnabled() bool {
	for _, m := range a.enroll.methods {
		if m.Password != nil && m.Password.Database {
			return true
		}
	}
	return false
}

func (a *Admin) handleLocalUsers(w http.ResponseWriter, r *http.Request, _ *adminSession) {
	users, err := a.db.listUsers()
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": a.localUsersEnabled(), "users": users})
}

type localUserReq struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	Email    string   `json:"email"`
	Groups   []string `json:"groups"`
}

func (a *Admin) handleLocalUserAdd(w http.ResponseWriter, r *http.Request, sess *adminSession) {
	var req localUserReq
	if !readJSON(w, r, &req) {
		return
	}
	if err := a.db.addUser(req.Username, req.Password, req.Email, req.Groups); err != nil {
		if errors.Is(err, errUserExists) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.Record("admin.user.add", sess.email, strings.ToLower(strings.TrimSpace(req.Username)), "groups: "+joinGroups(req.Groups))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *Admin) handleLocalUserEdit(w http.ResponseWriter, r *http.Request, sess *adminSession) {
	var req localUserReq
	if !readJSON(w, r, &req) {
		return
	}
	name := r.PathValue("name")
	if err := a.db.updateUser(name, req.Password, firstNonEmpty(req.Email, name), req.Groups); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	detail := "groups: " + joinGroups(req.Groups)
	if req.Password != "" {
		detail += "; password changed"
	}
	a.Record("admin.user.edit", sess.email, name, detail)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *Admin) handleLocalUserDelete(w http.ResponseWriter, r *http.Request, sess *adminSession) {
	name := strings.ToLower(r.PathValue("name"))
	if err := a.db.deleteUser(name); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		a.fail(w, err)
		return
	}
	a.Record("admin.user.delete", sess.email, name, "")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---- rules ------------------------------------------------------------

type methodRules struct {
	ID       string   `json:"id"`
	Type     string   `json:"type"`
	Label    string   `json:"label"`
	Disabled bool     `json:"disabled"`
	Groups   []string `json:"groups"`
	Default  []string `json:"defaultGroups"`
}

type smtpOut struct {
	Addr    string `json:"addr"`
	User    string `json:"user"`
	From    string `json:"from"`
	TLS     string `json:"tls"`
	Auth    string `json:"auth"`
	HasPass bool   `json:"hasPass"`
}

func (a *Admin) handleRulesGet(w http.ResponseWriter, r *http.Request, _ *adminSession) {
	s := a.enroll
	rules := s.Rules()
	methods := []methodRules{{ID: "email", Type: "email", Label: "E-mail", Disabled: s.emailDisabled(), Groups: []string{}, Default: []string{}}}
	for _, id := range s.methodOrder {
		m := s.methods[id]
		g := s.requiredGroups(m)
		if g == nil {
			g = []string{}
		}
		def := m.requireGroups()
		if def == nil {
			def = []string{}
		}
		methods = append(methods, methodRules{ID: id, Type: m.Type, Label: m.label(), Disabled: s.methodDisabled(id), Groups: g, Default: def})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"allowedDomains": rules.AllowedDomains,
		"certTtlHours":   rules.CertTTLHours,
		"methods":        methods,
		"smtp": smtpOut{Addr: rules.SMTP.Addr, User: rules.SMTP.User, From: rules.SMTP.From, TLS: rules.SMTP.TLS,
			Auth: rules.SMTP.Auth, HasPass: rules.SMTP.Pass != ""},
		"admins": map[string]any{"groups": a.cfg.Groups, "emails": a.cfg.Emails},
	})
}

type rulesReq struct {
	AllowedDomains []string        `json:"allowedDomains"`
	CertTTLHours   int             `json:"certTtlHours"`
	Methods        []methodRulesIn `json:"methods"`
	SMTP           smtpIn          `json:"smtp"`
}

type methodRulesIn struct {
	ID       string   `json:"id"`
	Disabled bool     `json:"disabled"`
	Groups   []string `json:"groups"`
}

type smtpIn struct {
	Addr string  `json:"addr"`
	User string  `json:"user"`
	From string  `json:"from"`
	TLS  string  `json:"tls"`
	Auth string  `json:"auth"`
	Pass *string `json:"pass"` // nil keeps the current password
}

func (a *Admin) handleRulesPut(w http.ResponseWriter, r *http.Request, sess *adminSession) {
	var req rulesReq
	if !readJSON(w, r, &req) {
		return
	}
	s := a.enroll
	old := s.Rules()
	next := EnrollRules{
		AllowedDomains: req.AllowedDomains, CertTTLHours: req.CertTTLHours,
		RequireGroups: map[string][]string{}, DisabledMethods: []string{},
		SMTP: SMTPRules{Addr: strings.TrimSpace(req.SMTP.Addr), User: req.SMTP.User, From: strings.TrimSpace(req.SMTP.From),
			TLS: req.SMTP.TLS, Auth: req.SMTP.Auth, Pass: old.SMTP.Pass},
	}
	if req.SMTP.Pass != nil {
		next.SMTP.Pass = *req.SMTP.Pass
	}
	for _, m := range req.Methods {
		if m.Disabled {
			next.DisabledMethods = append(next.DisabledMethods, m.ID)
		}
		if e := s.methods[m.ID]; e != nil {
			groups := []string{}
			for _, g := range m.Groups {
				if g = strings.TrimSpace(g); g != "" {
					groups = append(groups, g)
				}
			}
			// Store an override only when it differs from the configuration.
			if strings.Join(groups, "\x00") != strings.Join(e.requireGroups(), "\x00") {
				next.RequireGroups[m.ID] = groups
			}
		}
	}
	if err := s.SetRules(next); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var changed []string
	if strings.Join(old.AllowedDomains, ",") != strings.Join(next.AllowedDomains, ",") {
		changed = append(changed, "domains")
	}
	if old.CertTTLHours != next.CertTTLHours {
		changed = append(changed, "certificate lifetime")
	}
	if strings.Join(old.DisabledMethods, ",") != strings.Join(next.DisabledMethods, ",") {
		changed = append(changed, "enabled methods")
	}
	if len(old.RequireGroups) != len(next.RequireGroups) || fmtGroups(old.RequireGroups) != fmtGroups(next.RequireGroups) {
		changed = append(changed, "required groups")
	}
	om, nm := old.SMTP, next.SMTP
	om.Pass, nm.Pass = "", ""
	if om != nm || old.SMTP.Pass != next.SMTP.Pass {
		changed = append(changed, "SMTP")
	}
	a.Record("admin.rules", sess.email, "", strings.Join(changed, ", "))
	a.handleRulesGet(w, r, sess)
}

func fmtGroups(m map[string][]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + "=" + strings.Join(m[k], ",") + ";")
	}
	return b.String()
}

// ---- events -----------------------------------------------------------

func (a *Admin) handleEvents(w http.ResponseWriter, r *http.Request, _ *adminSession) {
	q := r.URL.Query()
	f := EventFilter{Kind: q.Get("kind"), Search: q.Get("q")}
	f.Before, _ = strconv.ParseInt(q.Get("before"), 10, 64)
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	ev, err := a.db.events(f)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ev)
}
