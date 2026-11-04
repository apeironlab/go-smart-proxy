package relay

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// AdminConfig enables the management interface of the relay.
//
// It is optional. Without it the relay works from its files only, as before.
// With it, the relay serves a web interface under /admin/ (on the enrollment
// listener) and keeps in a SQLite database the local password users, the
// certificates it issues, an audit log and the enrollment rules edited from
// the interface.
//
// Administrators sign in with the methods of the enrollment (password, LDAP,
// OpenID Connect, SAML), and must be listed in Emails or belong to one of
// Groups. The e-mail code is not accepted: it only proves an address.
type AdminConfig struct {
	// DBPath is the SQLite database (created private if missing).
	DBPath string
	// Shared, when set, is the database several relays use (OpenShared); the
	// interface then keeps its sessions and settings there too, and DBPath is
	// not used.
	Shared *Shared
	// Groups are the groups whose members are administrators; Emails are
	// administrators by address. At least one of the two is required.
	Groups []string
	Emails []string
	// Methods limits which sign-in methods (by id) may be used to sign in to
	// the interface. Empty means every configured method.
	Methods []string
	// Revoked is the deny list the interface edits; it must be the same one
	// the relay Server consults.
	Revoked *Revocations
	// SessionTTL is how long a sign-in lasts (default 8 hours); a session
	// idle for 30 minutes ends sooner.
	SessionTTL time.Duration
	Logger     *log.Logger
}

const (
	adminIdleTTL    = 30 * time.Minute
	adminLoginTTL   = 10 * time.Minute
	adminCookie     = "gsp_admin"
	adminLoginCook  = "gsp_admin_login"
	adminMaxSession = 64
)

// Admin is the management interface.
type Admin struct {
	cfg AdminConfig
	db  *adminDB
	log *log.Logger

	mu       sync.Mutex
	enroll   *EnrollServer
	server   *Server
	catalog  *Catalog
	policy   *Policy
	sessions map[string]*adminSession // by hash of the cookie
	sh       *Shared                  // sessions are kept there when set
	started  time.Time
	events   int
}

type adminSession struct {
	email   string
	method  string
	csrf    string
	created time.Time
	last    time.Time
}

// NewAdmin opens the database and prepares the interface. Pass it to
// EnrollConfig.Admin, and call SetServer with the relay Server.
func NewAdmin(cfg AdminConfig) (*Admin, error) {
	if len(cfg.Groups) == 0 && len(cfg.Emails) == 0 {
		return nil, errors.New("admin: set admin groups or admin e-mail addresses, or nobody could sign in")
	}
	for _, e := range cfg.Emails {
		if _, ok := NormalizeEmail(e); !ok {
			return nil, fmt.Errorf("admin: invalid administrator address %q", e)
		}
	}
	if !cfg.Revoked.Enabled() {
		return nil, errors.New("admin: a revocation file is required (the interface edits it)")
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 8 * time.Hour
	}
	var db *adminDB
	if cfg.Shared != nil {
		db = cfg.Shared.admin
	} else {
		var err error
		if db, err = openAdminDB(cfg.DBPath); err != nil {
			return nil, fmt.Errorf("admin: %w", err)
		}
	}
	a := &Admin{cfg: cfg, db: db, sh: cfg.Shared, log: cfg.Logger, sessions: map[string]*adminSession{}, started: time.Now()}
	if a.log == nil {
		a.log = log.Default()
	}
	return a, nil
}

// Ping checks that the database answers.
func (a *Admin) Ping() error { return a.db.db.Ping() }

// Close closes the database.
func (a *Admin) Close() error {
	if a.sh != nil {
		return nil // the shared database belongs to whoever opened it
	}
	return a.db.Close()
}

// SetServer connects the interface to the relay: it shows who is online, can
// disconnect users, and receives the connection events.
func (a *Admin) SetServer(s *Server) {
	a.mu.Lock()
	a.server = s
	a.mu.Unlock()
	s.SetAudit(a.store)
	s.OnSharedChange(a.syncSettings) // what another relay saved (shared database only)
}

const appsSetting = "apps"

// SetCatalog makes the interface the owner of the catalog: applications are
// edited here and kept in the database. A catalog read from a file stays
// read-only (and is only shown).
func (a *Admin) SetCatalog(c *Catalog) error {
	a.mu.Lock()
	a.catalog = c
	a.mu.Unlock()
	if c.ReadOnly() {
		return nil
	}
	var apps []App
	if _, err := a.db.getSetting(appsSetting, &apps); err != nil {
		return err
	}
	c.mu.Lock()
	c.persist = func(apps []App) error { return a.db.setSetting(appsSetting, apps) }
	c.mu.Unlock()
	if len(apps) > 0 {
		return c.Set(apps)
	}
	return nil
}

// syncSettings applies the settings another relay sharing the database saved.
func (a *Admin) syncSettings() {
	if c := a.cat(); c != nil && !c.ReadOnly() {
		var apps []App
		if ok, _ := a.db.getSetting(appsSetting, &apps); ok {
			c.applyStored(apps)
		}
	}
	if p := a.pol(); p != nil && !p.ReadOnly() {
		var cfg PolicyConfig
		if ok, _ := a.db.getSetting(policySetting, &cfg); ok {
			p.applyStored(cfg)
		}
	}
	a.mu.Lock()
	es := a.enroll
	a.mu.Unlock()
	if es != nil {
		es.applyStoredRules()
	}
}

const policySetting = "policy"

// SetPolicy makes the interface the owner of the blocking policy, kept in its
// database. A policy read from a file stays read-only.
func (a *Admin) SetPolicy(p *Policy) error {
	a.mu.Lock()
	a.policy = p
	a.mu.Unlock()
	if p.ReadOnly() {
		return nil
	}
	var cfg PolicyConfig
	if _, err := a.db.getSetting(policySetting, &cfg); err != nil {
		return err
	}
	p.mu.Lock()
	p.persist = func(c PolicyConfig) error { return a.db.setSetting(policySetting, c) }
	p.mu.Unlock()
	if len(cfg.Rules)+len(cfg.Lists) > 0 || len(cfg.Allow) > 0 {
		return p.Set(cfg)
	}
	return nil
}

func (a *Admin) pol() *Policy {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.policy
}

func (a *Admin) cat() *Catalog {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.catalog
}

func (a *Admin) srv() *Server {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.server
}

// AddLocalUser creates (or, with a new password, replaces) a user of the
// password methods that use the database. It is how the first administrator is
// created when no external identity provider is used.
func (a *Admin) AddLocalUser(username, password, email string, groups ...string) error {
	if err := a.db.addUser(username, password, email, groups); err != nil {
		if errors.Is(err, errUserExists) {
			return a.db.updateUser(username, password, firstNonEmpty(email, username), groups)
		}
		return err
	}
	return nil
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// Record adds an entry to the audit log.
func (a *Admin) Record(kind, actor, subject, detail string) {
	emitEvent(kind, actor, subject, detail)
	a.store(kind, actor, subject, detail)
}

// store writes an event to the audit log without announcing it again (the
// caller already did).
func (a *Admin) store(kind, actor, subject, detail string) {
	if err := a.db.addEvent(kind, actor, subject, detail); err != nil {
		a.log.Printf("admin: audit log: %v", err)
		return
	}
	a.mu.Lock()
	a.events++
	prune := a.events%500 == 0
	a.mu.Unlock()
	if prune {
		a.db.pruneEvents()
	}
}

func (a *Admin) attach(s *EnrollServer) {
	a.mu.Lock()
	a.enroll = s
	a.mu.Unlock()
	if s.cfg.Revoked == nil {
		s.cfg.Revoked = a.cfg.Revoked // one list: what the interface edits is what users revoke into
	}
}

// loginMethods lists the methods that can be used to sign in to the interface.
func (a *Admin) loginMethods() []methodInfo {
	allowed := map[string]bool{}
	for _, id := range a.cfg.Methods {
		allowed[id] = true
	}
	out := []methodInfo{}
	for _, id := range a.enroll.methodOrder {
		if len(allowed) > 0 && !allowed[id] {
			continue
		}
		m := a.enroll.methods[id]
		flow := "form"
		if m.browser != nil {
			flow = "browser"
		}
		out = append(out, methodInfo{ID: id, Type: m.Type, Label: m.label(), Flow: flow})
	}
	return out
}

func (a *Admin) isAdmin(id Identity) bool {
	email, ok := NormalizeEmail(id.Email)
	if !ok {
		return false
	}
	for _, e := range a.cfg.Emails {
		if n, _ := NormalizeEmail(e); n == email {
			return true
		}
	}
	return len(a.cfg.Groups) > 0 && groupMatches(id.Groups, a.cfg.Groups)
}

// ---- HTTP -------------------------------------------------------------

func (a *Admin) mount(m *http.ServeMux) {
	m.HandleFunc("GET /admin/api/session", a.handleSession)
	m.HandleFunc("POST /admin/api/login/{method}", a.handleLogin)
	m.HandleFunc("POST /admin/api/login/{method}/start", a.handleLoginStart)
	m.HandleFunc("POST /admin/api/logout", a.protect(a.handleLogout))

	m.HandleFunc("GET /admin/api/overview", a.protect(a.handleOverview))
	m.HandleFunc("GET /admin/api/users", a.protect(a.handleUsers))
	m.HandleFunc("GET /admin/api/certs", a.protect(a.handleCerts))
	m.HandleFunc("GET /admin/api/devices", a.protect(a.handleDevices))
	m.HandleFunc("POST /admin/api/revoke-device", a.protect(a.handleRevokeDevice))
	m.HandleFunc("POST /admin/api/invite", a.protect(a.handleInvite))
	m.HandleFunc("POST /admin/api/revoke", a.protect(a.handleRevoke))
	m.HandleFunc("POST /admin/api/unrevoke", a.protect(a.handleUnrevoke))
	m.HandleFunc("POST /admin/api/kick", a.protect(a.handleKick))

	m.HandleFunc("GET /admin/api/local-users", a.protect(a.handleLocalUsers))
	m.HandleFunc("POST /admin/api/local-users", a.protect(a.handleLocalUserAdd))
	m.HandleFunc("PUT /admin/api/local-users/{name}", a.protect(a.handleLocalUserEdit))
	m.HandleFunc("DELETE /admin/api/local-users/{name}", a.protect(a.handleLocalUserDelete))

	m.HandleFunc("GET /admin/api/apps", a.protect(a.handleApps))
	m.HandleFunc("PUT /admin/api/apps", a.protect(a.handleAppsPut))
	m.HandleFunc("GET /admin/api/policy", a.protect(a.handlePolicy))
	m.HandleFunc("PUT /admin/api/policy", a.protect(a.handlePolicyPut))
	m.HandleFunc("POST /admin/api/policy/refresh", a.protect(a.handlePolicyRefresh))
	m.HandleFunc("GET /admin/api/gateways", a.protect(a.handleGateways))
	m.HandleFunc("POST /admin/api/gateways", a.protect(a.handleGatewayIssue))
	m.HandleFunc("POST /admin/api/gateways/{id}/revoke", a.protect(a.handleGatewayRevoke))

	m.HandleFunc("GET /admin/api/rules", a.protect(a.handleRulesGet))
	m.HandleFunc("PUT /admin/api/rules", a.protect(a.handleRulesPut))
	m.HandleFunc("GET /admin/api/events", a.protect(a.handleEvents))

	m.Handle("GET /admin/", adminUI())
	m.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/", http.StatusMovedPermanently)
	})
}

func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func (a *Admin) secure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return a.enroll.cfg.TrustForwardedFor && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// sameOrigin refuses requests made by a page of another site. The cookie is
// SameSite=Strict already; this is the second lock.
func sameOrigin(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "none":
	default:
		return false
	}
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		if err != nil || !strings.EqualFold(u.Host, r.Host) {
			return false
		}
	}
	return true
}

type adminHandler func(w http.ResponseWriter, r *http.Request, sess *adminSession)

// protect lets a request through only when it comes with a valid session, and,
// for anything that changes state, the CSRF token and a JSON content type.
func (a *Admin) protect(h adminHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		noStore(w)
		if !sameOrigin(r) {
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}
		sess := a.session(r)
		if sess == nil {
			writeError(w, http.StatusUnauthorized, "sign in required")
			return
		}
		if r.Method != http.MethodGet {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(sess.csrf)) != 1 {
				writeError(w, http.StatusForbidden, "invalid CSRF token")
				return
			}
			if ct := r.Header.Get("Content-Type"); r.ContentLength != 0 && !strings.HasPrefix(ct, "application/json") {
				writeError(w, http.StatusUnsupportedMediaType, "JSON expected")
				return
			}
		}
		h(w, r, sess)
	}
}

func (a *Admin) session(r *http.Request) *adminSession {
	c, err := r.Cookie(adminCookie)
	if err != nil || c.Value == "" {
		return nil
	}
	key := hashToken(c.Value)
	now := time.Now()
	if a.sh != nil {
		return a.sharedSession(key, now)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sweepLocked(now)
	s := a.sessions[key]
	if s == nil {
		return nil
	}
	s.last = now
	return s
}

func (a *Admin) sweepLocked(now time.Time) {
	for k, s := range a.sessions {
		if now.Sub(s.created) > a.cfg.SessionTTL || now.Sub(s.last) > adminIdleTTL {
			delete(a.sessions, k)
		}
	}
}

func (a *Admin) startSession(w http.ResponseWriter, r *http.Request, email, method string) {
	token := randomToken(32)
	now := time.Now()
	if a.sh != nil {
		a.startSharedSession(hashToken(token), email, method, now)
	} else {
		a.startLocalSession(hashToken(token), email, method, now)
	}
	http.SetCookie(w, &http.Cookie{
		Name: adminCookie, Value: token, Path: "/admin", HttpOnly: true,
		Secure: a.secure(r), SameSite: http.SameSiteStrictMode, MaxAge: int(a.cfg.SessionTTL / time.Second),
	})
	a.Record("admin.login", email, method, a.enroll.clientIP(r))
}

func (a *Admin) startLocalSession(key, email, method string, now time.Time) {
	a.mu.Lock()
	a.sweepLocked(now)
	if len(a.sessions) >= adminMaxSession { // drop the oldest
		var oldK string
		var oldT time.Time
		for k, s := range a.sessions {
			if oldK == "" || s.last.Before(oldT) {
				oldK, oldT = k, s.last
			}
		}
		delete(a.sessions, oldK)
	}
	a.sessions[key] = &adminSession{email: email, method: method, csrf: randomToken(24), created: now, last: now}
	a.mu.Unlock()
}

func (a *Admin) handleSession(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	out := map[string]any{"authenticated": false, "methods": a.loginMethods()}
	if s := a.session(r); s != nil {
		out["authenticated"] = true
		out["email"] = s.email
		out["csrf"] = s.csrf
		out["expires"] = s.created.Add(a.cfg.SessionTTL)
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *Admin) loginMethod(w http.ResponseWriter, r *http.Request) (*methodEntry, bool) {
	id := r.PathValue("method")
	for _, mi := range a.loginMethods() {
		if mi.ID == id {
			return a.enroll.methods[id], true
		}
	}
	writeError(w, http.StatusNotFound, "method not found")
	return nil, false
}

func (a *Admin) handleLogin(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	m, ok := a.loginMethod(w, r)
	if !ok {
		return
	}
	if m.cred == nil {
		writeError(w, http.StatusBadRequest, "this method signs in on the provider's page")
		return
	}
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&creds); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	ip := a.enroll.clientIP(r)
	user := strings.ToLower(strings.TrimSpace(creds.Username))
	if !a.enroll.allow("adminlogin:"+m.ID+":"+user, 8) || !a.enroll.allow("adminip:"+ip, 30) {
		writeError(w, http.StatusTooManyRequests, "too many attempts, try again in a few minutes")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), authTimeout+5*time.Second)
	defer cancel()
	id, err := m.cred.Authenticate(ctx, creds.Username, creds.Password)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			a.Record("admin.denied", user, m.ID, "wrong credentials from "+ip)
			writeError(w, http.StatusUnauthorized, "wrong user name or password")
			return
		}
		a.log.Printf("admin: %s: %v", m.ID, err)
		writeError(w, http.StatusBadGateway, "sign-in is not available, try again later")
		return
	}
	if !a.isAdmin(id) {
		a.Record("admin.denied", id.Email, m.ID, "not an administrator, from "+ip)
		writeError(w, http.StatusForbidden, "this account is not an administrator")
		return
	}
	email, _ := NormalizeEmail(id.Email)
	a.startSession(w, r, email, m.ID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleLoginStart begins a sign-in on the identity provider's page. The
// browser that asks receives a cookie, and only that browser can complete the
// sign-in: a link sent to somebody else leads nowhere.
func (a *Admin) handleLoginStart(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	m, ok := a.loginMethod(w, r)
	if !ok {
		return
	}
	if m.browser == nil {
		writeError(w, http.StatusBadRequest, "this method uses a form")
		return
	}
	ip := a.enroll.clientIP(r)
	if !a.enroll.allow("adminip:"+ip, 30) {
		writeError(w, http.StatusTooManyRequests, "too many attempts, try again in a few minutes")
		return
	}
	nonce := randomToken(24)
	now := time.Now()
	it := &Enrollment{
		ID: randomToken(12), Admin: true, Method: m.ID, Created: now, Expires: now.Add(adminLoginTTL),
		State: randomToken(24), LoginHash: hashToken(nonce), ClientAddr: ip,
	}
	ctx, cancel := context.WithTimeout(r.Context(), authTimeout+5*time.Second)
	defer cancel()
	authURL, err := m.browser.Begin(ctx, it)
	if err != nil {
		a.log.Printf("admin: %s: cannot start the sign-in: %v", m.ID, err)
		writeError(w, http.StatusBadGateway, "the identity provider does not answer, try again later")
		return
	}
	s := a.enroll
	s.mu.Lock()
	s.itemAddLocked(it)
	s.mu.Unlock()
	// Lax, not Strict: the browser comes back from the identity provider.
	http.SetCookie(w, &http.Cookie{
		Name: adminLoginCook, Value: nonce, Path: "/enroll-auth", HttpOnly: true,
		Secure: a.secure(r), SameSite: http.SameSiteLaxMode, MaxAge: int(adminLoginTTL / time.Second),
	})
	writeJSON(w, http.StatusOK, map[string]any{"authUrl": authURL})
}

// finishLogin completes a browser sign-in for the interface.
func (a *Admin) finishLogin(w http.ResponseWriter, r *http.Request, m *methodEntry, it *Enrollment, id Identity) {
	s := a.enroll
	s.mu.Lock()
	s.itemDropLocked(it.ID)
	s.mu.Unlock()
	c, err := r.Cookie(adminLoginCook)
	if err != nil || !subtleEqual(hashToken(c.Value), it.LoginHash) {
		a.Record("admin.denied", id.Email, m.ID, "sign-in completed in a different browser than the one that started it")
		adminResultPage(w, false)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: adminLoginCook, Value: "", Path: "/enroll-auth", MaxAge: -1, HttpOnly: true, Secure: a.secure(r)})
	if !a.isAdmin(id) {
		a.Record("admin.denied", id.Email, m.ID, "not an administrator")
		adminResultPage(w, false)
		return
	}
	email, _ := NormalizeEmail(id.Email)
	a.startSession(w, r, email, m.ID)
	noStore(w)
	http.Redirect(w, r, "/admin/", http.StatusSeeOther)
}

func adminResultPage(w http.ResponseWriter, ok bool) {
	noStore(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>%s</title>
<body style="font-family:system-ui,sans-serif;max-width:32rem;margin:15vh auto;padding:0 1.5rem;line-height:1.5"><h1 style="font-size:1.4rem">%s</h1>
<p>Accesso non consentito. <a href="/admin/">Riprova</a>.<br>Access denied. <a href="/admin/">Try again</a>.</p></body>`,
		html.EscapeString("Accesso negato · Access denied"), html.EscapeString("Accesso negato · Access denied"))
	_ = ok
}

func (a *Admin) handleLogout(w http.ResponseWriter, r *http.Request, sess *adminSession) {
	if c, err := r.Cookie(adminCookie); err == nil {
		a.mu.Lock()
		delete(a.sessions, hashToken(c.Value))
		if a.sh != nil {
			a.sh.db.Exec(`DELETE FROM admin_sessions WHERE hash = ?`, hashToken(c.Value))
		}
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: adminCookie, Value: "", Path: "/admin", MaxAge: -1, HttpOnly: true, Secure: a.secure(r)})
	a.Record("admin.logout", sess.email, "", "")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---- helpers ----------------------------------------------------------

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid request")
		return false
	}
	return true
}

func (a *Admin) fail(w http.ResponseWriter, err error) {
	a.log.Printf("admin: %v", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

// AddUserToAdminDB creates (or updates) a local password user in the database
// of the management interface without starting the relay: how the first
// administrator is created from the command line.
func AddUserToAdminDB(dbPath, username, password, email string, groups ...string) error {
	db, err := openAdminDB(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.addUser(username, password, email, groups); err != nil {
		if errors.Is(err, errUserExists) {
			return db.updateUser(username, password, firstNonEmpty(email, username), groups)
		}
		return err
	}
	return nil
}
