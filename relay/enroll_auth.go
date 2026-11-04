package relay

import (
	"context"
	"errors"
	"fmt"
	"html"
	"log"
	"net/http"
	"strings"
	"time"
)

// methodEntry is a configured sign-in method, ready to use.
type methodEntry struct {
	AuthMethod
	cred    credentialMethod
	browser browserMethod
	saml    *samlMethod
}

// publicBase returns the address users and identity providers reach this
// enrollment endpoint at (no trailing slash).
func publicBase(publicURL string) string {
	u := strings.TrimRight(strings.TrimSpace(publicURL), "/")
	if u == "" {
		return ""
	}
	if !strings.Contains(u, "://") {
		u = "https://" + u
	}
	return u
}

// buildMethods turns the configuration into usable methods.
func (s *EnrollServer) buildMethods() error {
	cfg := s.cfg.Auth
	if cfg == nil {
		return nil
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("enrollment auth: %w", err)
	}
	base := publicBase(s.cfg.PublicURL)
	for _, m := range cfg.Methods {
		e := &methodEntry{AuthMethod: m}
		switch m.Type {
		case "password":
			pm, err := newPasswordMethod(m.Password)
			if err != nil {
				return fmt.Errorf("auth method %q: %w", m.ID, err)
			}
			e.cred = pm
		case "ldap":
			lm, err := newLDAPMethod(m.LDAP)
			if err != nil {
				return fmt.Errorf("auth method %q: %w", m.ID, err)
			}
			e.cred = lm
		case "oidc":
			if base == "" && m.OIDC.RedirectURL == "" {
				return fmt.Errorf("auth method %q: the public enrollment URL (-public-url) or redirect_url is needed", m.ID)
			}
			e.browser = newOIDCMethod(m.ID, m.OIDC, base)
		case "saml":
			if base == "" {
				return fmt.Errorf("auth method %q: the public enrollment URL (-public-url) is needed", m.ID)
			}
			sm := newSAMLMethod(m.ID, m.SAML, base)
			e.browser, e.saml = sm, sm
		}
		s.methods[m.ID] = e
		s.methodOrder = append(s.methodOrder, m.ID)
	}
	if cfg.DisableEmail && len(s.methods) == 0 {
		return errors.New("enrollment auth: the e-mail code is disabled and no other method is configured")
	}
	return nil
}

type methodInfo struct {
	ID    string `json:"id"`
	Type  string `json:"type"` // email, password, ldap, oidc, saml
	Label string `json:"label"`
	// Flow tells the client what to do: "code" (e-mail), "form" (user name and
	// password typed in the proxy) or "browser" (sign in on the provider's page).
	Flow string `json:"flow"`
}

// methodInfos lists how a user can enroll, e-mail code first.
func (s *EnrollServer) methodInfos() []methodInfo {
	out := []methodInfo{}
	if s.cfg.Auth == nil || !s.cfg.Auth.DisableEmail {
		out = append(out, methodInfo{ID: "email", Type: "email", Label: "E-mail", Flow: "code"})
	}
	for _, id := range s.methodOrder {
		m := s.methods[id]
		flow := "form"
		if m.browser != nil {
			flow = "browser"
		}
		out = append(out, methodInfo{ID: id, Type: m.Type, Label: m.label(), Flow: flow})
	}
	return out
}

// authRequired reports whether a request that names no method must be
// answered with the list of methods. A relay with no sign-in methods besides
// the e-mail code keeps answering as it always did.
func (s *EnrollServer) authRequired() bool {
	return s.cfg.Auth != nil && (len(s.methods) > 0 || s.cfg.Auth.DisableEmail)
}

// challengeHeader is the WWW-Authenticate value that announces a method. The
// scheme says what the client must do (GSP-Code, GSP-Form, GSP-Browser); the
// parameters name the method.
func challengeHeader(m methodInfo) string {
	clean := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == '"' || r == '\\' {
			return -1
		}
		return r
	}, m.Label)
	scheme := map[string]string{"code": "GSP-Code", "form": "GSP-Form", "browser": "GSP-Browser"}[m.Flow]
	return fmt.Sprintf(`%s id="%s", type="%s", realm="%s"`, scheme, m.ID, m.Type, clean)
}

// challenge answers 401: authentication is required, and these are the ways to
// provide it. Nothing has been sent or stored. The same list is in the body for
// programs and in WWW-Authenticate headers, as HTTP expects of a 401.
func (s *EnrollServer) challenge(w http.ResponseWriter) {
	infos := s.methodInfos()
	for _, m := range infos {
		w.Header().Add("WWW-Authenticate", challengeHeader(m))
	}
	writeJSON(w, http.StatusUnauthorized, map[string]any{
		"error":   "autenticazione richiesta: scegli uno dei metodi indicati",
		"methods": infos,
	})
}

// checkIdentity applies the rules that hold for every method once it has said
// who the user is: it must be the address the certificate was requested for,
// in an allowed domain, and in the required groups.
func (s *EnrollServer) checkIdentity(m *methodEntry, id Identity, want string) error {
	email, ok := NormalizeEmail(id.Email)
	if !ok {
		return fmt.Errorf("the identity has no valid e-mail address (%q)", id.Email)
	}
	if email != want {
		return fmt.Errorf("signed in as %s, but the certificate was requested for %s", email, want)
	}
	if !allowedDomain(email, s.cfg.AllowedDomains) {
		return fmt.Errorf("%s: domain not allowed", email)
	}
	if !groupMatches(id.Groups, m.requireGroups()) {
		return fmt.Errorf("%s is not in any of the required groups", email)
	}
	return nil
}

// issue signs the certificate for an authenticated user.
func (s *EnrollServer) issue(it *Enrollment) (string, error) {
	ttl := s.cfg.CertTTL
	if ttl <= 0 {
		ttl = 90 * 24 * time.Hour
	}
	signed, err := SignCSR(s.cfg.CADir, []byte(it.CSRPEM), it.Email, ttl)
	if err != nil {
		return "", err
	}
	return string(signed), nil
}

func (s *EnrollServer) method(w http.ResponseWriter, r *http.Request) (*methodEntry, bool) {
	m := s.methods[r.PathValue("method")]
	if m == nil {
		writeError(w, http.StatusNotFound, "metodo non trovato")
		return nil, false
	}
	return m, true
}

// handleLogin enrolls a user who typed a user name and password in the form
// of the proxy (methods password and ldap). The certificate is returned at
// once: there is nothing to wait for.
func (s *EnrollServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	m, ok := s.method(w, r)
	if !ok {
		return
	}
	if m.cred == nil {
		writeError(w, http.StatusBadRequest, "questo metodo si usa nel browser")
		return
	}
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	pr, ok := s.parseEnrollRequest(w, r, &creds)
	if !ok {
		return
	}
	// Guessing is slowed per account and per address, whatever the answer.
	user := strings.ToLower(strings.TrimSpace(creds.Username))
	if !s.allow("login:"+m.ID+":"+user, 10) || !s.allow("ip:"+s.clientIP(r), 30) {
		writeError(w, http.StatusTooManyRequests, "troppi tentativi, riprova tra qualche minuto")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), authTimeout+5*time.Second)
	defer cancel()
	id, err := m.cred.Authenticate(ctx, creds.Username, creds.Password)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			s.log.Printf("enrollment: %s: failed sign-in of %q for %s from %s", m.ID, user, pr.email, s.clientIP(r))
			w.Header().Add("WWW-Authenticate", challengeHeader(methodInfo{ID: m.ID, Type: m.Type, Label: m.label(), Flow: "form"}))
			writeError(w, http.StatusUnauthorized, "utente o password non validi")
			return
		}
		s.log.Printf("enrollment: %s: %v", m.ID, err)
		writeError(w, http.StatusBadGateway, "autenticazione non disponibile, riprova più tardi")
		return
	}
	if err := s.checkIdentity(m, id, pr.email); err != nil {
		s.log.Printf("enrollment: %s: %q refused: %v", m.ID, user, err)
		writeError(w, http.StatusForbidden, "accesso non consentito")
		return
	}
	it := &Enrollment{Email: pr.email, Device: pr.device, CSRPEM: pr.csr, Method: m.ID}
	cert, err := s.issue(it)
	if err != nil {
		s.log.Printf("enrollment signing for %s failed: %v", pr.email, err)
		writeError(w, http.StatusInternalServerError, "firma del certificato non riuscita")
		return
	}
	s.mu.Lock()
	s.users[pr.email] = true
	s.saveLocked()
	s.mu.Unlock()
	s.log.Printf("enrollment: %s: certificate issued to %s", m.ID, pr.email)
	writeJSON(w, http.StatusOK, map[string]any{
		"certPem":      cert,
		"relayAddress": s.cfg.PublicRelay,
		"relayCAPEM":   s.cfg.RelayCAPEM,
	})
}

// handleBrowserStart begins a sign-in on the identity provider's page (OpenID
// Connect, SAML) and returns the address to open. The client then polls
// GET /enroll/{id}, as with the e-mail code, until the certificate is ready.
func (s *EnrollServer) handleBrowserStart(w http.ResponseWriter, r *http.Request) {
	m, ok := s.method(w, r)
	if !ok {
		return
	}
	if m.browser == nil {
		writeError(w, http.StatusBadRequest, "questo metodo usa un modulo nel proxy")
		return
	}
	pr, ok := s.parseEnrollRequest(w, r, nil)
	if !ok {
		return
	}
	if !s.allow("email:"+pr.email, 6) || !s.allow("ip:"+s.clientIP(r), 20) {
		writeError(w, http.StatusTooManyRequests, "troppe richieste, riprova tra qualche minuto")
		return
	}
	pollToken := randomToken(32)
	now := time.Now()
	it := &Enrollment{
		ID: randomToken(12), Email: pr.email, Device: pr.device, CSRPEM: pr.csr, Method: m.ID,
		PollHash: hashToken(pollToken), Created: now, Expires: now.Add(enrollTTL),
		State: randomToken(24),
	}
	ctx, cancel := context.WithTimeout(r.Context(), authTimeout+5*time.Second)
	defer cancel()
	authURL, err := m.browser.Begin(ctx, it)
	if err != nil {
		s.log.Printf("enrollment: %s: cannot start the sign-in: %v", m.ID, err)
		writeError(w, http.StatusBadGateway, "il provider di identità non risponde, riprova più tardi")
		return
	}
	s.mu.Lock()
	s.items[it.ID] = it
	s.byState[it.State] = it.ID
	s.saveLocked()
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"id":           it.ID,
		"pollToken":    pollToken,
		"authUrl":      authURL,
		"expiresAt":    it.Expires,
		"relayAddress": s.cfg.PublicRelay,
		"relayCAPEM":   s.cfg.RelayCAPEM,
	})
}

// handleCallback is where an OpenID Connect provider sends the user back.
func (s *EnrollServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	m, ok := s.method(w, r)
	if !ok {
		return
	}
	s.finishBrowser(w, r, m, r.URL.Query().Get("state"))
}

// handleACS is where a SAML identity provider posts the assertion.
func (s *EnrollServer) handleACS(w http.ResponseWriter, r *http.Request) {
	m, ok := s.method(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		resultPage(w, false)
		return
	}
	s.finishBrowser(w, r, m, r.PostForm.Get("RelayState"))
}

// finishBrowser completes a browser sign-in. A state is good for one return
// only, so a replayed or forged callback finds nothing.
func (s *EnrollServer) finishBrowser(w http.ResponseWriter, r *http.Request, m *methodEntry, state string) {
	s.mu.Lock()
	id, known := s.byState[state]
	delete(s.byState, state)
	it := s.items[id]
	s.mu.Unlock()
	if state == "" || !known || it == nil || it.Method != m.ID || it.Approved || time.Now().After(it.Expires) {
		s.log.Printf("enrollment: %s: callback with an unknown or expired state", m.ID)
		resultPage(w, false)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), authTimeout+5*time.Second)
	defer cancel()
	ident, err := m.browser.Complete(ctx, r, it)
	if err == nil {
		err = s.checkIdentity(m, ident, it.Email)
	}
	if err != nil {
		s.log.Printf("enrollment: %s: sign-in of %s refused: %v", m.ID, it.Email, err)
		resultPage(w, false)
		return
	}
	cert, err := s.issue(it)
	if err != nil {
		s.log.Printf("enrollment signing for %s failed: %v", it.Email, err)
		resultPage(w, false)
		return
	}
	s.mu.Lock()
	it.Approved = true
	it.CertPEM = cert
	s.users[it.Email] = true
	s.saveLocked()
	s.mu.Unlock()
	s.log.Printf("enrollment: %s: certificate issued to %s", m.ID, it.Email)
	resultPage(w, true)
}

// handleSAMLMetadata serves the service provider metadata for the identity
// provider's administrator.
func (s *EnrollServer) handleSAMLMetadata(w http.ResponseWriter, r *http.Request) {
	m, ok := s.method(w, r)
	if !ok {
		return
	}
	if m.saml == nil {
		writeError(w, http.StatusNotFound, "metodo non trovato")
		return
	}
	b, err := m.saml.Metadata(r.Context())
	if err != nil {
		log.Printf("enrollment: %s: metadata: %v", m.ID, err)
		writeError(w, http.StatusBadGateway, "metadata non disponibili")
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Write(b)
}

// resultPage is what the user sees in the browser after signing in. It says
// nothing about why a sign-in failed: the details are in the relay's log.
func resultPage(w http.ResponseWriter, ok bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	title, text := "Accesso completato · Signed in", "Puoi chiudere questa finestra e tornare al proxy.<br>You can close this window and go back to the proxy."
	status := http.StatusOK
	if !ok {
		title, text = "Accesso non riuscito · Sign-in failed", "Torna al proxy e riprova. Se il problema continua, contatta l'amministratore.<br>Go back to the proxy and try again. If it keeps failing, contact the administrator."
		status = http.StatusForbidden
	}
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>%s</title>
<body style="font-family:system-ui,sans-serif;max-width:32rem;margin:15vh auto;padding:0 1.5rem;line-height:1.5"><h1 style="font-size:1.4rem">%s</h1><p>%s</p></body>`,
		html.EscapeString(title), html.EscapeString(title), text)
}
