package relay

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	enrollTTL        = 15 * time.Minute
	enrollMaxTries   = 5
	enrollCodeLen    = 8
	enrollRateWindow = 10 * time.Minute
)

// EnrollConfig configures the HTTPS enrollment endpoint.
type EnrollConfig struct {
	CADir       string
	PublicRelay string // host:port clients use for mTLS
	PublicURL   string // enrollment URL shown in emails
	DownloadURL string
	// RelayCAPEM is the CA that signs the mTLS relay server certificate. It is
	// returned to the client: the certificate used to protect the enrollment
	// HTTPS endpoint may be different (e.g. an intranet wildcard).
	RelayCAPEM     string
	AllowedDomains []string
	SMTPAddr       string
	SMTPUser       string
	SMTPPass       string
	SMTPFrom       string
	SMTPTLS        string // starttls (default), tls, none
	SMTPAuth       string // auto (default), plain, login, none
	StatePath      string
	CertTTL        time.Duration
	// TrustForwardedFor makes the rate limiter use the last X-Forwarded-For
	// entry (the one appended by a trusted reverse proxy) as the client IP.
	// Leave it off unless the endpoint is only reachable through that proxy.
	TrustForwardedFor bool
	// Auth adds sign-in methods (password, LDAP, OpenID Connect, SAML) to the
	// e-mail code. nil offers only the e-mail code.
	Auth *AuthConfig
	// Admin, when set, mounts the management interface under /admin/, keeps
	// the audit log and the issued certificates in its database, and lets the
	// rules be edited from there. nil leaves the relay exactly as configured
	// by files.
	Admin *Admin
	// Store, when set, remembers the groups each identity provider reports at
	// sign-in, which applications with group access use. Pass the Store of the
	// relay Server.
	Store *Store
	// Shared, when set, keeps the enrollments in progress and the certificates
	// issued in a database several relays use.
	Shared *Shared
	// Revoked is the deny list users add their certificates to when they
	// revoke them themselves (the page at /revoke). nil turns that off. Pass
	// the list the relay Server consults.
	Revoked *Revocations
	// MaxRenewAge is how long a device's certificate may be renewed without a
	// new sign-in (default one year).
	MaxRenewAge time.Duration
	// Disconnect, when set, is called after a revocation to cut the
	// connections that use the revoked certificates (Server.Kick).
	Disconnect func(email, serial string) int
	Logger     *log.Logger
	// SendMail is used by tests; when nil, SMTP is used.
	SendMail func(to, subject, body string) error
}

// Enrollment is a pending certificate request.
type Enrollment struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Device   string `json:"device,omitempty"`
	CSRPEM   string `json:"csr"`
	CodeHash string `json:"codeHash"`
	// Method is how the user proves who they are: "" or "email" (the code
	// sent by e-mail) or the id of an authentication method.
	Method string `json:"method,omitempty"`
	// Browser sign-in state: kept in memory only.
	State         string `json:"-"`
	Nonce         string `json:"-"`
	Verifier      string `json:"-"`
	SAMLRequestID string `json:"-"`
	// Ticket ties the confirmation form shown after the provider vouched for the
	// user to this enrollment; ClientAddr is who started it (shown to the user).
	Ticket     string    `json:"-"`
	ClientAddr string    `json:"-"`
	PollHash   string    `json:"pollHash"`
	Created    time.Time `json:"created"`
	Expires    time.Time `json:"expires"`
	Attempts   int       `json:"attempts"`
	Approved   bool      `json:"approved"`
	CertPEM    string    `json:"certPem,omitempty"`
	Known      bool      `json:"known"`
	// stateUsed: the browser sign-in state was spent. saved is what the database
	// row held when it was read (to write back only what changed).
	stateUsed bool
	saved     string
	// Admin marks a sign-in to the management interface (not a certificate
	// request); LoginHash ties it to the browser that started it.
	Admin     bool   `json:"-"`
	LoginHash string `json:"-"`
}

type enrollFile struct {
	Items []*Enrollment `json:"items"`
	Users []string      `json:"users"`
	Certs []*IssuedCert `json:"certs,omitempty"`
}

// EnrollServer serves the public enrollment API. It is separate from the mTLS
// relay listener, so clients can enroll before having a certificate.
type EnrollServer struct {
	cfg   EnrollConfig
	log   *log.Logger
	mu    sync.Mutex
	items map[string]*Enrollment
	users map[string]bool
	rate  map[string][]time.Time
	// certs is the ledger of certificates issued by this relay; revoke maps
	// the tokens of the revocation e-mails (hashed) to the address they are for.
	certs  []*IssuedCert
	revoke map[string]*revokeToken

	rulesMu sync.RWMutex
	rules   EnrollRules
	// lastPrune is the last time expired state was swept.
	lastPrune time.Time

	methods     map[string]*methodEntry // by id
	methodOrder []string
	byState     map[string]string // browser sign-in state -> enrollment id
	byTicket    map[string]string // confirmation ticket -> enrollment id
}

func NewEnrollServer(cfg EnrollConfig) (*EnrollServer, error) {
	s := &EnrollServer{
		cfg:    cfg,
		log:    cfg.Logger,
		items:  map[string]*Enrollment{},
		users:  map[string]bool{},
		revoke: map[string]*revokeToken{},
		rate:   map[string][]time.Time{},

		methods:  map[string]*methodEntry{},
		byState:  map[string]string{},
		byTicket: map[string]string{},
	}
	if s.log == nil {
		s.log = log.Default()
	}
	if cfg.CADir == "" {
		return nil, errors.New("enrollment: CA directory is required")
	}
	s.rules = s.initialRules()
	if _, _, err := loadCA(cfg.CADir); err != nil {
		return nil, fmt.Errorf("enrollment CA: %w", err)
	}
	if cfg.PublicRelay == "" {
		return nil, errors.New("enrollment: public relay address is required")
	}
	if u, err := url.Parse(cfg.PublicRelay); err == nil && u.Host != "" {
		cfg.PublicRelay = u.Host
	}
	s.cfg = cfg
	if err := s.buildMethods(); err != nil {
		return nil, err
	}
	if err := s.loadSavedRules(); err != nil {
		return nil, fmt.Errorf("enrollment rules: %w", err)
	}
	if r := s.Rules(); !s.emailDisabled() && cfg.SendMail == nil {
		if r.SMTP.Addr == "" {
			return nil, errors.New("enrollment: SMTP is not configured")
		}
		if r.SMTP.From == "" {
			return nil, errors.New("enrollment: SMTP from address is not configured")
		}
	}
	if cfg.Admin != nil {
		cfg.Admin.attach(s)
	}
	if len(s.Rules().AllowedDomains) == 0 {
		s.log.Printf("WARNING: enrollment is open to every e-mail domain (set -allow-domains to restrict it)")
	}
	if cfg.StatePath != "" && cfg.Shared == nil {
		if b, err := os.ReadFile(cfg.StatePath); err == nil {
			var f enrollFile
			if err := json.Unmarshal(b, &f); err == nil {
				for _, it := range f.Items {
					if time.Now().Before(it.Expires.Add(time.Hour)) {
						s.items[it.ID] = it
					}
				}
				for _, u := range f.Users {
					s.users[u] = true
				}
				s.certs = f.Certs
			}
		}
	}
	return s, nil
}

func (s *EnrollServer) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("POST /enroll", s.handleEnroll)
	// Sign-in methods. They live under their own prefix: /enroll/{id}/confirm
	// would otherwise clash with /enroll/<x>/<y>.
	m.HandleFunc("POST /enroll-auth/{method}", s.handleLogin)
	m.HandleFunc("POST /enroll-auth/{method}/start", s.handleBrowserStart)
	m.HandleFunc("GET /enroll-auth/{method}/callback", s.handleCallback)
	m.HandleFunc("POST /enroll-auth/{method}/acs", s.handleACS)
	m.HandleFunc("POST /enroll-auth/{method}/verify", s.handleVerify)
	m.HandleFunc("GET /enroll-auth/{method}/metadata", s.handleSAMLMetadata)
	m.HandleFunc("GET /enroll/{id}", s.handleStatus)
	m.HandleFunc("POST /enroll/{id}/confirm", s.handleConfirm)
	if s.cfg.Revoked.Enabled() && s.cfg.PublicURL != "" {
		s.mountSelfRevoke(m)
	}
	if s.cfg.Admin != nil {
		s.cfg.Admin.mount(m)
	}
	return m
}

func (s *EnrollServer) saveLocked() {
	if s.shared() {
		s.flushLocked()
		return
	}
	if s.cfg.StatePath == "" {
		return
	}
	f := enrollFile{}
	for _, it := range s.items {
		if !it.Admin {
			f.Items = append(f.Items, it)
		}
	}
	for u := range s.users {
		f.Users = append(f.Users, u)
	}
	f.Certs = s.certs
	b, _ := json.MarshalIndent(f, "", "  ")
	WriteFileAtomic(s.cfg.StatePath, b, 0o600)
}

func (s *EnrollServer) allow(key string, limit int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	cut := now.Add(-enrollRateWindow)
	s.pruneLocked(now, cut)
	times := s.rate[key]
	kept := times[:0]
	for _, t := range times {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= limit {
		s.rate[key] = kept
		return false
	}
	s.rate[key] = append(kept, now)
	return true
}

// pruneLocked drops expired enrollments and stale rate-limit entries, so that
// unauthenticated requests cannot grow memory and the state file without
// bound. Callers must hold s.mu.
func (s *EnrollServer) pruneLocked(now, cut time.Time) {
	if now.Sub(s.lastPrune) < time.Minute {
		return
	}
	s.lastPrune = now
	if s.shared() {
		s.pruneSharedLocked(now)
	}
	for id, it := range s.items {
		if now.After(it.Expires.Add(time.Hour)) {
			delete(s.items, id)
		}
	}
	for st, id := range s.byState {
		if _, ok := s.items[id]; !ok {
			delete(s.byState, st)
		}
	}
	for tk, id := range s.byTicket {
		if _, ok := s.items[id]; !ok {
			delete(s.byTicket, tk)
		}
	}
	for k, times := range s.rate {
		fresh := false
		for _, t := range times {
			if t.After(cut) {
				fresh = true
				break
			}
		}
		if !fresh {
			delete(s.rate, k)
		}
	}
}

func allowedDomain(email string, domains []string) bool {
	if len(domains) == 0 {
		return true
	}
	at := strings.LastIndexByte(email, '@')
	if at < 0 {
		return false
	}
	d := strings.ToLower(email[at+1:])
	for _, a := range domains {
		a = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(a), "@"))
		if a != "" && a == d {
			return true
		}
	}
	return false
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// Never fall back to a predictable value for a secret.
		panic("enrollment: no secure random source: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func randomCode() string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, enrollCodeLen)
	if _, err := rand.Read(b); err != nil {
		panic("enrollment: no secure random source: " + err.Error())
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

func hashToken(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func normalizeCode(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *EnrollServer) clientIP(r *http.Request) string {
	if s.cfg.TrustForwardedFor {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip := strings.TrimSpace(parts[len(parts)-1]); net.ParseIP(ip) != nil {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// enrollRequest is a validated enrollment request.
type enrollRequest struct {
	email  string
	device string
	csr    string // PEM
}

// parseEnrollRequest reads and checks what every enrollment method starts
// with: the e-mail address, the device code and a certificate request that is
// for that address. extra receives the remaining fields of the body.
func (s *EnrollServer) parseEnrollRequest(w http.ResponseWriter, r *http.Request, extra any) (*enrollRequest, bool) {
	var req struct {
		Email  string `json:"email"`
		CSR    string `json:"csr"`
		Device string `json:"device"`
	}
	body := http.MaxBytesReader(w, r.Body, 128<<10)
	raw, err := io.ReadAll(body)
	if err != nil || json.Unmarshal(raw, &req) != nil {
		writeError(w, http.StatusBadRequest, "richiesta non valida")
		return nil, false
	}
	if extra != nil && json.Unmarshal(raw, extra) != nil {
		writeError(w, http.StatusBadRequest, "richiesta non valida")
		return nil, false
	}
	email, ok := NormalizeEmail(req.Email)
	if !ok {
		writeError(w, http.StatusBadRequest, "indirizzo e-mail non valido")
		return nil, false
	}
	if !allowedDomain(email, s.Rules().AllowedDomains) {
		writeError(w, http.StatusForbidden, "dominio non abilitato")
		return nil, false
	}
	device, ok := NormalizeDevice(req.Device)
	if !ok {
		writeError(w, http.StatusBadRequest, "codice dispositivo non valido")
		return nil, false
	}
	// Validate the CSR before creating state or contacting anyone.
	block, _ := pem.Decode([]byte(req.CSR))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		writeError(w, http.StatusBadRequest, "CSR non valida")
		return nil, false
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		writeError(w, http.StatusBadRequest, "CSR non valida")
		return nil, false
	}
	identity := false
	for _, e := range csr.EmailAddresses {
		if v, ok := NormalizeEmail(e); ok && v == email {
			identity = true
		}
	}
	if !identity {
		writeError(w, http.StatusBadRequest, "la CSR non corrisponde all'e-mail")
		return nil, false
	}
	return &enrollRequest{email: email, device: device, csr: req.CSR}, true
}

func (s *EnrollServer) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var extra struct {
		// Method is how the user wants to prove who they are. Without one, a
		// relay that offers several ways answers 401 and lists them.
		Method string `json:"method"`
	}
	pr, ok := s.parseEnrollRequest(w, r, &extra)
	if !ok {
		return
	}
	method := strings.ToLower(strings.TrimSpace(extra.Method))
	if method == "" && s.authRequired() {
		s.challenge(w)
		return
	}
	if method != "" && method != "email" {
		writeError(w, http.StatusBadRequest, "questo metodo non usa /enroll: vedi l'elenco restituito dal relay")
		return
	}
	if s.emailDisabled() {
		writeError(w, http.StatusForbidden, "il codice via e-mail non è abilitato: usa uno degli altri metodi")
		return
	}
	email, device := pr.email, pr.device
	req := struct{ CSR string }{CSR: pr.csr}

	ip := s.clientIP(r)
	if !s.allow("email:"+email, 4) || !s.allow("ip:"+ip, 12) {
		writeError(w, http.StatusTooManyRequests, "troppe richieste, riprova tra qualche minuto")
		return
	}

	code := randomCode()
	pollToken := randomToken(32)
	id := randomToken(12)
	now := time.Now()

	s.mu.Lock()
	known := s.userKnownLocked(email)
	it := &Enrollment{
		ID: id, Email: email, Device: device, CSRPEM: req.CSR,
		CodeHash: hashToken(code), PollHash: hashToken(pollToken),
		Created: now, Expires: now.Add(enrollTTL), Known: known,
	}
	s.itemAddLocked(it)
	s.mu.Unlock()

	subject, body := enrollmentEmail(email, code, s.mailConfig(), known)
	if err := s.send(email, subject, body); err != nil {
		s.mu.Lock()
		s.itemDropLocked(id)
		s.mu.Unlock()
		s.log.Printf("enrollment mail to %s failed: %v", email, err)
		writeError(w, http.StatusBadGateway, "invio dell'e-mail non riuscito")
		return
	}
	s.audit("enroll.request", email, "", "e-mail code, from "+ip)
	writeJSON(w, http.StatusOK, map[string]any{
		"id":           id,
		"pollToken":    pollToken,
		"expiresAt":    it.Expires,
		"relayAddress": s.cfg.PublicRelay,
		"relayCAPEM":   s.cfg.RelayCAPEM,
	})
}

func enrollmentEmail(email, code string, cfg EnrollConfig, known bool) (subject, body string) {
	subject = "Go Smart Proxy: conferma del collegamento al relay"
	code = code[:4] + "-" + code[4:]
	var b strings.Builder
	b.WriteString("Ciao,\n\n")
	if known {
		b.WriteString("È stata richiesta una nuova configurazione per questo indirizzo e-mail.\n\n")
	} else {
		b.WriteString("Sei stato invitato a collegarti al relay Go Smart Proxy.\n\n")
		if cfg.DownloadURL != "" {
			fmt.Fprintf(&b, "Scarica il proxy da: %s\n\n", cfg.DownloadURL)
		}
	}
	fmt.Fprintf(&b, "Per confermare, inserisci questo codice nel proxy:\n\n    %s\n\n", code)
	fmt.Fprintf(&b, "Il codice scade tra %d minuti ed è utilizzabile una sola volta.\n\n", int(enrollTTL.Minutes()))
	if cfg.PublicURL != "" {
		fmt.Fprintf(&b, "Indirizzo del relay da usare nel proxy: %s\n\n", cfg.PublicURL)
	}
	b.WriteString("Se non hai richiesto tu questo collegamento, ignora questa e-mail.\n")
	return subject, b.String()
}

// SendInvite sends an invitation email with the enrollment address and download
// link. The user installs the proxy, enters the address and their e-mail, and
// completes the normal code-based enrollment.
func SendInvite(cfg EnrollConfig, to string) error {
	email, ok := NormalizeEmail(to)
	if !ok {
		return errors.New("indirizzo e-mail non valido")
	}
	subject := "Invito al relay Go Smart Proxy"
	var b strings.Builder
	b.WriteString("Ciao,\n\n")
	b.WriteString("Sei stato invitato a collegarti al relay Go Smart Proxy.\n\n")
	if cfg.DownloadURL != "" {
		fmt.Fprintf(&b, "Scarica il proxy da: %s\n\n", cfg.DownloadURL)
	}
	b.WriteString("Apri la pagina \"Relay\" nel proxy e inserisci:\n\n")
	if cfg.PublicURL != "" {
		fmt.Fprintf(&b, "    Indirizzo relay: %s\n", cfg.PublicURL)
	}
	fmt.Fprintf(&b, "    E-mail: %s\n\n", email)
	b.WriteString("Riceverai un codice di conferma via e-mail per completare il collegamento.\n")
	b.WriteString("Se non hai richiesto tu questo invito, ignora questo messaggio.\n")
	if cfg.SendMail != nil {
		return cfg.SendMail(email, subject, b.String())
	}
	return sendSMTP(cfg, email, subject, b.String())
}

func (s *EnrollServer) send(to, subject, body string) error {
	var err error
	if s.cfg.SendMail != nil {
		err = s.cfg.SendMail(to, subject, body)
	} else {
		err = sendSMTP(s.mailConfig(), to, subject, body)
	}
	if err != nil {
		CounterInc("gsp_relay_mail_total", "result", "failed")
	} else {
		CounterInc("gsp_relay_mail_total", "result", "sent")
	}
	return err
}

// smtpAuth chooses the authentication mechanism. In auto mode it prefers
// PLAIN and falls back to LOGIN, based on what the server advertises.
func smtpAuth(c *smtp.Client, cfg EnrollConfig) (smtp.Auth, error) {
	if cfg.SMTPUser == "" {
		return nil, nil
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.SMTPAuth))
	if mode == "none" {
		return nil, nil
	}
	ok, ext := c.Extension("AUTH")
	if !ok {
		return nil, errors.New("the SMTP server does not support authentication")
	}
	mechs := strings.ToUpper(ext)
	has := func(m string) bool { return strings.Contains(mechs, m) }
	switch mode {
	case "plain":
		if mechs != "" && !has("PLAIN") {
			return nil, fmt.Errorf("the SMTP server does not support PLAIN (advertises: %s)", mechs)
		}
		return smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPass, smtpHost(cfg.SMTPAddr)), nil
	case "login":
		return &loginAuth{user: cfg.SMTPUser, pass: cfg.SMTPPass}, nil
	case "", "auto":
		if mechs == "" || has("PLAIN") {
			return smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPass, smtpHost(cfg.SMTPAddr)), nil
		}
		if has("LOGIN") {
			return &loginAuth{user: cfg.SMTPUser, pass: cfg.SMTPPass}, nil
		}
		return nil, fmt.Errorf("no supported SMTP authentication mechanism (advertises: %s)", mechs)
	default:
		return nil, fmt.Errorf("unknown SMTP authentication mode %q", cfg.SMTPAuth)
	}
}

func smtpHost(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// loginAuth implements the LOGIN mechanism, which net/smtp does not provide.
type loginAuth struct {
	user, pass string
}

func (a *loginAuth) Start(*smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", nil, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	challenge := strings.ToLower(strings.TrimSpace(string(fromServer)))
	switch {
	case strings.Contains(challenge, "user"):
		return []byte(a.user), nil
	case strings.Contains(challenge, "pass"):
		return []byte(a.pass), nil
	default:
		return nil, fmt.Errorf("unexpected SMTP LOGIN challenge: %q", fromServer)
	}
}

func sendSMTP(cfg EnrollConfig, to, subject, body string) error {
	msg := "From: " + cfg.SMTPFrom + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n\r\n" + body
	host, _, err := net.SplitHostPort(cfg.SMTPAddr)
	if err != nil {
		host = cfg.SMTPAddr
	}

	mode := strings.ToLower(cfg.SMTPTLS)
	var conn net.Conn
	if mode == "tls" {
		d := &net.Dialer{Timeout: 10 * time.Second}
		conn, err = tls.DialWithDialer(d, "tcp", cfg.SMTPAddr, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	} else {
		conn, err = net.DialTimeout("tcp", cfg.SMTPAddr, 10*time.Second)
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	if mode == "starttls" {
		if err := c.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	}
	auth, err := smtpAuth(c, cfg)
	if err != nil {
		return err
	}
	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return err
		}
	}
	if err := c.Mail(cfg.SMTPFrom); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func (s *EnrollServer) bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return "", false
	}
	t := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	return t, t != ""
}

func (s *EnrollServer) find(w http.ResponseWriter, r *http.Request) (*Enrollment, string, bool) {
	token, ok := s.bearer(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "token mancante")
		return nil, "", false
	}
	id := r.PathValue("id")
	s.mu.Lock()
	it := s.itemLoadLocked(id)
	s.mu.Unlock()
	if it == nil || subtle.ConstantTimeCompare([]byte(hashToken(token)), []byte(it.PollHash)) != 1 {
		writeError(w, http.StatusNotFound, "richiesta non trovata")
		return nil, "", false
	}
	if time.Now().After(it.Expires) {
		writeError(w, http.StatusGone, "richiesta scaduta")
		return nil, "", false
	}
	return it, token, true
}

func (s *EnrollServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	it, _, ok := s.find(w, r)
	if !ok {
		return
	}
	status := "pending"
	if it.Approved {
		status = "approved"
	}
	res := map[string]any{"status": status, "email": it.Email, "expiresAt": it.Expires, "relayAddress": s.cfg.PublicRelay, "relayCAPEM": s.cfg.RelayCAPEM}
	if it.Approved {
		res["certPem"] = it.CertPEM
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *EnrollServer) handleConfirm(w http.ResponseWriter, r *http.Request) {
	it, _, ok := s.find(w, r)
	if !ok {
		return
	}
	if it.Method != "" && it.Method != "email" {
		writeError(w, http.StatusBadRequest, "questa richiesta non usa il codice via e-mail")
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "richiesta non valida")
		return
	}
	code := normalizeCode(req.Code)

	s.mu.Lock()
	approved := it.Approved
	certPEM := it.CertPEM
	if !approved {
		if it.Attempts >= enrollMaxTries {
			s.mu.Unlock()
			writeError(w, http.StatusTooManyRequests, "troppi tentativi")
			return
		}
		if subtle.ConstantTimeCompare([]byte(hashToken(code)), []byte(it.CodeHash)) != 1 {
			it.Attempts++
			s.saveLocked()
			left := enrollMaxTries - it.Attempts
			s.mu.Unlock()
			s.audit("enroll.denied", it.Email, "email", "wrong e-mail code from "+s.clientIP(r))
			writeError(w, http.StatusForbidden, fmt.Sprintf("codice non valido (%d tentativi rimasti)", left))
			return
		}
	}
	email := it.Email
	csr := []byte(it.CSRPEM)
	s.mu.Unlock()

	if !approved {
		signed, err := s.sign(csr, email, it.Device, "email", s.clientIP(r))
		if err != nil {
			s.log.Printf("enrollment signing for %s failed: %v", email, err)
			writeError(w, http.StatusInternalServerError, "firma del certificato non riuscita")
			return
		}
		s.mu.Lock()
		it.Approved = true
		it.CertPEM = signed
		it.CodeHash = ""
		s.noteUserLocked(email)
		s.saveLocked()
		s.mu.Unlock()
		certPEM = signed
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"certPem":      certPEM,
		"relayAddress": s.cfg.PublicRelay,
		"relayCAPEM":   s.cfg.RelayCAPEM,
	})
}
