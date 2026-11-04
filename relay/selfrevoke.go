package relay

import (
	"fmt"
	"html"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Two things protect a user from a certificate they did not ask for:
//
//   - every time a device is associated to their address, the relay e-mails
//     them (the device, when, from where, with a link to revoke);
//   - they can revoke the certificates of their address themselves, at
//     /revoke. The relay e-mails a link to the address, and only a click on
//     the page that link opens (never the link alone, which mail scanners
//     fetch) revokes.

// IssuedCert is a certificate this relay issued, kept so that its owner can
// see and revoke it.
type IssuedCert struct {
	Serial  string    `json:"serial"`
	Email   string    `json:"email"`
	Device  string    `json:"device,omitempty"`
	Method  string    `json:"method,omitempty"`
	IP      string    `json:"ip,omitempty"`
	Issued  time.Time `json:"issued"`
	Expires time.Time `json:"expires"`
	Revoked bool      `json:"revoked,omitempty"`
}

const (
	revokeTokenTTL = 30 * time.Minute
	// ledgerKeep is how long an expired certificate stays in the ledger.
	ledgerKeep = 30 * 24 * time.Hour
)

type revokeToken struct {
	email   string
	expires time.Time
}

func (s *EnrollServer) recordIssued(c *IssuedCert) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	kept := s.certs[:0]
	for _, x := range s.certs {
		if now.Before(x.Expires.Add(ledgerKeep)) {
			kept = append(kept, x)
		}
	}
	s.certs = append(kept, c)
	s.saveLocked()
}

// activeCerts lists the certificates of email that are valid and not revoked.
func (s *EnrollServer) activeCerts(email string) []IssuedCert {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	var out []IssuedCert
	for _, c := range s.certs {
		if c.Email == email && !c.Revoked && now.Before(c.Expires) {
			out = append(out, *c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Issued.After(out[j].Issued) })
	return out
}

func (s *EnrollServer) canMail() bool {
	return s.cfg.SendMail != nil || s.Rules().SMTP.Addr != ""
}

// revokeURL is where a user revokes their certificates.
func (s *EnrollServer) revokeURL(email string) string {
	if !s.cfg.Revoked.Enabled() || s.cfg.PublicURL == "" {
		return ""
	}
	return publicBase(s.cfg.PublicURL) + "/revoke"
}

// notifyDevice tells the owner of an address that a device was associated to
// it. It is sent in the background: a mail problem must not fail the
// enrollment, and is only logged.
func (s *EnrollServer) notifyDevice(email, device, method, ip string, expires time.Time) {
	if !s.canMail() {
		return
	}
	if device == "" {
		device = "-"
	}
	if method == "" || method == "email" {
		method = "e-mail"
	}
	var b strings.Builder
	b.WriteString("Ciao,\n\n")
	fmt.Fprintf(&b, "Un nuovo dispositivo è stato associato al tuo indirizzo (%s) sul relay Go Smart Proxy.\n\n", email)
	fmt.Fprintf(&b, "    Dispositivo: %s\n    Metodo: %s\n    Da: %s\n    Quando: %s\n    Certificato valido fino al: %s\n\n",
		device, method, orDash(ip), time.Now().Format("02/01/2006 15:04 MST"), expires.Format("02/01/2006"))
	b.WriteString("Se sei stato tu, non devi fare nulla.\n")
	b.WriteString("Se NON sei stato tu, revoca subito i certificati associati al tuo indirizzo")
	if u := s.revokeURL(email); u != "" {
		fmt.Fprintf(&b, ":\n\n    %s\n", u)
	} else {
		b.WriteString(" contattando l'amministratore del relay.\n")
	}
	b.WriteString("\n---\n\nHello,\n\n")
	fmt.Fprintf(&b, "A new device was associated to your address (%s) on the Go Smart Proxy relay: %s, from %s.\n", email, device, orDash(ip))
	b.WriteString("If it was you, there is nothing to do. If it was NOT you, revoke the certificates of your address now")
	if u := s.revokeURL(email); u != "" {
		fmt.Fprintf(&b, ": %s\n", u)
	} else {
		b.WriteString(" by contacting the relay administrator.\n")
	}
	go func() {
		if err := s.send(email, "Go Smart Proxy: nuovo dispositivo associato / new device associated", b.String()); err != nil {
			s.log.Printf("notification to %s failed: %v", email, err)
		}
	}()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// ---- pages ------------------------------------------------------------

func selfPage(w http.ResponseWriter, status int, title, body string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>%s</title>
<body style="font-family:system-ui,sans-serif;max-width:36rem;margin:10vh auto;padding:0 1.5rem;line-height:1.5"><h1 style="font-size:1.4rem">%s</h1>%s</body>`,
		html.EscapeString(title), html.EscapeString(title), body)
}

const revokeTitle = "Revoca i tuoi certificati · Revoke your certificates"

func (s *EnrollServer) mountSelfRevoke(m *http.ServeMux) {
	m.HandleFunc("GET /revoke", s.handleRevokeForm)
	m.HandleFunc("POST /revoke", s.handleRevokeRequest)
	m.HandleFunc("GET /revoke/confirm", s.handleRevokeConfirmPage)
	m.HandleFunc("POST /revoke/confirm", s.handleRevokeDo)
}

func (s *EnrollServer) handleRevokeForm(w http.ResponseWriter, r *http.Request) {
	selfPage(w, http.StatusOK, revokeTitle, `<p>Inserisci il tuo indirizzo e-mail: ti invieremo un messaggio con un collegamento per confermare la revoca.<br>
Enter your e-mail address: we will send you a message with a link to confirm the revocation.</p>
<form method="post" action="/revoke"><p><input type="email" name="email" required autofocus autocomplete="email" style="font-size:1.1rem;padding:.4rem;width:100%;box-sizing:border-box"></p>
<p><button style="font-size:1.1rem;padding:.4rem 1rem">Invia · Send</button></p></form>`)
}

// handleRevokeRequest e-mails the link. The answer never depends on whether
// the address has certificates, so the page cannot be used to find out who is
// a user.
func (s *EnrollServer) handleRevokeRequest(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		selfPage(w, http.StatusBadRequest, revokeTitle, "<p>Richiesta non valida · Invalid request</p>")
		return
	}
	email, ok := NormalizeEmail(r.PostForm.Get("email"))
	if !ok {
		selfPage(w, http.StatusBadRequest, revokeTitle, "<p>Indirizzo non valido · Invalid address</p>")
		return
	}
	ip := s.clientIP(r)
	if !s.allow("revoke:"+email, 3) || !s.allow("revokeip:"+ip, 15) {
		selfPage(w, http.StatusTooManyRequests, revokeTitle, "<p>Troppe richieste, riprova tra qualche minuto.<br>Too many requests, try again in a few minutes.</p>")
		return
	}
	if len(s.activeCerts(email)) > 0 && s.canMail() {
		token := randomToken(32)
		s.mu.Lock()
		now := time.Now()
		for k, t := range s.revoke {
			if now.After(t.expires) {
				delete(s.revoke, k)
			}
		}
		s.revoke[hashToken(token)] = &revokeToken{email: email, expires: now.Add(revokeTokenTTL)}
		s.mu.Unlock()
		link := publicBase(s.cfg.PublicURL) + "/revoke/confirm?token=" + token
		body := fmt.Sprintf("Ciao,\n\nè stata chiesta la revoca dei certificati associati a %s (richiesta da %s).\n\n"+
			"Per vedere i dispositivi e confermare, apri questo collegamento (valido %d minuti, una sola volta):\n\n    %s\n\n"+
			"Se non l'hai chiesto tu, ignora questo messaggio: non succede nulla.\n\n---\n\n"+
			"Hello,\n\nrevocation of the certificates of %s was requested (from %s). Open the link above to see the devices and confirm; "+
			"it is valid for %d minutes. If it was not you, ignore this message: nothing happens.\n",
			email, ip, int(revokeTokenTTL.Minutes()), link, email, ip, int(revokeTokenTTL.Minutes()))
		go func() {
			if err := s.send(email, "Go Smart Proxy: conferma la revoca dei certificati / confirm revocation", body); err != nil {
				s.log.Printf("revocation mail to %s failed: %v", email, err)
			}
		}()
		s.audit("user.revoke.request", email, "", "from "+ip)
	}
	selfPage(w, http.StatusOK, revokeTitle, `<p>Se l'indirizzo ha certificati attivi, abbiamo inviato un messaggio con un collegamento per confermare.<br>
If the address has active certificates, we sent a message with a link to confirm.</p>`)
}

// lookupToken finds a valid token without consuming it.
func (s *EnrollServer) lookupToken(token string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.revoke[hashToken(token)]
	if t == nil || time.Now().After(t.expires) {
		return "", false
	}
	return t.email, true
}

func badLink(w http.ResponseWriter) {
	selfPage(w, http.StatusForbidden, revokeTitle, `<p>Il collegamento non è valido o è scaduto. <a href="/revoke">Chiedine uno nuovo</a>.<br>
The link is invalid or has expired. <a href="/revoke">Ask for a new one</a>.</p>`)
}

// handleRevokeConfirmPage shows the devices. It changes nothing: mail
// scanners and previews open links.
func (s *EnrollServer) handleRevokeConfirmPage(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if !s.allow("revokeip:"+s.clientIP(r), 30) {
		selfPage(w, http.StatusTooManyRequests, revokeTitle, "<p>Troppe richieste · Too many requests</p>")
		return
	}
	email, ok := s.lookupToken(token)
	if !ok {
		badLink(w)
		return
	}
	certs := s.activeCerts(email)
	if len(certs) == 0 {
		selfPage(w, http.StatusOK, revokeTitle, "<p>Nessun certificato attivo per questo indirizzo.<br>No active certificates for this address.</p>")
		return
	}
	var rows strings.Builder
	for _, c := range certs {
		fmt.Fprintf(&rows, `<li><label><input type="checkbox" name="serial" value="%s" checked> <b>%s</b> · %s · %s → %s</label></li>`,
			html.EscapeString(c.Serial), html.EscapeString(orDash(c.Device)), html.EscapeString(orDash(c.IP)),
			c.Issued.Format("02/01/2006 15:04"), c.Expires.Format("02/01/2006"))
	}
	selfPage(w, http.StatusOK, revokeTitle, fmt.Sprintf(`<p>Certificati attivi di <b>%s</b>. Quelli selezionati saranno revocati: i dispositivi si disconnettono subito e dovranno registrarsi di nuovo.<br>
Active certificates of <b>%s</b>. The selected ones will be revoked: the devices disconnect at once and must enroll again.</p>
<form method="post" action="/revoke/confirm"><input type="hidden" name="token" value="%s"><ul style="list-style:none;padding:0">%s</ul>
<p><button style="font-size:1.1rem;padding:.4rem 1rem">Revoca · Revoke</button></p></form>`,
		html.EscapeString(email), html.EscapeString(email), html.EscapeString(token), rows.String()))
}

func (s *EnrollServer) handleRevokeDo(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		badLink(w)
		return
	}
	token := r.PostForm.Get("token")
	if !s.allow("revokeip:"+s.clientIP(r), 30) {
		selfPage(w, http.StatusTooManyRequests, revokeTitle, "<p>Troppe richieste · Too many requests</p>")
		return
	}
	email, ok := s.lookupToken(token)
	if !ok {
		badLink(w)
		return
	}
	want := map[string]bool{}
	for _, v := range r.PostForm["serial"] {
		want[strings.ToLower(strings.TrimSpace(v))] = true
	}
	if len(want) == 0 {
		selfPage(w, http.StatusBadRequest, revokeTitle, `<p>Seleziona almeno un dispositivo. · Select at least one device.</p>`)
		return
	}
	// The link is good for one revocation.
	s.mu.Lock()
	delete(s.revoke, hashToken(token))
	s.mu.Unlock()

	var done []IssuedCert
	for _, c := range s.activeCerts(email) {
		if !want[c.Serial] {
			continue
		}
		if err := s.cfg.Revoked.Add("serial:" + c.Serial); err != nil {
			s.log.Printf("revocation of %s for %s failed: %v", c.Serial, email, err)
			continue
		}
		s.mu.Lock()
		for _, x := range s.certs {
			if x.Serial == c.Serial {
				x.Revoked = true
			}
		}
		s.saveLocked()
		s.mu.Unlock()
		if a := s.cfg.Admin; a != nil {
			a.db.markCert(c.Serial, true, email)
		}
		if s.cfg.Disconnect != nil {
			s.cfg.Disconnect(email, c.Serial)
		}
		s.audit("user.revoke", email, c.Serial, orDash(c.Device))
		done = append(done, c)
	}
	s.log.Printf("revocation: %s revoked %d certificate(s) from %s", email, len(done), s.clientIP(r))
	if len(done) == 0 {
		selfPage(w, http.StatusInternalServerError, revokeTitle, "<p>Non è stato possibile revocare. · Could not revoke.</p>")
		return
	}
	if s.canMail() {
		var b strings.Builder
		fmt.Fprintf(&b, "Ciao,\n\nsono stati revocati %d certificati associati a %s:\n\n", len(done), email)
		for _, c := range done {
			fmt.Fprintf(&b, "    %s (%s)\n", orDash(c.Device), c.Serial[:min(12, len(c.Serial))])
		}
		b.WriteString("\nI dispositivi sono stati disconnessi. Per usare di nuovo il relay devono registrarsi un'altra volta.\n\n---\n\n")
		fmt.Fprintf(&b, "Hello,\n\n%d certificates of %s were revoked and their devices disconnected. They must enroll again to use the relay.\n", len(done), email)
		go func() {
			if err := s.send(email, "Go Smart Proxy: certificati revocati / certificates revoked", b.String()); err != nil {
				s.log.Printf("revocation notice to %s failed: %v", email, err)
			}
		}()
	}
	selfPage(w, http.StatusOK, revokeTitle, fmt.Sprintf(`<p>Fatto: %d certificati revocati. Ti abbiamo inviato una conferma.<br>Done: %d certificates revoked. We sent you a confirmation.</p>`, len(done), len(done)))
}
