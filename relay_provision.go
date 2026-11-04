package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"proxy/relay"
)

type pendingEnrollment struct {
	Name         string // the relay entry being created or renewed
	Method       string // "code" (e-mail) or "browser" (sign-in on the provider's page)
	AuthURL      string // browser sign-in: the page the user was sent to
	UserCode     string // browser sign-in: the code to type on the relay's confirmation page
	BaseURL      string
	Email        string
	Device       string
	ID           string
	PollToken    string
	CSRPEM       []byte
	KeyPEM       []byte
	ServerCAPEM  string
	ServerPin    string
	RelayCAPEM   string
	RelayAddress string
	Expires      time.Time
}

type certificateInfo struct {
	Subject       string `json:"subject"`
	Issuer        string `json:"issuer"`
	Fingerprint   string `json:"fingerprint"`
	CASubject     string `json:"caSubject,omitempty"`
	CAFingerprint string `json:"caFingerprint,omitempty"`
}

type untrustedCertificateError struct {
	Info certificateInfo
}

func (e *untrustedCertificateError) Error() string {
	return "certificato del server non riconosciuto"
}

type pendingTrust struct {
	BaseURL     string
	Email       string
	Fingerprint string
	Expires     time.Time
}

var (
	enrollMu      sync.Mutex
	enrollPending *pendingEnrollment
	trustPending  *pendingTrust
	// enrollResult is how the last enrollment ended, kept for a little while so
	// that the page, which polls, can tell success from failure.
	enrollResult *enrollOutcome
)

type enrollOutcome struct {
	Name  string // the relay that was configured
	Error string
	At    time.Time
}

func setEnrollResult(name, errText string) {
	enrollMu.Lock()
	enrollResult = &enrollOutcome{Name: name, Error: errText, At: time.Now()}
	enrollMu.Unlock()
}

type enrollResponse struct {
	ID           string    `json:"id"`
	PollToken    string    `json:"pollToken"`
	RelayAddress string    `json:"relayAddress"`
	RelayCAPEM   string    `json:"relayCAPEM"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

type confirmResponse struct {
	CertPEM      string `json:"certPem"`
	RelayAddress string `json:"relayAddress"`
	RelayCAPEM   string `json:"relayCAPEM"`
}

func normalizeEnrollURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("indirizzo relay mancante")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, errors.New("indirizzo relay non valido")
	}
	if u.Scheme != "https" {
		return nil, errors.New("l'enrollment richiede HTTPS")
	}
	if u.Path != "" && u.Path != "/" {
		return nil, errors.New("usa solo host:porta dell'endpoint di enrollment")
	}
	u.Path, u.RawQuery, u.Fragment = "", "", ""
	return u, nil
}

func generateCSR(email string) (csrPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: email},
		EmailAddresses: []string{email},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tpl, key)
	if err != nil {
		return nil, nil, err
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), nil
}

func enrollmentClient(serverCAPEM, pin, baseURL string) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if pin != "" {
		u, err := url.Parse(baseURL)
		if err != nil || u.Hostname() == "" {
			return nil, errors.New("indirizzo relay non valido")
		}
		tlsCfg.InsecureSkipVerify = true // the pin below is the verification
		tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("il server non ha presentato un certificato")
			}
			got := fingerprintDER(rawCerts[0])
			if normalizeFingerprint(got) != normalizeFingerprint(pin) {
				return fmt.Errorf("il certificato del server è cambiato (fingerprint %s)", got)
			}
			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			return leaf.VerifyHostname(u.Hostname())
		}
	} else if strings.TrimSpace(serverCAPEM) != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(serverCAPEM)) {
			return nil, errors.New("CA del relay non valida")
		}
		tlsCfg.RootCAs = pool
	}
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
			MaxIdleConns:    2,
			IdleConnTimeout: 30 * time.Second,
		},
	}, nil
}

func fingerprintDER(der []byte) string {
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:])
}

func normalizeFingerprint(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}

func postJSON(client *http.Client, endpoint, bearer string, in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &e) == nil && e.Error != "" {
			return errors.New(e.Error)
		}
		return fmt.Errorf("relay ha risposto %d", resp.StatusCode)
	}
	return json.Unmarshal(body, out)
}

// probeCertificate reads the certificate presented by the enrollment endpoint
// without validating it, so the user can be asked to accept its fingerprint.
func probeCertificate(base *url.URL) (certificateInfo, error) {
	port := base.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(base.Hostname(), port)
	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         base.Hostname(),
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return certificateInfo{}, err
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return certificateInfo{}, errors.New("the server presented no certificate")
	}
	leaf := certs[0]
	info := certificateInfo{
		Subject:     leaf.Subject.String(),
		Issuer:      leaf.Issuer.String(),
		Fingerprint: fingerprintDER(leaf.Raw),
	}
	if len(certs) > 1 {
		ca := certs[len(certs)-1]
		info.CASubject = ca.Subject.String()
		info.CAFingerprint = fingerprintDER(ca.Raw)
	}
	return info, nil
}

func isCertificateError(err error) bool {
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return true
	}
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		return true
	}
	var hostname x509.HostnameError
	if errors.As(err, &hostname) {
		return true
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) {
		return true
	}
	return false
}

// enrollTarget is everything a sign-in method needs to start: the relay being
// enrolled, a certificate request for the user and a TLS client that trusts the
// enrollment endpoint (by CA, or by the fingerprint the user accepted).
type enrollTarget struct {
	name        string
	base        *url.URL
	email       string
	device      string
	pin         string
	serverCAPEM string
	csrPEM      []byte
	keyPEM      []byte
	client      *http.Client
}

// checkEnrollInputs validates the e-mail and the relay name and normalizes the
// address of the enrollment endpoint.
func checkEnrollInputs(name, address, email string) (string, *url.URL, string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name != "" && !validRelayName(name) {
		return "", nil, "", errors.New("nome del relay non valido (minuscole, cifre, - e _)")
	}
	email, ok := relay.NormalizeEmail(email)
	if !ok {
		return "", nil, "", errors.New("indirizzo e-mail non valido")
	}
	base, err := normalizeEnrollURL(address)
	if err != nil {
		return "", nil, "", err
	}
	return name, base, email, nil
}

// acceptedPin returns the fingerprint the user accepted, if it is the one just
// shown for this endpoint and e-mail address and is still fresh.
func acceptedPin(base *url.URL, email, acceptFingerprint string) (string, error) {
	if acceptFingerprint == "" {
		return "", nil
	}
	enrollMu.Lock()
	trust := trustPending
	enrollMu.Unlock()
	if trust == nil || time.Now().After(trust.Expires) ||
		trust.Email != email || trust.BaseURL != base.String() ||
		normalizeFingerprint(trust.Fingerprint) != normalizeFingerprint(acceptFingerprint) {
		return "", errors.New("certificato non più valido: richiedi di nuovo l'enrollment")
	}
	return trust.Fingerprint, nil
}

// untrustedOrError turns a failure to verify the endpoint's certificate into
// the prompt that lets the user inspect and accept its fingerprint.
func untrustedOrError(base *url.URL, email, pin string, err error) error {
	if pin == "" && isCertificateError(err) {
		if info, perr := probeCertificate(base); perr == nil {
			enrollMu.Lock()
			trustPending = &pendingTrust{
				BaseURL:     base.String(),
				Email:       email,
				Fingerprint: info.Fingerprint,
				Expires:     time.Now().Add(5 * time.Minute),
			}
			enrollMu.Unlock()
			return &untrustedCertificateError{Info: info}
		}
	}
	return err
}

// prepareEnroll gathers what every method needs.
func prepareEnroll(name, address, email, serverCAPEM, acceptFingerprint string) (*enrollTarget, error) {
	name, base, email, err := checkEnrollInputs(name, address, email)
	if err != nil {
		return nil, err
	}
	pin, err := acceptedPin(base, email, acceptFingerprint)
	if err != nil {
		return nil, err
	}

	// The relay being enrolled: the named one (a renewal when it exists, a new
	// relay otherwise), or the first one, or a new relay called "default".
	configMu.Lock()
	if name == "" {
		if len(configuration.Relays) > 0 {
			name = configuration.Relays[0].Name
		} else {
			name = defaultRelayName
		}
	}
	device := ""
	if existing := findRelayConfigLocked(name); existing != nil {
		device = existing.Device
	} else if len(configuration.Relays) >= maxRelays {
		configMu.Unlock()
		return nil, errors.New("troppi relay configurati")
	} else if len(configuration.Relays) > 0 {
		device = configuration.Relays[0].Device // same device name on every relay
	}
	configMu.Unlock()
	if device == "" {
		device = randomDeviceID()
	}

	csrPEM, keyPEM, err := generateCSR(email)
	if err != nil {
		return nil, err
	}
	client, err := enrollmentClient(serverCAPEM, pin, base.String())
	if err != nil {
		return nil, err
	}
	return &enrollTarget{
		name: name, base: base, email: email, device: device, pin: pin,
		serverCAPEM: serverCAPEM, csrPEM: csrPEM, keyPEM: keyPEM, client: client,
	}, nil
}

func (t *enrollTarget) body(extra map[string]string) map[string]string {
	m := map[string]string{"email": t.email, "csr": string(t.csrPEM), "device": t.device}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

// pending builds the record of an enrollment in progress.
func (t *enrollTarget) pending(res enrollResponse, method string) (*pendingEnrollment, error) {
	if res.ID == "" || res.PollToken == "" {
		return nil, errors.New("risposta del relay non valida")
	}
	if res.RelayAddress == "" {
		return nil, errors.New("il relay non ha indicato l'indirizzo mTLS")
	}
	if _, _, err := net.SplitHostPort(res.RelayAddress); err != nil {
		return nil, fmt.Errorf("indirizzo relay non valido: %q", res.RelayAddress)
	}
	expires := res.ExpiresAt
	if expires.IsZero() {
		expires = time.Now().Add(15 * time.Minute)
	}
	return &pendingEnrollment{
		Name:         t.name,
		Method:       method,
		BaseURL:      t.base.String(),
		Email:        t.email,
		Device:       t.device,
		ID:           res.ID,
		PollToken:    res.PollToken,
		CSRPEM:       t.csrPEM,
		KeyPEM:       t.keyPEM,
		ServerCAPEM:  t.serverCAPEM,
		ServerPin:    t.pin,
		RelayCAPEM:   res.RelayCAPEM,
		RelayAddress: res.RelayAddress,
		Expires:      expires,
	}, nil
}

// enrollBegin is how the first request of an enrollment ended: the relay
// sent an e-mail code, or it answered 401 with the ways to sign in.
type enrollBegin struct {
	CodeSent bool           `json:"codeSent"`
	Methods  []enrollMethod `json:"methods,omitempty"`
}

// postJSONStatus is postJSON for answers where the status itself matters: it
// returns the status and the body whatever they are.
func postJSONStatus(client *http.Client, endpoint string, in any) (int, []byte, error) {
	b, err := json.Marshal(in)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(b))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	return resp.StatusCode, body, nil
}

// relayEnroll generates a CSR for email and makes the first enrollment request.
//
// A relay that offers only the e-mail code sends it. A relay that offers
// several ways to sign in answers 401 with the list, and nothing is sent: the
// user picks one and relayEnroll is called again with its method ("email" asks
// for the code). The private key stays in memory until the certificate is
// issued. acceptFingerprint is set when the user explicitly accepted an
// otherwise untrusted server certificate; the connection is then pinned to it.
func relayEnroll(name, address, email, serverCAPEM, acceptFingerprint, method string) (enrollBegin, error) {
	method = strings.ToLower(strings.TrimSpace(method))
	if method != "" && method != "email" {
		return enrollBegin{}, errors.New("questo metodo non si avvia da qui")
	}
	t, err := prepareEnroll(name, address, email, serverCAPEM, acceptFingerprint)
	if err != nil {
		return enrollBegin{}, err
	}
	extra := map[string]string(nil)
	if method != "" {
		extra = map[string]string{"method": method}
	}
	status, body, err := postJSONStatus(t.client, t.base.String()+"/enroll", t.body(extra))
	if err != nil {
		return enrollBegin{}, untrustedOrError(t.base, t.email, t.pin, err)
	}
	switch status {
	case http.StatusOK:
		var res enrollResponse
		if err := json.Unmarshal(body, &res); err != nil {
			return enrollBegin{}, errors.New("risposta del relay non valida")
		}
		p, err := t.pending(res, "code")
		if err != nil {
			return enrollBegin{}, err
		}
		enrollMu.Lock()
		trustPending = nil
		enrollPending = p
		enrollResult = nil
		enrollMu.Unlock()
		return enrollBegin{CodeSent: true}, nil
	case http.StatusUnauthorized:
		// Authentication is required: the body lists the ways to provide it.
		var out struct {
			Error   string         `json:"error"`
			Methods []enrollMethod `json:"methods"`
		}
		if json.Unmarshal(body, &out) != nil {
			return enrollBegin{}, errors.New("il relay richiede l'accesso ma non indica come")
		}
		methods := cleanEnrollMethods(out.Methods)
		if len(methods) == 0 {
			if out.Error != "" {
				return enrollBegin{}, errors.New(out.Error)
			}
			return enrollBegin{}, errors.New("il relay non offre nessun metodo di accesso utilizzabile")
		}
		return enrollBegin{Methods: methods}, nil
	default:
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &e) == nil && e.Error != "" {
			return enrollBegin{}, errors.New(e.Error)
		}
		return enrollBegin{}, fmt.Errorf("relay ha risposto %d", status)
	}
}

// enrollMethod is one way the relay lets a user prove who they are.
type enrollMethod struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Label string `json:"label"`
	// Flow is "code" (a code sent by e-mail), "form" (user name and password
	// typed in the proxy) or "browser" (sign in on the provider's page).
	Flow string `json:"flow"`
}

var enrollMethodIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,29}$`)

// userCodeRe is the shape of the confirmation code, for instance "K7QM-2XPD".
var userCodeRe = regexp.MustCompile(`^[A-Z2-9]{4}-[A-Z2-9]{4}$`)

// cleanEnrollMethods keeps the well-formed entries of a list sent by a relay.
// The list is shown to the user and its ids end up in addresses, so nothing is
// taken on trust.
func cleanEnrollMethods(in []enrollMethod) []enrollMethod {
	var methods []enrollMethod
	for _, m := range in {
		if m.ID != "email" && !enrollMethodIDRe.MatchString(m.ID) {
			continue
		}
		if m.Flow != "code" && m.Flow != "form" && m.Flow != "browser" {
			continue
		}
		if (m.ID == "email") != (m.Flow == "code") {
			continue
		}
		if len(m.Label) > 60 {
			m.Label = m.Label[:60]
		}
		if m.Label == "" {
			m.Label = m.ID
		}
		m.Type = strings.ToLower(m.Type)
		methods = append(methods, m)
	}
	return methods
}

// relayEnrollLogin enrolls with a user name and password typed in the proxy
// (methods password and ldap): the relay answers with the certificate at once.
// The password is sent over the verified (or pinned) connection and kept
// nowhere.
func relayEnrollLogin(name, address, email, serverCAPEM, acceptFingerprint, method, username, password string) error {
	if !enrollMethodIDRe.MatchString(method) {
		return errors.New("metodo non valido")
	}
	if strings.TrimSpace(username) == "" || password == "" {
		return errors.New("indica utente e password")
	}
	t, err := prepareEnroll(name, address, email, serverCAPEM, acceptFingerprint)
	if err != nil {
		return err
	}
	var res confirmResponse
	endpoint := t.base.String() + "/enroll-auth/" + url.PathEscape(method)
	if err := postJSON(t.client, endpoint, "", t.body(map[string]string{"username": username, "password": password}), &res); err != nil {
		return untrustedOrError(t.base, t.email, t.pin, err)
	}
	p := &pendingEnrollment{
		Name: t.name, BaseURL: t.base.String(), Email: t.email, Device: t.device,
		CSRPEM: t.csrPEM, KeyPEM: t.keyPEM, ServerCAPEM: t.serverCAPEM, ServerPin: t.pin,
	}
	enrollMu.Lock()
	trustPending = nil
	enrollMu.Unlock()
	return completeEnrollment(p, res)
}

// relayEnrollStart begins a sign-in on the identity provider's page (OpenID
// Connect, SAML). It returns the address the user must open; the proxy then
// polls the relay until the sign-in is done.
func relayEnrollStart(name, address, email, serverCAPEM, acceptFingerprint, method string) (string, error) {
	if !enrollMethodIDRe.MatchString(method) {
		return "", errors.New("metodo non valido")
	}
	t, err := prepareEnroll(name, address, email, serverCAPEM, acceptFingerprint)
	if err != nil {
		return "", err
	}
	var res struct {
		enrollResponse
		AuthURL  string `json:"authUrl"`
		UserCode string `json:"userCode"`
	}
	endpoint := t.base.String() + "/enroll-auth/" + url.PathEscape(method) + "/start"
	if err := postJSON(t.client, endpoint, "", t.body(nil), &res); err != nil {
		return "", untrustedOrError(t.base, t.email, t.pin, err)
	}
	// The address comes from the relay and will be opened in the browser: only
	// ordinary web addresses are acceptable.
	u, perr := url.Parse(res.AuthURL)
	if perr != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", errors.New("il relay ha indicato un indirizzo di accesso non valido")
	}
	// The code is what ties the sign-in in the browser to this device: the relay
	// asks for it after the identity provider has vouched for the user. It comes
	// from the relay and is shown on screen, so only the expected shape is kept.
	if !userCodeRe.MatchString(res.UserCode) {
		return "", errors.New("il relay non ha indicato il codice di conferma del dispositivo")
	}
	p, err := t.pending(res.enrollResponse, "browser")
	if err != nil {
		return "", err
	}
	p.AuthURL = res.AuthURL
	p.UserCode = res.UserCode
	enrollMu.Lock()
	trustPending = nil
	enrollPending = p
	enrollResult = nil
	enrollMu.Unlock()
	return res.AuthURL, nil
}

var enrollPollMu sync.Mutex

// pollBrowserEnrollment asks the relay whether the user has finished signing
// in and, if so, completes the enrollment. It does nothing for other kinds of
// enrollment.
func pollBrowserEnrollment() {
	enrollPollMu.Lock()
	defer enrollPollMu.Unlock()
	enrollMu.Lock()
	p := enrollPending
	enrollMu.Unlock()
	if p == nil || p.Method != "browser" {
		return
	}
	if time.Now().After(p.Expires) {
		enrollMu.Lock()
		if enrollPending == p {
			enrollPending = nil
		}
		enrollMu.Unlock()
		setEnrollResult(p.Name, "l'accesso è scaduto: riprova")
		return
	}
	client, err := enrollmentClient(p.ServerCAPEM, p.ServerPin, p.BaseURL)
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodGet, p.BaseURL+"/enroll/"+url.PathEscape(p.ID), nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+p.PollToken)
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusGone || resp.StatusCode == http.StatusNotFound {
		enrollMu.Lock()
		if enrollPending == p {
			enrollPending = nil
		}
		enrollMu.Unlock()
		setEnrollResult(p.Name, "l'accesso non è più valido: riprova")
		return
	}
	var st struct {
		Status       string `json:"status"`
		CertPEM      string `json:"certPem"`
		RelayAddress string `json:"relayAddress"`
		RelayCAPEM   string `json:"relayCAPEM"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(&st) != nil {
		return
	}
	if st.Status != "approved" || st.CertPEM == "" {
		return
	}
	if err := completeEnrollment(p, confirmResponse{CertPEM: st.CertPEM, RelayAddress: st.RelayAddress, RelayCAPEM: st.RelayCAPEM}); err != nil {
		log.Printf("Relay %q enrollment could not be completed: %v", p.Name, err)
		enrollMu.Lock()
		if enrollPending == p {
			enrollPending = nil
		}
		enrollMu.Unlock()
		setEnrollResult(p.Name, err.Error())
	}
}

// relayEnrollCancel forgets an enrollment in progress.
func relayEnrollCancel() {
	enrollMu.Lock()
	enrollPending, trustPending, enrollResult = nil, nil, nil
	enrollMu.Unlock()
}

// relayEnrollConfirm sends the code received by e-mail, stores the issued
// certificate in the encrypted configuration and starts the relay client.
func relayEnrollConfirm(code string) error {
	enrollMu.Lock()
	p := enrollPending
	enrollMu.Unlock()
	if p == nil {
		return errors.New("nessuna richiesta di enrollment in corso")
	}
	if p.Method == "browser" {
		return errors.New("questo accesso si completa nel browser, non con un codice")
	}
	if time.Now().After(p.Expires) {
		return errors.New("codice scaduto: richiedine un altro")
	}
	code = strings.ToUpper(strings.TrimSpace(code))
	if code == "" {
		return errors.New("codice mancante")
	}

	client, err := enrollmentClient(p.ServerCAPEM, p.ServerPin, p.BaseURL)
	if err != nil {
		return err
	}
	var res confirmResponse
	endpoint := p.BaseURL + "/enroll/" + url.PathEscape(p.ID) + "/confirm"
	if err := postJSON(client, endpoint, p.PollToken, map[string]string{"code": code}, &res); err != nil {
		return err
	}
	return completeEnrollment(p, res)
}

// completeEnrollment checks the certificate the relay issued, stores it in the
// encrypted configuration and starts the relay client. Whatever the method
// that proved the user's identity, this is the same.
func completeEnrollment(p *pendingEnrollment, res confirmResponse) error {
	if res.CertPEM == "" {
		return errors.New("il relay non ha restituito il certificato")
	}
	if res.RelayAddress == "" {
		res.RelayAddress = p.RelayAddress
	}
	if res.RelayAddress == "" {
		return errors.New("il relay non ha indicato l'indirizzo mTLS")
	}
	if _, _, err := net.SplitHostPort(res.RelayAddress); err != nil {
		return fmt.Errorf("indirizzo relay non valido: %q", res.RelayAddress)
	}

	cert, err := tls.X509KeyPair([]byte(res.CertPEM), p.KeyPEM)
	if err != nil {
		return fmt.Errorf("certificato restituito non valido: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}
	emailOK := false
	for _, e := range leaf.EmailAddresses {
		if v, ok := relay.NormalizeEmail(e); ok && v == p.Email {
			emailOK = true
		}
	}
	if !emailOK {
		return errors.New("il certificato non corrisponde all'indirizzo e-mail")
	}
	if time.Now().After(leaf.NotAfter) {
		return errors.New("il certificato è scaduto")
	}

	configMu.Lock()
	cfg := findRelayConfigLocked(p.Name)
	if cfg == nil {
		cfg = &RelayConfig{Name: p.Name}
		configuration.Relays = append(configuration.Relays, cfg)
	}
	cfg.Address = res.RelayAddress
	cfg.Cert = ""
	cfg.Key = ""
	cfg.CA = ""
	cfg.CertPEM = res.CertPEM
	cfg.KeyPEM = string(p.KeyPEM)
	relayCA := res.RelayCAPEM
	if relayCA == "" {
		relayCA = p.RelayCAPEM
	}
	if relayCA == "" {
		relayCA = p.ServerCAPEM
	}
	cfg.CAPEM = relayCA
	cfg.Device = p.Device
	cfg.EnrollURL = p.BaseURL
	err = persistConfigurationLocked()
	configMu.Unlock()
	if err != nil {
		return err
	}

	enrollMu.Lock()
	if enrollPending == p {
		enrollPending = nil
	}
	enrollMu.Unlock()
	setEnrollResult(p.Name, "")

	relayHub.apply(cfg)
	log.Printf("Relay %q enrollment completed for %s (device %s)", p.Name, p.Email, p.Device)
	return nil
}

func enrollPendingInfo() map[string]any {
	enrollMu.Lock()
	defer enrollMu.Unlock()
	if enrollPending == nil {
		info := map[string]any{"pending": false}
		// How the last enrollment ended, for a couple of minutes.
		if r := enrollResult; r != nil && time.Since(r.At) < 2*time.Minute {
			info["result"] = map[string]any{"name": r.Name, "error": r.Error}
		}
		return info
	}
	return map[string]any{
		"pending":   true,
		"name":      enrollPending.Name,
		"phase":     enrollPending.Method,
		"authUrl":   enrollPending.AuthURL,
		"userCode":  enrollPending.UserCode,
		"email":     enrollPending.Email,
		"address":   enrollPending.BaseURL,
		"expiresAt": enrollPending.Expires,
	}
}
