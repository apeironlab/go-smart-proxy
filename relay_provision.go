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
	"strings"
	"sync"
	"time"

	"proxy/relay"
)

type pendingEnrollment struct {
	Name         string // the relay entry being created or renewed
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
)

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

// relayEnroll generates a CSR for email and asks the relay to send a
// confirmation code. The private key stays in memory until confirmation.
// acceptFingerprint is set when the user explicitly accepted an otherwise
// untrusted server certificate; the connection is then pinned to it.
func relayEnroll(name, address, email, serverCAPEM, acceptFingerprint string) error {
	name = strings.ToLower(strings.TrimSpace(name))
	if name != "" && !validRelayName(name) {
		return errors.New("nome del relay non valido (minuscole, cifre, - e _)")
	}
	email, ok := relay.NormalizeEmail(email)
	if !ok {
		return errors.New("indirizzo e-mail non valido")
	}
	base, err := normalizeEnrollURL(address)
	if err != nil {
		return err
	}

	pin := ""
	if acceptFingerprint != "" {
		enrollMu.Lock()
		trust := trustPending
		enrollMu.Unlock()
		if trust == nil || time.Now().After(trust.Expires) ||
			trust.Email != email || trust.BaseURL != base.String() ||
			normalizeFingerprint(trust.Fingerprint) != normalizeFingerprint(acceptFingerprint) {
			return errors.New("certificato non più valido: richiedi di nuovo l'enrollment")
		}
		pin = trust.Fingerprint
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
		return errors.New("troppi relay configurati")
	} else if len(configuration.Relays) > 0 {
		device = configuration.Relays[0].Device // same device name on every relay
	}
	configMu.Unlock()
	if device == "" {
		device = randomDeviceID()
	}

	csrPEM, keyPEM, err := generateCSR(email)
	if err != nil {
		return err
	}
	client, err := enrollmentClient(serverCAPEM, pin, base.String())
	if err != nil {
		return err
	}
	var res enrollResponse
	if err := postJSON(client, base.String()+"/enroll", "", map[string]string{
		"email":  email,
		"csr":    string(csrPEM),
		"device": device,
	}, &res); err != nil {
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
	if res.ID == "" || res.PollToken == "" {
		return errors.New("risposta del relay non valida")
	}
	if res.RelayAddress == "" {
		return errors.New("il relay non ha indicato l'indirizzo mTLS")
	}
	if _, _, err := net.SplitHostPort(res.RelayAddress); err != nil {
		return fmt.Errorf("indirizzo relay non valido: %q", res.RelayAddress)
	}
	expires := res.ExpiresAt
	if expires.IsZero() {
		expires = time.Now().Add(15 * time.Minute)
	}

	enrollMu.Lock()
	trustPending = nil
	enrollPending = &pendingEnrollment{
		Name:         name,
		BaseURL:      base.String(),
		Email:        email,
		Device:       device,
		ID:           res.ID,
		PollToken:    res.PollToken,
		CSRPEM:       csrPEM,
		KeyPEM:       keyPEM,
		ServerCAPEM:  serverCAPEM,
		ServerPin:    pin,
		RelayCAPEM:   res.RelayCAPEM,
		RelayAddress: res.RelayAddress,
		Expires:      expires,
	}
	enrollMu.Unlock()
	return nil
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
	if res.CertPEM == "" {
		return errors.New("il relay non ha restituito il certificato")
	}
	if res.RelayAddress == "" {
		res.RelayAddress = p.RelayAddress
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

	relayHub.apply(cfg)
	log.Printf("Relay %q enrollment completed for %s (device %s)", p.Name, p.Email, p.Device)
	return nil
}

func enrollPendingInfo() map[string]any {
	enrollMu.Lock()
	defer enrollMu.Unlock()
	if enrollPending == nil {
		return map[string]any{"pending": false}
	}
	return map[string]any{
		"pending":   true,
		"name":      enrollPending.Name,
		"email":     enrollPending.Email,
		"address":   enrollPending.BaseURL,
		"expiresAt": enrollPending.Expires,
	}
}
