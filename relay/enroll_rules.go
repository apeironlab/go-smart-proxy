package relay

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// SMTPRules is the outgoing mail setup that can be edited at run time.
type SMTPRules struct {
	Addr string `json:"addr"`
	User string `json:"user"`
	Pass string `json:"pass,omitempty"`
	From string `json:"from"`
	TLS  string `json:"tls"`  // starttls, tls or none
	Auth string `json:"auth"` // auto, plain, login or none
}

// EnrollRules are the enrollment rules the management interface can change
// while the relay runs. They start from the configuration; once saved in the
// database they take precedence over it.
type EnrollRules struct {
	AllowedDomains []string `json:"allowedDomains"`
	CertTTLHours   int      `json:"certTtlHours"`
	// RequireGroups replaces the groups required by a method (by method id).
	RequireGroups map[string][]string `json:"requireGroups"`
	// DisabledMethods are method ids (including "email") switched off.
	DisabledMethods []string  `json:"disabledMethods"`
	SMTP            SMTPRules `json:"smtp"`
}

const rulesSetting = "enroll_rules"

func (s *EnrollServer) initialRules() EnrollRules {
	c := s.cfg
	r := EnrollRules{
		AllowedDomains:  append([]string{}, c.AllowedDomains...),
		CertTTLHours:    int(c.CertTTL / time.Hour),
		RequireGroups:   map[string][]string{},
		DisabledMethods: []string{},
		SMTP:            SMTPRules{Addr: c.SMTPAddr, User: c.SMTPUser, Pass: c.SMTPPass, From: c.SMTPFrom, TLS: c.SMTPTLS, Auth: c.SMTPAuth},
	}
	if r.CertTTLHours <= 0 {
		r.CertTTLHours = 90 * 24
		if c.CertTTL > 0 {
			r.CertTTLHours = 1 // shorter than an hour: keep to the minimum the rules can express
		}
	}
	if c.Auth != nil && c.Auth.DisableEmail {
		r.DisabledMethods = append(r.DisabledMethods, "email")
	}
	return r
}

// Rules returns a copy of the rules in force.
func (s *EnrollServer) Rules() EnrollRules {
	s.rulesMu.RLock()
	defer s.rulesMu.RUnlock()
	r := s.rules
	r.AllowedDomains = append([]string{}, r.AllowedDomains...)
	r.DisabledMethods = append([]string{}, r.DisabledMethods...)
	r.RequireGroups = map[string][]string{}
	for k, v := range s.rules.RequireGroups {
		r.RequireGroups[k] = append([]string{}, v...)
	}
	return r
}

// ValidateRules checks rules before they are applied.
func (s *EnrollServer) ValidateRules(r EnrollRules) error {
	if r.CertTTLHours < 1 || r.CertTTLHours > 5*365*24 {
		return errors.New("the certificate lifetime must be between 1 hour and 5 years")
	}
	for _, d := range r.AllowedDomains {
		d = strings.TrimPrefix(strings.TrimSpace(d), "@")
		if d == "" || strings.ContainsAny(d, " @/") || !strings.Contains(d, ".") && d != "localhost" {
			return fmt.Errorf("invalid domain %q", d)
		}
	}
	enabled := 0
	known := map[string]bool{"email": true}
	for id := range s.methods {
		known[id] = true
	}
	off := map[string]bool{}
	for _, id := range r.DisabledMethods {
		if !known[id] {
			return fmt.Errorf("unknown method %q", id)
		}
		off[id] = true
	}
	for id := range known {
		if !off[id] {
			enabled++
		}
	}
	if enabled == 0 {
		return errors.New("at least one sign-in method must stay enabled")
	}
	if !off["email"] {
		if r.SMTP.Addr == "" && s.cfg.SendMail == nil {
			return errors.New("the e-mail code needs an SMTP server")
		}
		if r.SMTP.Addr != "" {
			if _, _, err := net.SplitHostPort(r.SMTP.Addr); err != nil {
				return errors.New("the SMTP address must be host:port")
			}
		}
		if r.SMTP.From == "" && s.cfg.SendMail == nil {
			return errors.New("the e-mail code needs a sender address")
		}
	}
	switch strings.ToLower(r.SMTP.TLS) {
	case "", "starttls", "tls", "none":
	default:
		return errors.New("SMTP security must be starttls, tls or none")
	}
	switch strings.ToLower(r.SMTP.Auth) {
	case "", "auto", "plain", "login", "none":
	default:
		return errors.New("SMTP authentication must be auto, plain, login or none")
	}
	for id := range r.RequireGroups {
		if s.methods[id] == nil {
			return fmt.Errorf("method %q has no groups to set", id)
		}
	}
	return nil
}

// SetRules applies the rules and, when the management interface is enabled,
// keeps them in its database so that they survive a restart.
func (s *EnrollServer) SetRules(r EnrollRules) error {
	if err := s.ValidateRules(r); err != nil {
		return err
	}
	cleaned := []string{}
	for _, d := range r.AllowedDomains {
		if d = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(d), "@")); d != "" {
			cleaned = append(cleaned, d)
		}
	}
	r.AllowedDomains = cleaned
	if r.RequireGroups == nil {
		r.RequireGroups = map[string][]string{}
	}
	if s.cfg.Admin != nil {
		if err := s.cfg.Admin.db.setSetting(rulesSetting, r); err != nil {
			return err
		}
	}
	s.rulesMu.Lock()
	s.rules = r
	s.rulesMu.Unlock()
	return nil
}

func (s *EnrollServer) loadSavedRules() error {
	if s.cfg.Admin == nil {
		return nil
	}
	var r EnrollRules
	ok, err := s.cfg.Admin.db.getSetting(rulesSetting, &r)
	if err != nil || !ok {
		return err
	}
	if r.RequireGroups == nil {
		r.RequireGroups = map[string][]string{}
	}
	if err := s.ValidateRules(r); err != nil {
		// Do not refuse to start over saved settings that no longer fit the
		// configuration (e.g. a method that was removed): keep the configured ones.
		s.log.Printf("WARNING: the enrollment rules saved in the database are ignored: %v", err)
		return nil
	}
	s.rulesMu.Lock()
	s.rules = r
	s.rulesMu.Unlock()
	return nil
}

func (s *EnrollServer) isOff(id string) bool {
	s.rulesMu.RLock()
	defer s.rulesMu.RUnlock()
	for _, d := range s.rules.DisabledMethods {
		if d == id {
			return true
		}
	}
	return false
}

func (s *EnrollServer) emailDisabled() bool { return s.isOff("email") }

func (s *EnrollServer) methodDisabled(id string) bool { return s.isOff(id) }

// requiredGroups are the groups a user of method m must belong to.
func (s *EnrollServer) requiredGroups(m *methodEntry) []string {
	s.rulesMu.RLock()
	defer s.rulesMu.RUnlock()
	if g, ok := s.rules.RequireGroups[m.ID]; ok {
		return g
	}
	return m.requireGroups()
}

// mailConfig is the configuration used to send mail: the one from the file
// with the SMTP rules in force on top.
func (s *EnrollServer) mailConfig() EnrollConfig {
	c := s.cfg
	r := s.Rules()
	c.SMTPAddr, c.SMTPUser, c.SMTPPass, c.SMTPFrom, c.SMTPTLS, c.SMTPAuth =
		r.SMTP.Addr, r.SMTP.User, r.SMTP.Pass, r.SMTP.From, r.SMTP.TLS, r.SMTP.Auth
	return c
}

func (s *EnrollServer) certTTL() time.Duration {
	s.rulesMu.RLock()
	defer s.rulesMu.RUnlock()
	return time.Duration(s.rules.CertTTLHours) * time.Hour
}

// sign issues a certificate for an authenticated request and records it.
func (s *EnrollServer) sign(csr []byte, email, device, method, ip string) (string, error) {
	return s.signFor(csr, email, device, method, ip, time.Time{}, true)
}

// signFor issues a certificate bound to the device. origin is when the chain of
// renewals started, a zero time for a fresh sign-in; notify says whether the
// owner is e-mailed about a new device.
func (s *EnrollServer) signFor(csr []byte, email, device, method, ip string, origin time.Time, notify bool) (string, error) {
	signed, err := SignCSRForDevice(s.cfg.CADir, csr, email, device, s.certTTL())
	if err != nil {
		return "", err
	}
	if origin.IsZero() {
		origin = time.Now()
	}
	if method == "" {
		method = "email"
	}
	serial, notAfter := "", time.Time{}
	if block, _ := pem.Decode(signed); block != nil {
		if c, err := x509.ParseCertificate(block.Bytes); err == nil {
			serial, notAfter = strings.ToLower(c.SerialNumber.Text(16)), c.NotAfter
		}
	}
	if a := s.cfg.Admin; a != nil && serial != "" {
		if err := a.db.recordCert(CertRecord{Serial: serial, Email: email, Device: device, Method: method, Issued: time.Now(), Expires: notAfter}); err != nil {
			s.log.Printf("recording the certificate of %s: %v", email, err)
		}
	}
	s.audit("enroll.issued", email, serial, method)
	CounterInc("gsp_relay_enrollments_total", "method", method)
	if serial != "" {
		s.recordIssued(&IssuedCert{Serial: serial, Email: email, Device: device, Method: method, IP: ip, Issued: time.Now(), Expires: notAfter, Origin: origin})
	}
	if notify {
		s.notifyDevice(email, device, method, ip, notAfter)
	}
	return string(signed), nil
}

// audit writes an entry to the management interface's log, if it is enabled.
func (s *EnrollServer) audit(kind, actor, subject, detail string) {
	emitEvent(kind, actor, subject, detail)
	if s.cfg.Admin != nil {
		s.cfg.Admin.store(kind, actor, subject, detail)
	}
}
