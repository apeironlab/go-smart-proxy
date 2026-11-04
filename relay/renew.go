package relay

import (
	"errors"
	"fmt"
	"time"
)

// Certificates are renewed over the connection they secure, without a new
// sign-in: the proxy sends a request for a new certificate (a new key) on the
// mTLS connection, and the relay issues it when
//
//   - the certificate in use is not revoked and its user is still allowed (the
//     domain list applies as at enrollment);
//   - it is in the last part of its life (a third of it, at least a week), so
//     a stolen certificate cannot be swapped for fresh ones at will;
//   - the chain of renewals started less than MaxRenewAge ago (a year by
//     default): after that the user must sign in again, which is when an
//     identity provider gets to say the account was disabled.
//
// The new certificate is bound to the same device. The old one stays valid
// until it expires or is revoked: the proxy needs it for a moment, and a
// failed renewal must leave it working.

// DefaultMaxRenewAge is how long certificates can be renewed without a sign-in.
const DefaultMaxRenewAge = 365 * 24 * time.Hour

// RenewWindow is how long before expiry a certificate may be renewed.
func RenewWindow(notBefore, notAfter time.Time) time.Duration {
	w := notAfter.Sub(notBefore) / 3
	if w < 7*24*time.Hour {
		w = 7 * 24 * time.Hour
	}
	if full := notAfter.Sub(notBefore); w > full {
		w = full
	}
	return w
}

// originOf finds when the sign-in behind a certificate happened.
func (s *EnrollServer) originOf(serial string, fallback time.Time) time.Time {
	if s.shared() {
		return s.sqlOriginOf(serial, fallback)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.certs {
		if c.Serial == serial {
			if !c.Origin.IsZero() {
				return c.Origin
			}
			return c.Issued
		}
	}
	return fallback
}

// RenewCertificate is Server.Renewer.
func (s *EnrollServer) RenewCertificate(c RenewContext, csrPEM []byte) (string, error) {
	now := time.Now()
	if !allowedDomain(c.Email, s.Rules().AllowedDomains) {
		return "", errors.New("this address is no longer allowed: sign in again")
	}
	if s.cfg.Revoked.IsRevoked(c.Email, c.Serial) {
		return "", errors.New("the certificate is revoked")
	}
	if remaining := c.NotAfter.Sub(now); remaining > RenewWindow(c.NotBefore, c.NotAfter) {
		return "", fmt.Errorf("too early: the certificate can be renewed from %s", c.NotAfter.Add(-RenewWindow(c.NotBefore, c.NotAfter)).Format("2006-01-02"))
	}
	maxAge := s.cfg.MaxRenewAge
	if maxAge <= 0 {
		maxAge = DefaultMaxRenewAge
	}
	// A certificate issued before the ledger existed counts from its start.
	origin := s.originOf(c.Serial, c.NotBefore.Add(time.Hour))
	if now.Sub(origin) > maxAge {
		return "", errors.New("it is time to sign in again")
	}
	if !s.allow("renew:"+c.Email+"/"+c.Device, 6) {
		return "", errors.New("too many requests")
	}
	cert, err := s.signFor(csrPEM, c.Email, c.Device, "renewal", c.Addr, origin, false)
	if err != nil {
		return "", err
	}
	s.audit("cert.renew", c.Email, c.Device, "replaces "+c.Serial)
	s.notifyRenewal(c.Email, c.Device, c.Addr)
	return cert, nil
}

// notifyRenewal tells the owner a certificate was renewed, so that a renewal
// they did not expect does not go unnoticed.
func (s *EnrollServer) notifyRenewal(email, device, ip string) {
	if !s.canMail() {
		return
	}
	body := fmt.Sprintf("Ciao,\n\nil certificato del dispositivo %s associato a %s è stato rinnovato automaticamente (da %s).\n"+
		"Non devi fare nulla. Se non te lo aspettavi, revoca i certificati del tuo indirizzo", orDash(device), email, orDash(ip))
	if u := s.revokeURL(email); u != "" {
		body += ": " + u
	}
	body += "\n\n---\n\nHello,\n\nthe certificate of device " + orDash(device) + " of " + email + " was renewed automatically. If you did not expect it, revoke your certificates."
	if u := s.revokeURL(email); u != "" {
		body += " " + u
	}
	go func() {
		if err := s.send(email, "Go Smart Proxy: certificato rinnovato / certificate renewed", body+"\n"); err != nil {
			s.log.Printf("renewal notice to %s failed: %v", email, err)
		}
	}()
}
