package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/apeironlab/go-smart-proxy/relay"
)

// The certificate is renewed by the proxy, over the connection it secures,
// when it enters the last part of its life: no code, no sign-in. The relay
// decides whether to allow it (see relay/renew.go).

// Variables so that tests can speed them up.
var (
	renewFirstCheck atomic.Int64 // time.Duration
	renewEvery      atomic.Int64
)

func init() {
	renewFirstCheck.Store(int64(20 * time.Second))
	renewEvery.Store(int64(6 * time.Hour))
}

// certDeviceOf returns the device a relay's certificate is bound to.
func certDeviceOf(cfg *RelayConfig) string {
	cert, err := relayCertificate(cfg)
	if err != nil || len(cert.Certificate) == 0 {
		return ""
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return ""
	}
	return relay.DeviceFromCert(leaf)
}

// renewLoop checks the certificate while the session lasts.
func (r *relayClient) renewLoop(sess *yamux.Session, leaf *x509.Certificate) {
	t := time.NewTimer(time.Duration(renewFirstCheck.Load()))
	defer t.Stop()
	for {
		select {
		case <-sess.CloseChan():
			return
		case <-t.C:
		}
		if err := r.renewIfDue(sess, leaf); err != nil {
			log.Printf("relay %q: certificate renewal: %v", r.name, err)
		} else if time.Until(leaf.NotAfter) <= relay.RenewWindow(leaf.NotBefore, leaf.NotAfter) {
			return // renewed: the session is being replaced
		}
		t.Reset(time.Duration(renewEvery.Load()))
	}
}

// renewIfDue asks the relay for a new certificate when the one in use is in its
// renewal window, and switches to it.
func (r *relayClient) renewIfDue(sess *yamux.Session, leaf *x509.Certificate) error {
	if time.Until(leaf.NotAfter) > relay.RenewWindow(leaf.NotBefore, leaf.NotAfter) {
		return nil
	}
	email, ok := relay.EmailFromCert(leaf)
	if !ok {
		return errors.New("the certificate has no e-mail identity")
	}
	csr, key, err := generateCSR(email)
	if err != nil {
		return err
	}
	st, err := sess.OpenStream()
	if err != nil {
		return err
	}
	defer st.Close()
	if err := relay.WriteLine(st, relay.RenewReq{T: relay.TRenew, CSR: string(csr)}); err != nil {
		return err
	}
	st.SetReadDeadline(time.Now().Add(30 * time.Second))
	var resp relay.RenewResp
	if err := relay.ReadLine(relay.NewReader(st), &resp); err != nil {
		return fmt.Errorf("no answer (a relay that predates renewal closes the stream): %w", err)
	}
	if !resp.OK {
		return errors.New(resp.Error)
	}
	// Never switch to something that does not work: it must be for us, for
	// this device, from the key we made, and newer than the one we have.
	pair, err := tls.X509KeyPair([]byte(resp.CertPEM), key)
	if err != nil {
		return fmt.Errorf("the new certificate does not match the key: %w", err)
	}
	nl, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	if e, _ := relay.EmailFromCert(nl); e != email {
		return errors.New("the new certificate is for another address")
	}
	if d := relay.DeviceFromCert(leaf); d != "" && relay.DeviceFromCert(nl) != d {
		return errors.New("the new certificate is for another device")
	}
	if !nl.NotAfter.After(leaf.NotAfter) {
		return errors.New("the new certificate does not last longer")
	}

	configMu.Lock()
	cfg := findRelayConfigLocked(r.name)
	if cfg == nil {
		configMu.Unlock()
		return errors.New("relay no longer configured")
	}
	old := *cfg
	cfg.Cert, cfg.Key = "", ""
	cfg.CertPEM, cfg.KeyPEM = resp.CertPEM, string(key)
	if cfg.CAPEM == "" && old.CA != "" {
		// keep trusting the CA that was in a file
		if b, err := relay.ReadPEMFile(old.CA); err == nil {
			cfg.CAPEM = b
			cfg.CA = ""
		}
	}
	err = persistConfigurationLocked()
	if err != nil {
		*cfg = old
	}
	configMu.Unlock()
	if err != nil {
		return fmt.Errorf("cannot save the new certificate: %w", err)
	}
	log.Printf("relay %q: certificate renewed (valid until %s)", r.name, nl.NotAfter.Format("2006-01-02"))
	relayHub.apply(cfg) // reconnects with it
	return nil
}
