package relay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	caFile  = "ca.pem"
	caKey   = "ca-key.pem"
	caYears = 10
	leafTTL = 2 * 365 * 24 * time.Hour
)

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), mode)
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	return n.Add(n, big.NewInt(1))
}

// InitCA creates a new certificate authority in dir (ca.pem, ca-key.pem).
func InitCA(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(dir, caKey)); err == nil {
		return errors.New("a CA already exists in " + dir)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "proxy relay CA", Organization: []string{"proxy relay"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(caYears, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(dir, caFile), "CERTIFICATE", der, 0o644); err != nil {
		return err
	}
	return writePEM(filepath.Join(dir, caKey), "EC PRIVATE KEY", kb, 0o600)
}

func loadCA(dir string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	tc, err := tls.LoadX509KeyPair(filepath.Join(dir, caFile), filepath.Join(dir, caKey))
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(tc.Certificate[0])
	if err != nil {
		return nil, nil, err
	}
	key, ok := tc.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("unsupported CA key type")
	}
	return cert, key, nil
}

func issue(caDir, outDir, prefix string, tpl *x509.Certificate) error {
	ca, caPriv, err := loadCA(caDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tpl.SerialNumber = serial()
	tpl.NotBefore = time.Now().Add(-time.Hour)
	tpl.NotAfter = time.Now().Add(leafTTL)
	tpl.KeyUsage = x509.KeyUsageDigitalSignature
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caPriv)
	if err != nil {
		return err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(outDir, prefix+".pem"), "CERTIFICATE", der, 0o644); err != nil {
		return err
	}
	if err := writePEM(filepath.Join(outDir, prefix+"-key.pem"), "EC PRIVATE KEY", kb, 0o600); err != nil {
		return err
	}
	b, err := os.ReadFile(filepath.Join(caDir, caFile))
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outDir, caFile), b, 0o644)
}

// IssueClient issues a client certificate whose identity is the e-mail address.
func IssueClient(caDir, outDir, email string) error {
	email, ok := NormalizeEmail(email)
	if !ok {
		return fmt.Errorf("invalid e-mail address")
	}
	return issue(caDir, outDir, "client", &x509.Certificate{
		Subject:        pkix.Name{CommonName: email},
		EmailAddresses: []string{email},
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
}

// IssueServer issues the relay's server certificate for the given host names / IPs.
func IssueServer(caDir, outDir string, hosts []string) error {
	if len(hosts) == 0 {
		return errors.New("at least one host is required")
	}
	tpl := &x509.Certificate{
		Subject:     pkix.Name{CommonName: hosts[0]},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, h)
		}
	}
	return issue(caDir, outDir, "server", tpl)
}

// LoadPool loads a PEM bundle of CA certificates.
func LoadPool(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("%s: no certificates found", path)
	}
	return pool, nil
}
