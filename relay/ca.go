package relay

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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

// SignCSR signs a client certificate request for email. The identity in the
// certificate always comes from the verified e-mail; the CSR must ask for the
// same identity, and its signature and public key are validated.
func SignCSR(caDir string, csrPEM []byte, email string, ttl time.Duration) ([]byte, error) {
	email, ok := NormalizeEmail(email)
	if !ok {
		return nil, fmt.Errorf("invalid e-mail address")
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("invalid certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate request: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid certificate request signature: %w", err)
	}
	identity := false
	for _, e := range csr.EmailAddresses {
		if v, ok := NormalizeEmail(e); ok && v == email {
			identity = true
			break
		}
	}
	if !identity {
		if v, ok := NormalizeEmail(csr.Subject.CommonName); ok && v == email {
			identity = true
		}
	}
	if !identity {
		return nil, errors.New("the certificate request is for a different e-mail address")
	}
	switch pub := csr.PublicKey.(type) {
	case *rsa.PublicKey:
		if pub.N.BitLen() < 2048 {
			return nil, errors.New("RSA key too small")
		}
	case *ecdsa.PublicKey:
		if pub.Curve != elliptic.P256() && pub.Curve != elliptic.P384() {
			return nil, errors.New("unsupported elliptic curve")
		}
	case ed25519.PublicKey:
	default:
		return nil, errors.New("unsupported public key type")
	}

	ca, caPriv, err := loadCA(caDir)
	if err != nil {
		return nil, err
	}
	if ttl <= 0 {
		ttl = 90 * 24 * time.Hour
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: email},
		EmailAddresses:        []string{email},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, csr.PublicKey, caPriv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
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

// gatewayURIPrefix marks the certificate of an application gateway: its
// identity is a URI, never an e-mail address, and enrollment cannot produce
// one (SignCSR copies only the e-mail identity), so no user can pose as a gateway.
const gatewayURIPrefix = "urn:gsp:gateway:"

// GatewayFromCert returns the id of the gateway a certificate belongs to.
func GatewayFromCert(c *x509.Certificate) (string, bool) {
	for _, u := range c.URIs {
		if id, ok := strings.CutPrefix(u.String(), gatewayURIPrefix); ok && authIDRe.MatchString(id) {
			return id, true
		}
	}
	return "", false
}

// GatewayCredentials is a freshly issued gateway certificate.
type GatewayCredentials struct {
	CertPEM, KeyPEM, CAPEM []byte
	Serial                 string // lowercase hex
	NotAfter               time.Time
}

// NewGatewayCredentials issues the certificate of the application gateway id,
// valid for ttl.
func NewGatewayCredentials(caDir, id string, ttl time.Duration) (*GatewayCredentials, error) {
	if !authIDRe.MatchString(id) {
		return nil, errors.New("invalid gateway id (lowercase letters, digits, - and _)")
	}
	ca, caPriv, err := loadCA(caDir)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	u, _ := url.Parse(gatewayURIPrefix + id)
	tpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "gateway " + id},
		URIs:        []*url.URL{u},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(ttl),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caPriv)
	if err != nil {
		return nil, err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(filepath.Join(caDir, caFile))
	if err != nil {
		return nil, err
	}
	return &GatewayCredentials{
		CertPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:   pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}),
		CAPEM:    caPEM,
		Serial:   strings.ToLower(tpl.SerialNumber.Text(16)),
		NotAfter: tpl.NotAfter,
	}, nil
}

// IssueGateway writes a gateway certificate, its key and the CA into outDir
// (gateway.pem, gateway-key.pem, ca.pem).
func IssueGateway(caDir, outDir, id string) error {
	c, err := NewGatewayCredentials(caDir, id, leafTTL)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return err
	}
	for name, data := range map[string][]byte{"gateway.pem": c.CertPEM, "gateway-key.pem": c.KeyPEM, caFile: c.CAPEM} {
		mode := os.FileMode(0o644)
		if name == "gateway-key.pem" {
			mode = 0o600
		}
		if err := os.WriteFile(filepath.Join(outDir, name), data, mode); err != nil {
			return err
		}
	}
	return nil
}
