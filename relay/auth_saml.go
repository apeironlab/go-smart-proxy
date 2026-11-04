package relay

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/crewjam/saml"
)

// SAMLConfig signs users in with SAML 2.0 (SP-initiated, HTTP-Redirect to the
// identity provider and HTTP-POST back). Give the identity provider the
// service provider metadata served at <public-url>/enroll-auth/<id>/metadata.
type SAMLConfig struct {
	// IDPMetadataURL or IDPMetadataFile describe the identity provider.
	IDPMetadataURL  string `yaml:"idp_metadata_url"`
	IDPMetadataFile string `yaml:"idp_metadata_file"`
	// EntityID of this service provider; default the metadata address.
	EntityID string `yaml:"entity_id"`
	// CertFile and KeyFile are an optional signing key pair for authentication
	// requests (and decryption of encrypted assertions).
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	// EmailAttribute is the assertion attribute holding the e-mail address. By
	// default the NameID is used when it looks like an address.
	EmailAttribute string `yaml:"email_attribute"`
	// GroupsAttribute and RequireGroups work as for the other methods.
	GroupsAttribute string   `yaml:"groups_attribute"`
	RequireGroups   []string `yaml:"require_groups"`
}

func (c *SAMLConfig) validate() error {
	if (c.IDPMetadataURL == "") == (c.IDPMetadataFile == "") {
		return errors.New("set exactly one of idp_metadata_url and idp_metadata_file")
	}
	if c.IDPMetadataURL != "" {
		if u, err := url.Parse(c.IDPMetadataURL); err != nil || u.Host == "" || (u.Scheme != "https" && !isLoopbackHost(u.Hostname())) {
			return fmt.Errorf("idp_metadata_url must be an https address (got %q)", c.IDPMetadataURL)
		}
	}
	if (c.CertFile == "") != (c.KeyFile == "") {
		return errors.New("cert_file and key_file go together")
	}
	return nil
}

type samlMethod struct {
	id   string
	cfg  *SAMLConfig
	base string

	mu      sync.Mutex
	sp      *saml.ServiceProvider
	fetched time.Time
}

func newSAMLMethod(id string, cfg *SAMLConfig, base string) *samlMethod {
	return &samlMethod{id: id, cfg: cfg, base: base}
}

func (m *samlMethod) loadMetadata(ctx context.Context) (*saml.EntityDescriptor, error) {
	var raw []byte
	if m.cfg.IDPMetadataFile != "" {
		b, err := os.ReadFile(m.cfg.IDPMetadataFile)
		if err != nil {
			return nil, err
		}
		raw = b
	} else {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.cfg.IDPMetadataURL, nil)
		if err != nil {
			return nil, err
		}
		client := &http.Client{Timeout: authTimeout, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("identity provider metadata: HTTP %d", resp.StatusCode)
		}
		if raw, err = io.ReadAll(io.LimitReader(resp.Body, 4<<20)); err != nil {
			return nil, err
		}
	}
	var ed saml.EntityDescriptor
	if err := xml.Unmarshal(raw, &ed); err != nil {
		// metadata may list several entities
		var eds saml.EntitiesDescriptor
		if err2 := xml.Unmarshal(raw, &eds); err2 != nil || len(eds.EntityDescriptors) == 0 {
			return nil, fmt.Errorf("identity provider metadata: %w", err)
		}
		ed = eds.EntityDescriptors[0]
	}
	return &ed, nil
}

// serviceProvider builds the SP, reading the identity provider's metadata the
// first time and again every hour (certificates rotate).
func (m *samlMethod) serviceProvider(ctx context.Context) (*saml.ServiceProvider, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sp != nil && time.Since(m.fetched) < time.Hour {
		return m.sp, nil
	}
	ed, err := m.loadMetadata(ctx)
	if err != nil {
		if m.sp != nil {
			return m.sp, nil
		}
		return nil, err
	}
	meta, _ := url.Parse(m.base + "/enroll-auth/" + m.id + "/metadata")
	acs, _ := url.Parse(m.base + "/enroll-auth/" + m.id + "/acs")
	sp := &saml.ServiceProvider{
		EntityID:    m.cfg.EntityID,
		MetadataURL: *meta,
		AcsURL:      *acs,
		IDPMetadata: ed,
	}
	if sp.EntityID == "" {
		sp.EntityID = meta.String()
	}
	if m.cfg.CertFile != "" {
		pair, err := tls.LoadX509KeyPair(m.cfg.CertFile, m.cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("saml key pair: %w", err)
		}
		cert, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return nil, err
		}
		signer, ok := pair.PrivateKey.(crypto.Signer)
		if !ok {
			return nil, errors.New("saml key: unsupported key type")
		}
		sp.Key, sp.Certificate = signer, cert
	}
	m.sp, m.fetched = sp, time.Now()
	return sp, nil
}

// Metadata serves the service provider metadata, to give to the identity provider.
func (m *samlMethod) Metadata(ctx context.Context) ([]byte, error) {
	sp, err := m.serviceProvider(ctx)
	if err != nil {
		return nil, err
	}
	return xml.MarshalIndent(sp.Metadata(), "", "  ")
}

func (m *samlMethod) Begin(ctx context.Context, e *Enrollment) (string, error) {
	sp, err := m.serviceProvider(ctx)
	if err != nil {
		return "", err
	}
	idpURL := sp.GetSSOBindingLocation(saml.HTTPRedirectBinding)
	if idpURL == "" {
		return "", errors.New("the identity provider offers no HTTP-Redirect sign-on address")
	}
	req, err := sp.MakeAuthenticationRequest(idpURL, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		return "", err
	}
	e.SAMLRequestID = req.ID
	redirect, err := req.Redirect(e.State, sp)
	if err != nil {
		return "", err
	}
	return redirect.String(), nil
}

func (m *samlMethod) Complete(ctx context.Context, r *http.Request, e *Enrollment) (Identity, error) {
	sp, err := m.serviceProvider(ctx)
	if err != nil {
		return Identity{}, err
	}
	// ParseResponse checks the signature against the identity provider's
	// certificate, the audience, the validity period and that the response
	// answers the request we made (InResponseTo).
	a, err := sp.ParseResponse(r, []string{e.SAMLRequestID})
	if err != nil {
		var ire *saml.InvalidResponseError
		if errors.As(err, &ire) {
			return Identity{}, fmt.Errorf("invalid SAML response: %v", ire.PrivateErr)
		}
		return Identity{}, err
	}
	attrs := map[string][]string{}
	for _, st := range a.AttributeStatements {
		for _, at := range st.Attributes {
			for _, v := range at.Values {
				attrs[at.Name] = append(attrs[at.Name], v.Value)
				if at.FriendlyName != "" {
					attrs[at.FriendlyName] = append(attrs[at.FriendlyName], v.Value)
				}
			}
		}
	}
	email := ""
	if m.cfg.EmailAttribute != "" {
		if v := attrs[m.cfg.EmailAttribute]; len(v) > 0 {
			email = v[0]
		}
	} else if a.Subject != nil && a.Subject.NameID != nil && strings.Contains(a.Subject.NameID.Value, "@") {
		email = a.Subject.NameID.Value
	}
	if email == "" {
		return Identity{}, errors.New("the assertion carries no e-mail address (set email_attribute)")
	}
	return Identity{Email: email, Groups: attrs[m.cfg.GroupsAttribute]}, nil
}
