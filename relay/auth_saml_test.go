package relay

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"html"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/logger"
)

// fakeSAMLIdP is a SAML identity provider (the library's own) with one user
// "signed in" whose attributes the test sets.
type fakeSAMLIdP struct {
	srv  *httptest.Server
	idp  *saml.IdentityProvider
	meta string // path of the metadata file

	mu      sync.Mutex
	session saml.Session
}

func selfSigned(t *testing.T, cn string) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return key, cert
}

type staticSession struct{ p *fakeSAMLIdP }

func (s staticSession) GetSession(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
	s.p.mu.Lock()
	defer s.p.mu.Unlock()
	sess := s.p.session
	sess.ID, sess.CreateTime, sess.ExpireTime, sess.Index = randomToken(8), time.Now(), time.Now().Add(time.Hour), randomToken(8)
	return &sess
}

type spLookup struct {
	enrollURL *string
	method    string
}

func (l spLookup) GetServiceProvider(r *http.Request, id string) (*saml.EntityDescriptor, error) {
	resp, err := http.Get(*l.enrollURL + "/enroll-auth/" + l.method + "/metadata")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var ed saml.EntityDescriptor
	if err := xml.Unmarshal(raw, &ed); err != nil {
		return nil, err
	}
	return &ed, nil
}

func newFakeSAMLIdP(t *testing.T, enrollURL *string, method string) *fakeSAMLIdP {
	t.Helper()
	key, cert := selfSigned(t, "idp.example.com")
	p := &fakeSAMLIdP{session: saml.Session{NameID: "alice@example.com", NameIDFormat: string(saml.EmailAddressNameIDFormat), UserEmail: "alice@example.com"}}
	mux := http.NewServeMux()
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	base, _ := url.Parse(p.srv.URL)
	p.idp = &saml.IdentityProvider{
		Key: key, Certificate: cert,
		MetadataURL:             url.URL{Scheme: base.Scheme, Host: base.Host, Path: "/metadata"},
		SSOURL:                  url.URL{Scheme: base.Scheme, Host: base.Host, Path: "/sso"},
		ServiceProviderProvider: spLookup{enrollURL: enrollURL, method: method},
		SessionProvider:         staticSession{p},
		Logger:                  logger.DefaultLogger,
	}
	mux.HandleFunc("/sso", p.idp.ServeSSO)
	meta, err := xml.Marshal(p.idp.Metadata())
	if err != nil {
		t.Fatal(err)
	}
	p.meta = filepath.Join(t.TempDir(), "idp-metadata.xml")
	if err := os.WriteFile(p.meta, meta, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func (p *fakeSAMLIdP) setUser(email string, attrs map[string][]string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.session = saml.Session{NameID: email, NameIDFormat: string(saml.EmailAddressNameIDFormat)}
	if strings.Contains(email, "@") {
		p.session.UserEmail = email
	}
	for name, vals := range attrs {
		p.session.CustomAttributes = append(p.session.CustomAttributes, saml.Attribute{
			Name: name, FriendlyName: name,
			Values: func() []saml.AttributeValue {
				var out []saml.AttributeValue
				for _, v := range vals {
					out = append(out, saml.AttributeValue{Type: "xs:string", Value: v})
				}
				return out
			}(),
		})
	}
}

var samlField = regexp.MustCompile(`name="(SAMLResponse|RelayState)"\s+value="([^"]*)"`)

type samlRound struct {
	start struct {
		ID        string `json:"id"`
		PollToken string `json:"pollToken"`
		AuthURL   string `json:"authUrl"`
	}
	response, relayState string
}

// beginSAML starts an enrollment and walks it to the identity provider, which
// answers with the form a browser would post back.
func beginSAML(t *testing.T, ts *httptest.Server, method, email string) *samlRound {
	t.Helper()
	csr, _ := testCSR(t, email)
	r := &samlRound{}
	postJSONTest(t, ts.URL+"/enroll-auth/"+method+"/start", "", map[string]string{"email": email, "csr": string(csr), "device": "laptop"}, &r.start, 200)
	resp, err := http.Get(r.start.AuthURL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	for _, m := range samlField.FindAllStringSubmatch(string(body), -1) {
		if m[1] == "SAMLResponse" {
			r.response = html.UnescapeString(m[2])
		} else {
			r.relayState = html.UnescapeString(m[2])
		}
	}
	if r.response == "" {
		t.Fatalf("the identity provider returned no SAML response (status %d): %.300s", resp.StatusCode, body)
	}
	return r
}

func (r *samlRound) post(t *testing.T, ts *httptest.Server, method, response, relayState string) browserResult {
	t.Helper()
	resp, err := http.PostForm(ts.URL+"/enroll-auth/"+method+"/acs", url.Values{"SAMLResponse": {response}, "RelayState": {relayState}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	res := browserResult{status: resp.StatusCode}
	req, _ := http.NewRequest("GET", ts.URL+"/enroll/"+r.start.ID, nil)
	req.Header.Set("Authorization", "Bearer "+r.start.PollToken)
	sresp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer sresp.Body.Close()
	var st struct{ Status, CertPEM string }
	jsonDecode(sresp.Body, &st)
	res.approved, res.cert = st.Status == "approved", st.CertPEM
	return res
}

func samlServer(t *testing.T, tweak func(*SAMLConfig)) (*httptest.Server, *fakeSAMLIdP, *syncBuf, *EnrollServer) {
	t.Helper()
	var enrollURL string
	idp := newFakeSAMLIdP(t, &enrollURL, "sso")
	logs := &syncBuf{}
	ts, es := authServer(t, func(c *EnrollConfig, _ string) {
		sc := &SAMLConfig{IDPMetadataFile: idp.meta}
		if tweak != nil {
			tweak(sc)
		}
		c.Logger = log.New(logs, "", 0)
		c.Auth = &AuthConfig{Methods: []AuthMethod{{ID: "sso", Type: "saml", Label: "Company SSO", SAML: sc}}}
	})
	enrollURL = ts.URL
	return ts, idp, logs, es
}

func mustURL(s string) url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return *u
}

func TestSAMLMetadataIsServed(t *testing.T) {
	ts, _, _, _ := samlServer(t, nil)
	resp, err := http.Get(ts.URL + "/enroll-auth/sso/metadata")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var ed saml.EntityDescriptor
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || xml.Unmarshal(raw, &ed) != nil {
		t.Fatalf("metadata: %d %.200s", resp.StatusCode, raw)
	}
	if ed.EntityID != ts.URL+"/enroll-auth/sso/metadata" || len(ed.SPSSODescriptors) != 1 ||
		ed.SPSSODescriptors[0].AssertionConsumerServices[0].Location != ts.URL+"/enroll-auth/sso/acs" {
		t.Fatalf("entity %q: %+v", ed.EntityID, ed.SPSSODescriptors)
	}
	// only SAML methods have metadata
	idpOIDC := newFakeIdP(t)
	ts2, _ := oidcServer(t, idpOIDC, nil)
	if resp, _ := http.Get(ts2.URL + "/enroll-auth/idp/metadata"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("an OIDC method has no SAML metadata: %d", resp.StatusCode)
	}
}

func TestSAMLSignIn(t *testing.T) {
	ts, _, _, _ := samlServer(t, nil)
	r := beginSAML(t, ts, "sso", "alice@example.com")
	res := r.post(t, ts, "sso", r.response, r.relayState)
	if res.status != 200 || !res.approved {
		t.Fatalf("sign-in: status %d approved %v", res.status, res.approved)
	}
	if got := certEmail(t, res.cert); got != "alice@example.com" {
		t.Fatalf("certificate for %q", got)
	}
	// the same response, played again, finds nothing
	if again := r.post(t, ts, "sso", r.response, r.relayState); again.status != http.StatusForbidden {
		t.Fatalf("a replayed response must be refused, got %d", again.status)
	}
}

func TestSAMLAttributesAndGroups(t *testing.T) {
	ts, idp, logs, _ := samlServer(t, func(c *SAMLConfig) {
		c.EmailAttribute, c.GroupsAttribute, c.RequireGroups = "mail", "memberOf", []string{"vpn"}
	})
	// the NameID is opaque: the address is in an attribute
	idp.setUser("opaque-id-123", map[string][]string{"mail": {"alice@example.com"}, "memberOf": {"staff", "vpn"}})
	r := beginSAML(t, ts, "sso", "alice@example.com")
	if res := r.post(t, ts, "sso", r.response, r.relayState); !res.approved {
		t.Fatalf("attribute-based identity: status %d\n%s", res.status, logs.String())
	}
}

func TestSAMLRefusals(t *testing.T) {
	cases := []struct {
		name  string
		user  func(*fakeSAMLIdP)
		tweak func(*SAMLConfig)
		why   string
	}{
		{"signed in as someone else", func(p *fakeSAMLIdP) { p.setUser("bob@example.com", nil) }, nil, "signed in as bob@example.com"},
		{"not in the required group", func(p *fakeSAMLIdP) {
			p.setUser("alice@example.com", map[string][]string{"groups": {"staff"}})
		}, func(c *SAMLConfig) { c.GroupsAttribute, c.RequireGroups = "groups", []string{"vpn"} }, "required groups"},
		{"no e-mail anywhere", func(p *fakeSAMLIdP) { p.setUser("opaque-id", nil) }, nil, "no e-mail address"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ts, idp, logs, _ := samlServer(t, c.tweak)
			c.user(idp)
			r := beginSAML(t, ts, "sso", "alice@example.com")
			res := r.post(t, ts, "sso", r.response, r.relayState)
			if res.status != http.StatusForbidden || res.approved {
				t.Fatalf("must be refused: status %d approved %v", res.status, res.approved)
			}
			if !strings.Contains(logs.String(), c.why) {
				t.Fatalf("refused, but not for the expected reason %q:\n%s", c.why, logs.String())
			}
		})
	}
}

func TestSAMLForgeries(t *testing.T) {
	ts, realIdP, logs, es := samlServer(t, nil)

	// 1. a response that was altered after signing
	r := beginSAML(t, ts, "sso", "alice@example.com")
	raw, _ := base64.StdEncoding.DecodeString(r.response)
	tampered := strings.Replace(string(raw), "alice@example.com", "mallory@example.com", -1)
	if tampered == string(raw) {
		t.Fatal("the test response does not contain the address to alter")
	}
	if res := r.post(t, ts, "sso", base64.StdEncoding.EncodeToString([]byte(tampered)), r.relayState); res.status != http.StatusForbidden || res.approved {
		t.Fatalf("a tampered response must be refused: %d", res.status)
	}

	// 2. a valid response of one sign-in, handed over with the state of another
	a := beginSAML(t, ts, "sso", "alice@example.com")
	b := beginSAML(t, ts, "sso", "alice@example.com")
	if res := b.post(t, ts, "sso", a.response, b.relayState); res.status != http.StatusForbidden || res.approved {
		t.Fatalf("a response to another request (InResponseTo) must be refused: %d", res.status)
	}

	// 3. a response from an identity provider the relay does not trust, which
	// answers the very request the relay made (InResponseTo is right, the
	// audience and destination are right: only the signing key is wrong)
	fe := ""
	evil := newFakeSAMLIdP(t, &fe, "sso")
	fe = ts.URL
	// it even claims to be the real identity provider: only its key gives it away
	evil.idp.MetadataURL = realIdP.idp.MetadataURL
	c := beginSAML(t, ts, "sso", "alice@example.com")
	es.mu.Lock()
	realRequestID := es.items[c.start.ID].SAMLRequestID
	es.mu.Unlock()
	if realRequestID == "" {
		t.Fatal("the relay did not remember the request id")
	}
	helper := saml.ServiceProvider{
		EntityID:    ts.URL + "/enroll-auth/sso/metadata",
		MetadataURL: mustURL(ts.URL + "/enroll-auth/sso/metadata"),
		AcsURL:      mustURL(ts.URL + "/enroll-auth/sso/acs"),
		IDPMetadata: evil.idp.Metadata(),
	}
	areq, err := helper.MakeAuthenticationRequest(evil.idp.SSOURL.String(), saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		t.Fatal(err)
	}
	areq.ID = realRequestID
	redirect, err := areq.Redirect(c.relayState, &helper)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := http.Get(redirect.String())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(forged.Body)
	forged.Body.Close()
	var evilResponse string
	for _, m := range samlField.FindAllStringSubmatch(string(body), -1) {
		if m[1] == "SAMLResponse" {
			evilResponse = html.UnescapeString(m[2])
		}
	}
	if evilResponse == "" {
		t.Fatalf("the untrusted provider produced no response: %.300s", body)
	}
	if res := c.post(t, ts, "sso", evilResponse, c.relayState); res.status != http.StatusForbidden || res.approved {
		t.Fatalf("a response signed by an unknown key must be refused: %d", res.status)
	}

	// 4. no state, or not a response at all
	if res := c.post(t, ts, "sso", "AAAA", ""); res.status != http.StatusForbidden {
		t.Fatalf("no state: %d", res.status)
	}
	if res := c.post(t, ts, "sso", "not base64!", c.relayState); res.status != http.StatusForbidden {
		t.Fatalf("garbage: %d", res.status)
	}
	log := logs.String()
	for _, want := range []string{
		"cannot validate signature on Response", // the altered response and the untrusted key
		"`InResponseTo` does not match",         // somebody else's request
		"unknown or expired state",              // no state, replays
	} {
		if !strings.Contains(log, want) {
			t.Errorf("the log must say %q:\n%s", want, log)
		}
	}
	if n := strings.Count(log, "cannot validate signature on Response"); n < 2 {
		t.Errorf("both the altered response and the untrusted key must fail on the signature, saw %d:\n%s", n, log)
	}
}

func TestSAMLIdentityProviderUnreachable(t *testing.T) {
	ts, idp, _, _ := samlServer(t, nil)
	_ = idp
	// metadata file removed after start: the first use cannot read it
	dir := t.TempDir()
	cfg := &SAMLConfig{IDPMetadataFile: filepath.Join(dir, "missing.xml")}
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	ts2, _ := authServer(t, func(c *EnrollConfig, _ string) {
		c.Auth = &AuthConfig{Methods: []AuthMethod{{ID: "sso", Type: "saml", SAML: cfg}}}
	})
	csr, _ := testCSR(t, "alice@example.com")
	postJSONTest(t, ts2.URL+"/enroll-auth/sso/start", "", map[string]string{"email": "alice@example.com", "csr": string(csr)}, nil, http.StatusBadGateway)
	_ = ts
}
