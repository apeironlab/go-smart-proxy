package relay

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// fakeIdP is an OpenID Connect provider: discovery, authorization with PKCE,
// token endpoint with signed ID tokens, keys and userinfo.
type fakeIdP struct {
	srv *httptest.Server
	key *rsa.PrivateKey

	mu     sync.Mutex
	codes  map[string]idpCode
	claims map[string]any // what the user's ID token says
	// misbehave lets a test corrupt the ID token claims.
	misbehave func(c map[string]any)
	// omitEmail leaves e-mail out of the ID token (it is at userinfo).
	omitEmail bool
	authz     []url.Values
	tokenReqs []tokenRequest
}

// tokenRequest is what the relay sent to the token endpoint.
type tokenRequest struct {
	authHeader string
	form       url.Values
}

type idpCode struct {
	nonce, challenge, clientID string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeIdP{key: key, codes: map[string]idpCode{}, claims: map[string]any{
		"sub": "u1", "email": "alice@example.com", "email_verified": true, "groups": []any{"vpn", "staff"},
	}}
	mux := http.NewServeMux()
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": p.srv.URL, "authorization_endpoint": p.srv.URL + "/authorize", "token_endpoint": p.srv.URL + "/token",
			"jwks_uri": p.srv.URL + "/jwks", "userinfo_endpoint": p.srv.URL + "/userinfo",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported":              []string{"code"}, "subject_types_supported": []string{"public"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &p.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		p.mu.Lock()
		p.authz = append(p.authz, q)
		code := randomToken(12)
		p.codes[code] = idpCode{nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), clientID: q.Get("client_id")}
		p.mu.Unlock()
		back, _ := url.Parse(q.Get("redirect_uri"))
		v := back.Query()
		v.Set("code", code)
		v.Set("state", q.Get("state"))
		back.RawQuery = v.Encode()
		http.Redirect(w, r, back.String(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		p.mu.Lock()
		p.tokenReqs = append(p.tokenReqs, tokenRequest{authHeader: r.Header.Get("Authorization"), form: r.PostForm})
		c, ok := p.codes[r.PostForm.Get("code")]
		delete(p.codes, r.PostForm.Get("code")) // a code works once
		p.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		claims := map[string]any{}
		p.mu.Lock()
		for k, v := range p.claims {
			claims[k] = v
		}
		p.mu.Unlock()
		if p.omitEmail {
			delete(claims, "email")
			delete(claims, "email_verified")
		}
		claims["iss"], claims["aud"], claims["nonce"] = p.srv.URL, c.clientID, c.nonce
		claims["iat"], claims["exp"] = time.Now().Unix(), time.Now().Add(time.Hour).Unix()
		if p.misbehave != nil {
			p.misbehave(claims)
		}
		sig, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: p.key, KeyID: "k1"}}, (&jose.SignerOptions{}).WithType("JWT"))
		raw, err := jwt.Signed(sig).Claims(claims).Serialize()
		if err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 3600, "id_token": raw})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"sub": p.claims["sub"], "email": p.claims["email"], "email_verified": p.claims["email_verified"]})
	})
	return p
}

// page is what a browser gets back from the relay.
type page struct {
	status int
	body   string
	ticket string // the hidden field of the confirmation form, if any
}

var ticketField = regexp.MustCompile(`name="ticket" value="([^"]*)"`)

func newPage(resp *http.Response) page {
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	pg := page{status: resp.StatusCode, body: string(b)}
	if m := ticketField.FindStringSubmatch(pg.body); m != nil {
		pg.ticket = html.UnescapeString(m[1])
	}
	return pg
}

func getPage(t *testing.T, u string) page {
	t.Helper()
	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	return newPage(resp)
}

// verify types the code shown in the proxy into the relay's confirmation page.
func verify(t *testing.T, ts *httptest.Server, method, ticket, code string) page {
	t.Helper()
	resp, err := http.PostForm(ts.URL+"/enroll-auth/"+method+"/verify", url.Values{"ticket": {ticket}, "code": {code}})
	if err != nil {
		t.Fatal(err)
	}
	return newPage(resp)
}

type pollResult struct{ Status, CertPEM string }

func pollStatus(t *testing.T, ts *httptest.Server, id, poll string) pollResult {
	t.Helper()
	req, _ := http.NewRequest("GET", ts.URL+"/enroll/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+poll)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var st pollResult
	json.NewDecoder(resp.Body).Decode(&st)
	return st
}

type browserResult struct {
	status   int
	approved bool
	cert     string
	id       string
	poll     string
	callback string
}

// browserSignIn runs a whole sign-in the way a user's browser would: start,
// authorize at the provider, come back to the callback, then poll.
func browserSignIn(t *testing.T, ts *httptest.Server, method, email string) browserResult {
	t.Helper()
	csr, _ := testCSR(t, email)
	var start struct {
		ID        string `json:"id"`
		PollToken string `json:"pollToken"`
		AuthURL   string `json:"authUrl"`
		UserCode  string `json:"userCode"`
	}
	postJSONTest(t, ts.URL+"/enroll-auth/"+method+"/start", "", map[string]string{"email": email, "csr": string(csr), "device": "laptop"}, &start, 200)
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noRedirect.Get(start.AuthURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	callback := resp.Header.Get("Location")
	if callback == "" {
		t.Fatalf("the provider did not redirect back (status %d)", resp.StatusCode)
	}
	return finishCallback(t, ts, method, start.ID, start.PollToken, callback, start.UserCode)
}

// finishCallback is what the user's browser does after the provider sent it
// back: open the callback and, if the relay asks which device this is, type the
// code shown in the proxy. A refusal at the callback ends there.
func finishCallback(t *testing.T, ts *httptest.Server, method, id, poll, callback, userCode string) browserResult {
	t.Helper()
	pg := getPage(t, callback)
	res := browserResult{status: pg.status, id: id, poll: poll, callback: callback}
	if pg.status == http.StatusOK && pg.ticket != "" {
		res.status = verify(t, ts, method, pg.ticket, userCode).status
	}
	st := pollStatus(t, ts, id, poll)
	res.approved, res.cert = st.Status == "approved", st.CertPEM
	return res
}

func oidcServer(t *testing.T, idp *fakeIdP, tweak func(*OIDCConfig)) (*httptest.Server, *EnrollServer) {
	t.Helper()
	return authServer(t, func(c *EnrollConfig, _ string) {
		oc := &OIDCConfig{Issuer: idp.srv.URL, ClientID: "relay", ClientSecret: "s3cret"}
		if tweak != nil {
			tweak(oc)
		}
		c.Auth = &AuthConfig{Methods: []AuthMethod{{ID: "idp", Type: "oidc", Label: "Company sign-in", OIDC: oc}}}
	})
}

func TestOIDCSignIn(t *testing.T) {
	idp := newFakeIdP(t)
	ts, _ := oidcServer(t, idp, func(c *OIDCConfig) { c.RequireGroups = []string{"vpn"} })

	res := browserSignIn(t, ts, "idp", "alice@example.com")
	if res.status != 200 || !res.approved {
		t.Fatalf("sign-in: status %d approved %v", res.status, res.approved)
	}
	if got := certEmail(t, res.cert); got != "alice@example.com" {
		t.Fatalf("certificate for %q", got)
	}

	// what the provider was asked: authorization code flow with PKCE and a nonce
	idp.mu.Lock()
	q := idp.authz[0]
	idp.mu.Unlock()
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" ||
		q.Get("nonce") == "" || q.Get("state") == "" || q.Get("client_id") != "relay" || q.Get("login_hint") != "alice@example.com" ||
		!strings.Contains(q.Get("scope"), "openid") || !strings.HasSuffix(q.Get("redirect_uri"), "/enroll-auth/idp/callback") {
		t.Fatalf("authorization request: %v", q)
	}

	// the same return cannot be played twice
	again := finishCallback(t, ts, "idp", res.id, res.poll, res.callback, "")
	if again.status != http.StatusForbidden {
		t.Fatalf("a replayed callback must be refused, got %d", again.status)
	}
	if !again.approved {
		t.Fatal("the first approval stays valid")
	}
}

// syncBuf is a log sink that tests can read while the server writes.
type syncBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestOIDCRefusals(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(*fakeIdP)
		tweak   func(*OIDCConfig)
		why     string // what the relay's log must say, so a refusal is for the right reason
	}{
		{"signed in as someone else", func(p *fakeIdP) { p.claims["email"] = "bob@example.com" }, nil, "signed in as bob@example.com"},
		{"wrong nonce", func(p *fakeIdP) { p.misbehave = func(c map[string]any) { c["nonce"] = "other" } }, nil, "wrong nonce"},
		{"wrong audience", func(p *fakeIdP) { p.misbehave = func(c map[string]any) { c["aud"] = "another-app" } }, nil, "ID token"},
		{"wrong issuer", func(p *fakeIdP) { p.misbehave = func(c map[string]any) { c["iss"] = "https://evil.example" } }, nil, "ID token"},
		{"expired token", func(p *fakeIdP) {
			p.misbehave = func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }
		}, nil, "expired"},
		{"unverified e-mail", func(p *fakeIdP) { p.claims["email_verified"] = false }, nil, "not verified"},
		{"not in the required group", func(p *fakeIdP) { p.claims["groups"] = []any{"staff"} }, func(c *OIDCConfig) { c.RequireGroups = []string{"vpn"} }, "required groups"},
		{"no groups at all", func(p *fakeIdP) { delete(p.claims, "groups") }, func(c *OIDCConfig) { c.RequireGroups = []string{"vpn"} }, "required groups"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			idp := newFakeIdP(t)
			c.prepare(idp)
			logs := &syncBuf{}
			ts, _ := authServer(t, func(cfg *EnrollConfig, _ string) {
				oc := &OIDCConfig{Issuer: idp.srv.URL, ClientID: "relay", ClientSecret: "s3cret"}
				if c.tweak != nil {
					c.tweak(oc)
				}
				cfg.Logger = log.New(logs, "", 0)
				cfg.Auth = &AuthConfig{Methods: []AuthMethod{{ID: "idp", Type: "oidc", OIDC: oc}}}
			})
			res := browserSignIn(t, ts, "idp", "alice@example.com")
			if res.status != http.StatusForbidden || res.approved || res.cert != "" {
				t.Fatalf("must be refused without a certificate: status %d approved %v", res.status, res.approved)
			}
			if !strings.Contains(logs.String(), c.why) {
				t.Fatalf("refused, but not for the expected reason %q:\n%s", c.why, logs.String())
			}
		})
	}
}

func TestOIDCOptions(t *testing.T) {
	// an unverified address is accepted only when the operator says so
	idp := newFakeIdP(t)
	idp.claims["email_verified"] = false
	ts, _ := oidcServer(t, idp, func(c *OIDCConfig) { c.AllowUnverifiedEmail = true })
	if res := browserSignIn(t, ts, "idp", "alice@example.com"); !res.approved {
		t.Fatalf("allow_unverified_email: status %d", res.status)
	}

	// e-mail only at the userinfo endpoint
	idp = newFakeIdP(t)
	idp.omitEmail = true
	ts, _ = oidcServer(t, idp, nil)
	if res := browserSignIn(t, ts, "idp", "alice@example.com"); !res.approved {
		t.Fatalf("userinfo fallback: status %d", res.status)
	}

	// another claim name for e-mail and groups
	idp = newFakeIdP(t)
	idp.claims["upn"] = "alice@example.com"
	idp.claims["roles"] = []any{"vpn"}
	idp.claims["email"] = "ignored@example.com"
	ts, _ = oidcServer(t, idp, func(c *OIDCConfig) {
		c.EmailClaim, c.GroupsClaim, c.RequireGroups = "upn", "roles", []string{"vpn"}
	})
	if res := browserSignIn(t, ts, "idp", "alice@example.com"); !res.approved {
		t.Fatalf("custom claims: status %d", res.status)
	}
}

func TestOIDCCallbackProblems(t *testing.T) {
	idp := newFakeIdP(t)
	ts, es := oidcServer(t, idp, nil)
	csr, _ := testCSR(t, "alice@example.com")
	var start struct {
		ID, PollToken string
		AuthURL       string `json:"authUrl"`
	}
	postJSONTest(t, ts.URL+"/enroll-auth/idp/start", "", map[string]string{"email": "alice@example.com", "csr": string(csr)}, &start, 200)
	start.PollToken = ""
	var raw map[string]any
	postJSONTest(t, ts.URL+"/enroll-auth/idp/start", "", map[string]string{"email": "alice@example.com", "csr": string(csr)}, &raw, 200)

	get := func(u string) int {
		resp, err := http.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	cb := ts.URL + "/enroll-auth/idp/callback"
	if c := get(cb); c != http.StatusForbidden {
		t.Errorf("no state: %d", c)
	}
	if c := get(cb + "?state=forged&code=x"); c != http.StatusForbidden {
		t.Errorf("forged state: %d", c)
	}
	if c := get(cb + "?state=&code=x"); c != http.StatusForbidden {
		t.Errorf("empty state: %d", c)
	}

	// the provider says no
	u, _ := url.Parse(raw["authUrl"].(string))
	state := u.Query().Get("state")
	if c := get(cb + "?error=access_denied&state=" + url.QueryEscape(state)); c != http.StatusForbidden {
		t.Errorf("provider refusal: %d", c)
	}
	// ... and the state is spent: a later good answer is no use
	if c := get(cb + "?code=anything&state=" + url.QueryEscape(state)); c != http.StatusForbidden {
		t.Errorf("a used state: %d", c)
	}

	// a state of another method does not work on this one
	es.mu.Lock()
	for _, it := range es.items {
		it.Method = "other"
	}
	es.mu.Unlock()
	u2, _ := url.Parse(start.AuthURL)
	if c := get(cb + "?code=x&state=" + url.QueryEscape(u2.Query().Get("state"))); c != http.StatusForbidden {
		t.Errorf("state of a different method: %d", c)
	}

	// expired
	idp2 := newFakeIdP(t)
	ts2, es2 := oidcServer(t, idp2, nil)
	res := func() browserResult {
		csr, _ := testCSR(t, "alice@example.com")
		var st struct {
			ID, PollToken string
			AuthURL       string `json:"authUrl"`
		}
		postJSONTest(t, ts2.URL+"/enroll-auth/idp/start", "", map[string]string{"email": "alice@example.com", "csr": string(csr)}, &st, 200)
		es2.mu.Lock()
		es2.items[st.ID].Expires = time.Now().Add(-time.Minute)
		es2.mu.Unlock()
		noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		r, _ := noRedirect.Get(st.AuthURL)
		r.Body.Close()
		return finishCallback(t, ts2, "idp", st.ID, st.PollToken, r.Header.Get("Location"), "")
	}()
	if res.status != http.StatusForbidden || res.approved {
		t.Fatalf("an expired sign-in must be refused: %d %v", res.status, res.approved)
	}
}

func TestOIDCStartAndConfirmRules(t *testing.T) {
	idp := newFakeIdP(t)
	ts, _ := oidcServer(t, idp, nil)
	csr, _ := testCSR(t, "alice@example.com")
	var st struct {
		ID        string `json:"id"`
		PollToken string `json:"pollToken"`
	}
	postJSONTest(t, ts.URL+"/enroll-auth/idp/start", "", map[string]string{"email": "alice@example.com", "csr": string(csr)}, &st, 200)
	// the e-mail code cannot be used to confirm a browser sign-in
	postJSONTest(t, ts.URL+"/enroll/"+st.ID+"/confirm", st.PollToken, map[string]string{"code": "AAAA-AAAA"}, nil, http.StatusBadRequest)
	// before the user comes back the status is pending, with no certificate
	req, _ := http.NewRequest("GET", ts.URL+"/enroll/"+st.ID, nil)
	req.Header.Set("Authorization", "Bearer "+st.PollToken)
	resp, _ := http.DefaultClient.Do(req)
	var s struct{ Status, CertPEM string }
	json.NewDecoder(resp.Body).Decode(&s)
	resp.Body.Close()
	if s.Status != "pending" || s.CertPEM != "" {
		t.Fatalf("before sign-in: %+v", s)
	}
	// the password method's form endpoint refuses a browser method and vice versa
	postJSONTest(t, ts.URL+"/enroll-auth/idp", "", map[string]string{"email": "alice@example.com", "csr": string(csr)}, nil, http.StatusBadRequest)
}

func TestOIDCProviderDown(t *testing.T) {
	idp := newFakeIdP(t)
	ts, _ := oidcServer(t, idp, nil)
	idp.srv.Close()
	csr, _ := testCSR(t, "alice@example.com")
	postJSONTest(t, ts.URL+"/enroll-auth/idp/start", "", map[string]string{"email": "alice@example.com", "csr": string(csr)}, nil, http.StatusBadGateway)
}

func TestOIDCPublicClientWithPKCEAndNoRefreshToken(t *testing.T) {
	idp := newFakeIdP(t)
	// no client secret: a public client
	ts, _ := authServer(t, func(c *EnrollConfig, _ string) {
		c.Auth = &AuthConfig{Methods: []AuthMethod{{ID: "idp", Type: "oidc", OIDC: &OIDCConfig{Issuer: idp.srv.URL, ClientID: "public-relay"}}}}
	})
	res := browserSignIn(t, ts, "idp", "alice@example.com")
	if res.status != 200 || !res.approved {
		t.Fatalf("a public client must be able to enroll: status %d approved %v", res.status, res.approved)
	}

	idp.mu.Lock()
	defer idp.mu.Unlock()
	if len(idp.tokenReqs) != 1 {
		t.Fatalf("exactly one request to the token endpoint expected, got %d (a retry means the first style was refused)", len(idp.tokenReqs))
	}
	tr := idp.tokenReqs[0]
	if tr.authHeader != "" {
		t.Errorf("a public client must not authenticate with HTTP Basic, got %q", tr.authHeader)
	}
	if _, has := tr.form["client_secret"]; has {
		t.Errorf("no client secret may be sent: %v", tr.form)
	}
	if tr.form.Get("client_id") != "public-relay" || tr.form.Get("grant_type") != "authorization_code" || tr.form.Get("code_verifier") == "" {
		t.Errorf("token request: %v", tr.form)
	}
	// PKCE with S256, and no ask for a refresh token
	q := idp.authz[0]
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		t.Errorf("PKCE must be used: %v", q)
	}
	for _, sc := range strings.Fields(q.Get("scope")) {
		if sc == "offline_access" {
			t.Errorf("no refresh token is wanted, but offline_access was requested: %q", q.Get("scope"))
		}
	}
	if q.Get("access_type") != "" || q.Get("prompt") != "" {
		t.Errorf("no offline access or forced consent: %v", q)
	}
}

func TestOIDCConfidentialClientStillWorksAndOfflineAccessIsRefused(t *testing.T) {
	idp := newFakeIdP(t)
	ts, _ := oidcServer(t, idp, nil) // with a client secret
	if res := browserSignIn(t, ts, "idp", "alice@example.com"); !res.approved {
		t.Fatalf("a confidential client: %d", res.status)
	}
	idp.mu.Lock()
	hasSecret := false
	for _, tr := range idp.tokenReqs {
		if tr.form.Get("client_secret") == "s3cret" || strings.HasPrefix(tr.authHeader, "Basic ") {
			hasSecret = true
		}
	}
	idp.mu.Unlock()
	if !hasSecret {
		t.Error("when a secret is configured it must be used")
	}

	m := AuthMethod{ID: "x", Type: "oidc", OIDC: &OIDCConfig{Issuer: "https://idp.example.com", ClientID: "c", Scopes: []string{"openid", "email", "offline_access"}}}
	if err := (&AuthConfig{Methods: []AuthMethod{m}}).Validate(); err == nil || !strings.Contains(err.Error(), "offline_access") {
		t.Fatalf("offline_access must be refused: %v", err)
	}
}

// A sign-in link can be sent to somebody else. An attacker starts an
// enrollment for the victim's address with the attacker's own key, then
// persuades the victim to open the link and sign in. Whoever signs in at the
// identity provider must not, by that alone, hand the attacker a certificate.
func TestSigningInForSomeoneElsesEnrollmentGivesThemNothing(t *testing.T) {
	idp := newFakeIdP(t) // the user who signs in is alice@example.com
	ts, _ := oidcServer(t, idp, nil)

	// the attacker starts it, keeping the poll token and the key
	csr, _ := testCSR(t, "alice@example.com")
	var start struct {
		ID        string `json:"id"`
		PollToken string `json:"pollToken"`
		AuthURL   string `json:"authUrl"`
		UserCode  string `json:"userCode"`
	}
	postJSONTest(t, ts.URL+"/enroll-auth/idp/start", "", map[string]string{"email": "alice@example.com", "csr": string(csr)}, &start, 200)
	if start.UserCode == "" {
		t.Fatal("the starter must be given a code to show: it is what ties the sign-in to the device that asked")
	}

	// the victim follows the link and signs in at the provider
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noRedirect.Get(start.AuthURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	page := getPage(t, resp.Header.Get("Location"))
	if page.status != 200 || page.ticket == "" {
		t.Fatalf("after the provider vouches for the user, the relay must still ask for the device's code (status %d)", page.status)
	}

	// the victim does not have the code: whatever they type, nothing is issued
	for _, guess := range []string{"", "AAAA-AAAA", "ZZZZ-9999", "ABCD-EFGH"} {
		if p := verify(t, ts, "idp", page.ticket, guess); p.status == 200 {
			t.Fatalf("a wrong code (%q) must not approve", guess)
		}
	}
	if st := pollStatus(t, ts, start.ID, start.PollToken); st.Status == "approved" || st.CertPEM != "" {
		t.Fatalf("the attacker must get no certificate: %+v", st)
	}
}

// startAndSignIn runs a sign-in up to the confirmation page.
func startAndSignIn(t *testing.T, ts *httptest.Server) (start struct {
	ID        string `json:"id"`
	PollToken string `json:"pollToken"`
	AuthURL   string `json:"authUrl"`
	UserCode  string `json:"userCode"`
}, pg page) {
	t.Helper()
	csr, _ := testCSR(t, "alice@example.com")
	postJSONTest(t, ts.URL+"/enroll-auth/idp/start", "", map[string]string{"email": "alice@example.com", "csr": string(csr), "device": "laptop-1"}, &start, 200)
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noRedirect.Get(start.AuthURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	pg = getPage(t, resp.Header.Get("Location"))
	if pg.status != 200 || pg.ticket == "" {
		t.Fatalf("expected the confirmation page, got %d", pg.status)
	}
	return start, pg
}

func TestDeviceCodeConfirmation(t *testing.T) {
	idp := newFakeIdP(t)
	ts, _ := oidcServer(t, idp, nil)

	start, pg := startAndSignIn(t, ts)
	// the page says who is asking, so someone who was only sent a link can tell
	for _, want := range []string{"alice@example.com", "laptop-1", "127.0.0.1"} {
		if !strings.Contains(pg.body, want) {
			t.Errorf("the confirmation page must show %q", want)
		}
	}
	// the code has the shape the proxy displays
	if matched, _ := regexp.MatchString(`^[A-Z2-9]{4}-[A-Z2-9]{4}$`, start.UserCode); !matched {
		t.Fatalf("user code %q", start.UserCode)
	}
	// still waiting: nothing issued before the code is typed
	if st := pollStatus(t, ts, start.ID, start.PollToken); st.Status != "pending" || st.CertPEM != "" {
		t.Fatalf("before the code: %+v", st)
	}

	// a wrong code says how many tries are left and keeps the form
	wrong := verify(t, ts, "idp", pg.ticket, "AAAA-AAAA")
	if wrong.status != http.StatusForbidden || wrong.ticket != pg.ticket || !strings.Contains(wrong.body, "(4)") {
		t.Fatalf("a wrong code: %d, ticket kept=%v\n%.300s", wrong.status, wrong.ticket == pg.ticket, wrong.body)
	}
	// the code may be typed as the user likes: lower case, without the dash, with spaces
	typed := " " + strings.ToLower(strings.ReplaceAll(start.UserCode, "-", "")) + " "
	if ok := verify(t, ts, "idp", pg.ticket, typed); ok.status != 200 {
		t.Fatalf("the right code, typed loosely: %d", ok.status)
	}
	st := pollStatus(t, ts, start.ID, start.PollToken)
	if st.Status != "approved" || certEmail(t, st.CertPEM) != "alice@example.com" {
		t.Fatalf("after the code: %+v", st)
	}
	// the ticket is good for one use
	if again := verify(t, ts, "idp", pg.ticket, start.UserCode); again.status != http.StatusForbidden {
		t.Fatalf("a ticket used twice: %d", again.status)
	}
}

func TestTooManyWrongDeviceCodesEndTheSignIn(t *testing.T) {
	idp := newFakeIdP(t)
	ts, _ := oidcServer(t, idp, nil)
	start, pg := startAndSignIn(t, ts)
	for i := 0; i < enrollMaxTries; i++ {
		verify(t, ts, "idp", pg.ticket, "AAAA-AAAA")
	}
	// even the right code is useless now: the sign-in is over
	if p := verify(t, ts, "idp", pg.ticket, start.UserCode); p.status == 200 {
		t.Fatal("after too many wrong codes the right one must not work")
	}
	if st := pollStatus(t, ts, start.ID, start.PollToken); st.CertPEM != "" {
		t.Fatalf("no certificate after the lock-out: %+v", st)
	}
}

func TestConfirmationNeedsATicketFromTheProvider(t *testing.T) {
	idp := newFakeIdP(t)
	ts, _ := oidcServer(t, idp, nil)
	csr, _ := testCSR(t, "alice@example.com")
	var start struct {
		ID, PollToken string
		UserCode      string `json:"userCode"`
	}
	postJSONTest(t, ts.URL+"/enroll-auth/idp/start", "", map[string]string{"email": "alice@example.com", "csr": string(csr)}, &start, 200)

	// Knowing the code is not enough: whoever started the enrollment knows it,
	// but a ticket exists only after the provider has vouched for the user.
	for _, ticket := range []string{"", "guess", start.ID, start.PollToken} {
		if p := verify(t, ts, "idp", ticket, start.UserCode); p.status == 200 {
			t.Fatalf("ticket %q must not be accepted", ticket)
		}
	}
	if st := pollStatus(t, ts, start.ID, start.PollToken); st.CertPEM != "" {
		t.Fatalf("a certificate without signing in: %+v", st)
	}
	// a ticket of another method does not work on this one
	_, pg := startAndSignIn(t, ts)
	if p := verify(t, ts, "other", pg.ticket, "AAAA-AAAA"); p.status == 200 {
		t.Fatal("a ticket is for its own method")
	}
}

func TestConfirmationPageIsHardened(t *testing.T) {
	idp := newFakeIdP(t)
	ts, _ := oidcServer(t, idp, nil)
	csr, _ := testCSR(t, "alice@example.com")
	var start struct {
		AuthURL string `json:"authUrl"`
	}
	postJSONTest(t, ts.URL+"/enroll-auth/idp/start", "", map[string]string{"email": "alice@example.com", "csr": string(csr)}, &start, 200)
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, _ := noRedirect.Get(start.AuthURL)
	resp.Body.Close()
	r, err := http.Get(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	h := r.Header
	if h.Get("Cache-Control") != "no-store" || h.Get("Referrer-Policy") != "no-referrer" || h.Get("X-Frame-Options") != "DENY" ||
		!strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors 'none'") ||
		!strings.Contains(h.Get("Content-Security-Policy"), "form-action 'self'") || !strings.Contains(h.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("headers: %v", h)
	}
}
