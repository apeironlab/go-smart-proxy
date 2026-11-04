package relay

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	return finishCallback(t, ts, start.ID, start.PollToken, callback)
}

func finishCallback(t *testing.T, ts *httptest.Server, id, poll, callback string) browserResult {
	t.Helper()
	resp, err := http.Get(callback)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	res := browserResult{status: resp.StatusCode, id: id, poll: poll, callback: callback}
	req, _ := http.NewRequest("GET", ts.URL+"/enroll/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+poll)
	sresp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer sresp.Body.Close()
	var st struct {
		Status  string `json:"status"`
		CertPEM string `json:"certPem"`
	}
	json.NewDecoder(sresp.Body).Decode(&st)
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
	again := finishCallback(t, ts, res.id, res.poll, res.callback)
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
		return finishCallback(t, ts2, st.ID, st.PollToken, r.Header.Get("Location"))
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
