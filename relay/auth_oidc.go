package relay

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCConfig signs users in with OpenID Connect (authorization code flow with
// PKCE) with any OpenID Connect provider.
//
// Register the relay as a **public client** of the provider (no client secret),
// with the redirect address <public-url>/enroll-auth/<id>/callback (or
// redirect_url below). PKCE is what protects the exchange. The sign-in is only
// used to learn the user's e-mail address for enrollment, so no refresh token
// is asked for (no offline_access scope) and no token is kept: the ID token is
// checked once and thrown away.
type OIDCConfig struct {
	Issuer string `yaml:"issuer"` // https://login.example.com/realms/corp
	// ClientID identifies the relay to the provider. ClientSecret is for
	// providers that insist on a confidential client; leave it out for a public
	// client, which is the recommended setup: then only the client id and the
	// PKCE verifier are sent to the token endpoint.
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	// RedirectURL overrides the address the provider sends the user back to.
	RedirectURL string   `yaml:"redirect_url"`
	Scopes      []string `yaml:"scopes"`      // default: openid, email, profile
	EmailClaim  string   `yaml:"email_claim"` // default email
	// AllowUnverifiedEmail accepts an e-mail the provider has not verified.
	// Leave it off unless the provider is the only source of truth for e-mail.
	AllowUnverifiedEmail bool `yaml:"allow_unverified_email"`
	// GroupsClaim is the claim listing the user's groups (default groups), and
	// RequireGroups, when set, lets in only members of at least one of them.
	GroupsClaim   string   `yaml:"groups_claim"`
	RequireGroups []string `yaml:"require_groups"`
}

func (c *OIDCConfig) defaults() {
	if len(c.Scopes) == 0 {
		c.Scopes = []string{oidc.ScopeOpenID, "email", "profile"}
	}
	if c.EmailClaim == "" {
		c.EmailClaim = "email"
	}
	if c.GroupsClaim == "" {
		c.GroupsClaim = "groups"
	}
}

func (c *OIDCConfig) validate() error {
	c.defaults()
	u, err := url.Parse(c.Issuer)
	if err != nil || u.Host == "" || (u.Scheme != "https" && !isLoopbackHost(u.Hostname())) {
		return fmt.Errorf("issuer must be an https address (got %q)", c.Issuer)
	}
	if strings.TrimSpace(c.ClientID) == "" {
		return errors.New("client_id is required")
	}
	for _, sc := range c.Scopes {
		if sc == "offline_access" {
			return errors.New("offline_access is not needed (and not allowed): the sign-in is used once for enrollment, no refresh token is wanted")
		}
	}
	if len(c.RequireGroups) > 0 && c.GroupsClaim == "" {
		return errors.New("require_groups needs groups_claim")
	}
	return nil
}

func isLoopbackHost(h string) bool { return h == "localhost" || h == "127.0.0.1" || h == "::1" }

type oidcMethod struct {
	id   string
	cfg  *OIDCConfig
	base string // public address of the enrollment endpoint

	mu       sync.Mutex
	provider *oidc.Provider
	fetched  time.Time
}

func newOIDCMethod(id string, cfg *OIDCConfig, base string) *oidcMethod {
	cfg.defaults()
	return &oidcMethod{id: id, cfg: cfg, base: base}
}

func (m *oidcMethod) redirectURL() string {
	if m.cfg.RedirectURL != "" {
		return m.cfg.RedirectURL
	}
	return m.base + "/enroll-auth/" + m.id + "/callback"
}

// discover returns the provider, reading its discovery document the first time
// (and again every hour, so rotated endpoints are picked up).
func (m *oidcMethod) discover(ctx context.Context) (*oidc.Provider, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.provider != nil && time.Since(m.fetched) < time.Hour {
		return m.provider, nil
	}
	p, err := oidc.NewProvider(ctx, m.cfg.Issuer)
	if err != nil {
		if m.provider != nil {
			return m.provider, nil // keep working with the last good document
		}
		return nil, fmt.Errorf("OpenID provider %s: %w", m.cfg.Issuer, err)
	}
	m.provider, m.fetched = p, time.Now()
	return p, nil
}

func (m *oidcMethod) oauth(p *oidc.Provider) *oauth2.Config {
	endpoint := p.Endpoint()
	if m.cfg.ClientSecret == "" {
		// A public client authenticates with nothing but its client id, in the
		// form body. Left to guess, the library would first try HTTP Basic
		// with an empty secret, which public clients are often refused.
		endpoint.AuthStyle = oauth2.AuthStyleInParams
	}
	return &oauth2.Config{
		ClientID:     m.cfg.ClientID,
		ClientSecret: m.cfg.ClientSecret,
		Endpoint:     endpoint,
		RedirectURL:  m.redirectURL(),
		Scopes:       m.cfg.Scopes,
	}
}

func (m *oidcMethod) Begin(ctx context.Context, e *Enrollment) (string, error) {
	p, err := m.discover(ctx)
	if err != nil {
		return "", err
	}
	e.Nonce = randomToken(24)
	e.Verifier = oauth2.GenerateVerifier()
	opts := []oauth2.AuthCodeOption{
		oauth2.S256ChallengeOption(e.Verifier),
		oidc.Nonce(e.Nonce),
		oauth2.SetAuthURLParam("login_hint", e.Email),
	}
	return m.oauth(p).AuthCodeURL(e.State, opts...), nil
}

func (m *oidcMethod) Complete(ctx context.Context, r *http.Request, e *Enrollment) (Identity, error) {
	q := r.URL.Query()
	if perr := q.Get("error"); perr != "" {
		return Identity{}, fmt.Errorf("the provider refused the sign-in: %s %s", perr, q.Get("error_description"))
	}
	code := q.Get("code")
	if code == "" {
		return Identity{}, errors.New("no authorization code")
	}
	p, err := m.discover(ctx)
	if err != nil {
		return Identity{}, err
	}
	tok, err := m.oauth(p).Exchange(ctx, code, oauth2.VerifierOption(e.Verifier))
	if err != nil {
		return Identity{}, fmt.Errorf("code exchange: %w", err)
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return Identity{}, errors.New("the provider returned no ID token")
	}
	idt, err := p.Verifier(&oidc.Config{ClientID: m.cfg.ClientID}).Verify(ctx, raw)
	if err != nil {
		return Identity{}, fmt.Errorf("ID token: %w", err)
	}
	if idt.Nonce != e.Nonce {
		return Identity{}, errors.New("ID token: wrong nonce")
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		return Identity{}, err
	}
	// Some providers leave e-mail and groups out of the ID token and serve
	// them at the userinfo endpoint.
	if _, ok := claims[m.cfg.EmailClaim]; !ok {
		if ui, err := p.UserInfo(ctx, oauth2.StaticTokenSource(tok)); err == nil {
			var extra map[string]any
			if ui.Claims(&extra) == nil {
				for k, v := range extra {
					if _, have := claims[k]; !have {
						claims[k] = v
					}
				}
			}
		}
	}
	email, _ := claims[m.cfg.EmailClaim].(string)
	if email == "" {
		return Identity{}, fmt.Errorf("the provider did not send the %q claim", m.cfg.EmailClaim)
	}
	if !m.cfg.AllowUnverifiedEmail {
		if verified, ok := claims["email_verified"]; ok {
			switch v := verified.(type) {
			case bool:
				if !v {
					return Identity{}, errors.New("the provider has not verified this e-mail address")
				}
			case string:
				if v != "true" {
					return Identity{}, errors.New("the provider has not verified this e-mail address")
				}
			}
		}
	}
	return Identity{Email: email, Groups: stringList(claims[m.cfg.GroupsClaim])}, nil
}

// stringList reads a claim that is a string or a list of strings.
func stringList(v any) []string {
	switch t := v.(type) {
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return t
	}
	return nil
}
