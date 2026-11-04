package relay

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Enrollment can prove who a user is in several ways. The relay always offers
// the e-mail code (it can be switched off); an AuthConfig adds any of:
//
//   - password: local users with bcrypt hashes, typed in a form in the proxy;
//   - ldap:     a directory (LDAP, Active Directory), also typed in the form;
//   - oidc:     OpenID Connect, in the browser (any OpenID Connect provider);
//   - saml:     SAML 2.0 in the browser.
//
// Whatever the method, its only job is to establish the e-mail address of the
// user, and optionally the groups they belong to. The certificate that is then
// issued, and everything after it, works exactly as with the e-mail code.

// AuthConfig lists the enrollment methods a relay offers.
type AuthConfig struct {
	// DisableEmail removes the e-mail code: only the methods below remain.
	DisableEmail bool         `yaml:"disable_email"`
	Methods      []AuthMethod `yaml:"methods"`
}

// AuthMethod is one way of authenticating. Exactly one of Password, LDAP,
// OIDC and SAML is set, matching Type.
type AuthMethod struct {
	ID    string `yaml:"id"`    // short name used in URLs: lowercase letters, digits, - and _
	Type  string `yaml:"type"`  // password, ldap, oidc or saml
	Label string `yaml:"label"` // what the user sees on the button

	Password *PasswordConfig `yaml:"password,omitempty"`
	LDAP     *LDAPConfig     `yaml:"ldap,omitempty"`
	OIDC     *OIDCConfig     `yaml:"oidc,omitempty"`
	SAML     *SAMLConfig     `yaml:"saml,omitempty"`
}

// Identity is what a method established about the user.
type Identity struct {
	Email  string
	Groups []string
}

// ErrInvalidCredentials is returned for a wrong user name or password. The
// caller must not say which of the two was wrong.
var ErrInvalidCredentials = errors.New("invalid credentials")

// credentialMethod authenticates a user name and password typed in a form.
type credentialMethod interface {
	Authenticate(ctx context.Context, username, password string) (Identity, error)
}

// browserMethod authenticates the user in their browser: Begin returns the
// address to send them to, Complete handles the return of the identity
// provider and says who signed in.
type browserMethod interface {
	Begin(ctx context.Context, e *Enrollment) (authURL string, err error)
	Complete(ctx context.Context, r *http.Request, e *Enrollment) (Identity, error)
}

var authIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,29}$`)

// LoadAuthConfig reads an AuthConfig from a YAML file. ${VAR} references are
// replaced with environment variables, so secrets (client secrets, service
// account passwords) need not be written in the file.
func LoadAuthConfig(path string) (*AuthConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg AuthConfig
	dec := yaml.NewDecoder(strings.NewReader(os.ExpandEnv(string(b))))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &cfg, nil
}

// Validate checks the configuration without contacting anything.
func (c *AuthConfig) Validate() error {
	if c == nil {
		return nil
	}
	seen := map[string]bool{"email": true}
	for i, m := range c.Methods {
		if !authIDRe.MatchString(m.ID) {
			return fmt.Errorf("auth method %d: invalid id %q (lowercase letters, digits, - and _)", i+1, m.ID)
		}
		if seen[m.ID] {
			return fmt.Errorf("auth method %q: duplicate (or reserved) id", m.ID)
		}
		seen[m.ID] = true
		set := 0
		for _, ok := range []bool{m.Password != nil, m.LDAP != nil, m.OIDC != nil, m.SAML != nil} {
			if ok {
				set++
			}
		}
		if set != 1 {
			return fmt.Errorf("auth method %q: set exactly one of password, ldap, oidc, saml", m.ID)
		}
		var err error
		switch m.Type {
		case "password":
			if m.Password == nil {
				err = errors.New("type password needs a password section")
			} else {
				err = m.Password.validate()
			}
		case "ldap":
			if m.LDAP == nil {
				err = errors.New("type ldap needs an ldap section")
			} else {
				err = m.LDAP.validate()
			}
		case "oidc":
			if m.OIDC == nil {
				err = errors.New("type oidc needs an oidc section")
			} else {
				err = m.OIDC.validate()
			}
		case "saml":
			if m.SAML == nil {
				err = errors.New("type saml needs a saml section")
			} else {
				err = m.SAML.validate()
			}
		default:
			err = fmt.Errorf("unknown type %q (password, ldap, oidc or saml)", m.Type)
		}
		if err != nil {
			return fmt.Errorf("auth method %q: %w", m.ID, err)
		}
	}
	return nil
}

// label is what the user sees for a method.
func (m AuthMethod) label() string {
	if strings.TrimSpace(m.Label) != "" {
		return m.Label
	}
	switch m.Type {
	case "password":
		return "Password"
	case "ldap":
		return "Directory login"
	case "oidc":
		return "Single sign-on"
	case "saml":
		return "SAML sign-on"
	}
	return m.ID
}

// groupMatches reports whether any of have satisfies any of need. A group
// matches case-insensitively, either as a whole or, for a directory
// distinguished name ("CN=vpn-users,OU=Groups,DC=example,DC=com"), by its CN.
// An empty need matches everyone.
func groupMatches(have, need []string) bool {
	if len(need) == 0 {
		return true
	}
	for _, h := range have {
		hl := strings.ToLower(strings.TrimSpace(h))
		cn := ""
		if strings.HasPrefix(hl, "cn=") {
			cn = strings.TrimPrefix(strings.SplitN(hl, ",", 2)[0], "cn=")
		}
		for _, n := range need {
			nl := strings.ToLower(strings.TrimSpace(n))
			if nl != "" && (nl == hl || nl == cn) {
				return true
			}
		}
	}
	return false
}

// requireGroupsOf returns the group requirement of a method.
func (m AuthMethod) requireGroups() []string {
	switch {
	case m.LDAP != nil:
		return m.LDAP.RequireGroups
	case m.OIDC != nil:
		return m.OIDC.RequireGroups
	case m.SAML != nil:
		return m.SAML.RequireGroups
	case m.Password != nil:
		return m.Password.RequireGroups
	}
	return nil
}

// authTimeout bounds the calls to a directory or an identity provider.
const authTimeout = 15 * time.Second
