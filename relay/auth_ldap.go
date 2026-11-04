package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// LDAPConfig authenticates users against a directory (OpenLDAP, Active
// Directory, FreeIPA...). The relay finds the user with a search, then checks
// the password by binding as them, so the password never touches the relay's
// own storage.
type LDAPConfig struct {
	// URL is ldaps://host:636, or ldap://host:389 together with StartTLS.
	URL      string `yaml:"url"`
	StartTLS bool   `yaml:"start_tls"`
	// AllowPlaintext permits ldap:// without TLS. Passwords then cross the
	// network in clear: only for a lab.
	AllowPlaintext bool `yaml:"allow_plaintext"`
	// CAFile is a PEM bundle used to verify the directory's certificate, when
	// it is not signed by a public CA.
	CAFile             string `yaml:"ca_file"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`

	// BindDN and BindPassword are the service account that searches for the
	// user. Leave them empty only if the directory allows anonymous searches.
	BindDN       string `yaml:"bind_dn"`
	BindPassword string `yaml:"bind_password"`
	BaseDN       string `yaml:"base_dn"`
	// UserFilter finds the user; %s is the user name typed in the form, escaped.
	// Default (uid=%s). For Active Directory: (&(objectClass=user)(sAMAccountName=%s)).
	UserFilter string `yaml:"user_filter"`
	EmailAttr  string `yaml:"email_attr"` // default mail
	GroupAttr  string `yaml:"group_attr"` // default memberOf
	// RequireGroups, when set, lets in only members of at least one of them
	// (a group name, or the CN of a memberOf entry).
	RequireGroups []string `yaml:"require_groups"`
}

func (c *LDAPConfig) defaults() {
	if c.UserFilter == "" {
		c.UserFilter = "(uid=%s)"
	}
	if c.EmailAttr == "" {
		c.EmailAttr = "mail"
	}
	if c.GroupAttr == "" {
		c.GroupAttr = "memberOf"
	}
}

func (c *LDAPConfig) validate() error {
	c.defaults()
	u, err := url.Parse(c.URL)
	if err != nil || u.Host == "" || (u.Scheme != "ldap" && u.Scheme != "ldaps") {
		return fmt.Errorf("url must look like ldaps://host:636 (got %q)", c.URL)
	}
	if u.Scheme == "ldap" && !c.StartTLS && !c.AllowPlaintext {
		return errors.New("an ldap:// url needs start_tls: true (or allow_plaintext: true for a lab): passwords must not cross the network in clear")
	}
	if strings.TrimSpace(c.BaseDN) == "" {
		return errors.New("base_dn is required")
	}
	if strings.Count(c.UserFilter, "%s") != 1 {
		return errors.New(`user_filter must contain %s exactly once, for example (uid=%s)`)
	}
	if c.BindDN != "" && c.BindPassword == "" {
		return errors.New("bind_dn is set without bind_password")
	}
	return nil
}

type ldapMethod struct {
	cfg *LDAPConfig
	tls *tls.Config
}

func newLDAPMethod(cfg *LDAPConfig) (*ldapMethod, error) {
	cfg.defaults()
	u, _ := url.Parse(cfg.URL)
	tlsCfg := &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.InsecureSkipVerify}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_file %s: no certificates found", cfg.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	return &ldapMethod{cfg: cfg, tls: tlsCfg}, nil
}

// userFilter is the search filter for a user name typed in the form. The name
// is escaped, so characters such as * ( ) \ can never change the meaning of
// the filter (LDAP injection).
func (m *ldapMethod) userFilter(username string) string {
	return strings.Replace(m.cfg.UserFilter, "%s", ldap.EscapeFilter(username), 1)
}

func (m *ldapMethod) connect() (*ldap.Conn, error) {
	opts := []ldap.DialOpt{ldap.DialWithDialer(&net.Dialer{Timeout: authTimeout})}
	if strings.HasPrefix(m.cfg.URL, "ldaps://") {
		opts = append(opts, ldap.DialWithTLSConfig(m.tls))
	}
	l, err := ldap.DialURL(m.cfg.URL, opts...)
	if err != nil {
		return nil, err
	}
	l.SetTimeout(authTimeout)
	if m.cfg.StartTLS && strings.HasPrefix(m.cfg.URL, "ldap://") {
		if err := l.StartTLS(m.tls); err != nil {
			l.Close()
			return nil, fmt.Errorf("start TLS: %w", err)
		}
	}
	return l, nil
}

func (m *ldapMethod) Authenticate(_ context.Context, username, password string) (Identity, error) {
	username = strings.TrimSpace(username)
	// An empty password would make many directories accept an anonymous bind
	// as a successful login: never let it through.
	if username == "" || password == "" || len(username) > 256 || len(password) > 1024 {
		return Identity{}, ErrInvalidCredentials
	}
	l, err := m.connect()
	if err != nil {
		return Identity{}, fmt.Errorf("directory: %w", err)
	}
	defer l.Close()

	if m.cfg.BindDN != "" {
		if err := l.Bind(m.cfg.BindDN, m.cfg.BindPassword); err != nil {
			return Identity{}, fmt.Errorf("directory service account: %w", err)
		}
	}
	res, err := l.Search(ldap.NewSearchRequest(
		m.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, int(authTimeout.Seconds()), false,
		m.userFilter(username),
		[]string{"dn", m.cfg.EmailAttr, m.cfg.GroupAttr}, nil,
	))
	if err != nil {
		var le *ldap.Error
		if errors.As(err, &le) && le.ResultCode == ldap.LDAPResultSizeLimitExceeded {
			return Identity{}, ErrInvalidCredentials // several matches: never guess
		}
		return Identity{}, fmt.Errorf("directory search: %w", err)
	}
	if len(res.Entries) != 1 {
		return Identity{}, ErrInvalidCredentials
	}
	entry := res.Entries[0]

	// The password is checked by the directory itself.
	if err := l.Bind(entry.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return Identity{}, ErrInvalidCredentials
		}
		return Identity{}, fmt.Errorf("directory login: %w", err)
	}
	email := strings.TrimSpace(entry.GetAttributeValue(m.cfg.EmailAttr))
	if email == "" {
		return Identity{}, fmt.Errorf("the directory entry of %q has no %s attribute", username, m.cfg.EmailAttr)
	}
	return Identity{Email: email, Groups: entry.GetAttributeValues(m.cfg.GroupAttr)}, nil
}
