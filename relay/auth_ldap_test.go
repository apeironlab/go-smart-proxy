package relay

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	nmldap "github.com/nmcclain/ldap"
)

type fakeDirectory struct {
	mu       sync.Mutex
	filters  []string
	bound    []string
	entries  map[string]*nmldap.Entry // by DN
	password map[string]string        // by DN
}

func entry(dn string, attrs map[string][]string) *nmldap.Entry {
	e := &nmldap.Entry{DN: dn}
	for k, v := range attrs {
		e.Attributes = append(e.Attributes, &nmldap.EntryAttribute{Name: k, Values: v})
	}
	return e
}

func (d *fakeDirectory) Bind(dn, pw string, _ net.Conn) (nmldap.LDAPResultCode, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.bound = append(d.bound, dn)
	if dn == "" && pw == "" { // anonymous bind: many directories accept it
		return nmldap.LDAPResultSuccess, nil
	}
	if want, ok := d.password[dn]; ok && want == pw {
		return nmldap.LDAPResultSuccess, nil
	}
	return nmldap.LDAPResultInvalidCredentials, nil
}

func unescapeFilter(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+2 < len(s) {
			var c byte
			if _, err := fmt.Sscanf(s[i+1:i+3], "%02x", &c); err == nil {
				b.WriteByte(c)
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func (d *fakeDirectory) Search(boundDN string, req nmldap.SearchRequest, _ net.Conn) (nmldap.ServerSearchResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.filters = append(d.filters, req.Filter)
	if boundDN != "cn=svc,dc=example,dc=com" {
		return nmldap.ServerSearchResult{ResultCode: nmldap.LDAPResultInsufficientAccessRights}, nil
	}
	// only understands (uid=VALUE); the value comes escaped
	if !strings.HasPrefix(req.Filter, "(uid=") || !strings.HasSuffix(req.Filter, ")") {
		return nmldap.ServerSearchResult{}, nil
	}
	val := unescapeFilter(strings.TrimSuffix(strings.TrimPrefix(req.Filter, "(uid="), ")"))
	// a literal wildcard in the filter would match everyone: the value is
	// compared as plain text, so only an unescaped filter could be abused
	var out []*nmldap.Entry
	for _, e := range d.entries {
		if strings.EqualFold(e.GetAttributeValue("uid"), val) && !strings.Contains(req.Filter, "*") {
			out = append(out, e)
		}
	}
	return nmldap.ServerSearchResult{Entries: out, ResultCode: nmldap.LDAPResultSuccess}, nil
}

func startDirectory(t *testing.T) (*fakeDirectory, string) {
	t.Helper()
	d := &fakeDirectory{entries: map[string]*nmldap.Entry{}, password: map[string]string{
		"cn=svc,dc=example,dc=com":                 "svcpw",
		"uid=alice,ou=people,dc=example,dc=com":    "alicepw",
		"uid=bob,ou=people,dc=example,dc=com":      "bobpw",
		"uid=dup,ou=people,dc=example,dc=com":      "duppw",
		"uid=dup,ou=contractors,dc=example,dc=com": "duppw",
		"uid=nomail,ou=people,dc=example,dc=com":   "nomailpw",
	}}
	add := func(dn string, attrs map[string][]string) { d.entries[dn] = entry(dn, attrs) }
	add("uid=alice,ou=people,dc=example,dc=com", map[string][]string{
		"uid": {"alice"}, "mail": {"Alice@Example.com"},
		"memberOf": {"CN=VPN-Users,OU=Groups,DC=example,DC=com", "CN=Staff,OU=Groups,DC=example,DC=com"},
	})
	add("uid=bob,ou=people,dc=example,dc=com", map[string][]string{"uid": {"bob"}, "mail": {"bob@example.com"}})
	add("uid=dup,ou=people,dc=example,dc=com", map[string][]string{"uid": {"dup"}, "mail": {"dup@example.com"}})
	add("uid=dup,ou=contractors,dc=example,dc=com", map[string][]string{"uid": {"dup"}, "mail": {"dup2@example.com"}})
	add("uid=nomail,ou=people,dc=example,dc=com", map[string][]string{"uid": {"nomail"}})

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	srv := nmldap.NewServer()
	srv.BindFunc("", d)
	srv.SearchFunc("", d)
	go srv.ListenAndServe(addr)
	t.Cleanup(func() { close(srv.Quit) })
	for i := 0; i < 50; i++ {
		if c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond); err == nil {
			c.Close()
			return d, addr
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the test directory did not start")
	return nil, ""
}

func testLDAP(t *testing.T, addr string, tweak func(*LDAPConfig)) *ldapMethod {
	t.Helper()
	cfg := &LDAPConfig{
		URL: "ldap://" + addr, AllowPlaintext: true,
		BindDN: "cn=svc,dc=example,dc=com", BindPassword: "svcpw",
		BaseDN: "dc=example,dc=com",
	}
	if tweak != nil {
		tweak(cfg)
	}
	m, err := newLDAPMethod(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestLDAPAuthentication(t *testing.T) {
	_, addr := startDirectory(t)
	m := testLDAP(t, addr, nil)

	id, err := m.Authenticate(nil, "alice", "alicepw")
	if err != nil || id.Email != "Alice@Example.com" || len(id.Groups) != 2 {
		t.Fatalf("alice: %+v %v", id, err)
	}
	if !groupMatches(id.Groups, []string{"vpn-users"}) {
		t.Fatal("the CN of memberOf must satisfy a group requirement")
	}
	if id, err := m.Authenticate(nil, "bob", "bobpw"); err != nil || id.Email != "bob@example.com" || len(id.Groups) != 0 {
		t.Fatalf("bob: %+v %v", id, err)
	}

	// everything that is not a clean success looks the same to the caller
	for _, c := range [][2]string{
		{"alice", "wrong"},    // bad password
		{"ghost", "whatever"}, // unknown user
		{"dup", "duppw"},      // two matches: never guess which one is meant
		{"alice", ""},         // empty password would be an anonymous bind
		{"", "alicepw"},       // no user
		{"*", "alicepw"},      // wildcard
	} {
		if _, err := m.Authenticate(nil, c[0], c[1]); err != ErrInvalidCredentials {
			t.Errorf("%q/%q must give ErrInvalidCredentials, got %v", c[0], c[1], err)
		}
	}
	// a directory entry without an e-mail address cannot be enrolled
	if _, err := m.Authenticate(nil, "nomail", "nomailpw"); err == nil || err == ErrInvalidCredentials {
		t.Fatalf("an entry without mail: %v", err)
	}
}

func TestLDAPFilterEscaping(t *testing.T) {
	m, err := newLDAPMethod(&LDAPConfig{URL: "ldaps://d.example.com", BaseDN: "dc=example", UserFilter: "(&(objectClass=person)(sAMAccountName=%s))"})
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"alice":      "(&(objectClass=person)(sAMAccountName=alice))",
		"*":          `(&(objectClass=person)(sAMAccountName=\2a))`,
		"*)(uid=*":   `(&(objectClass=person)(sAMAccountName=\2a\29\28uid=\2a))`,
		`a\b`:        `(&(objectClass=person)(sAMAccountName=a\5cb))`,
		"x)(|(uid=*": `(&(objectClass=person)(sAMAccountName=x\29\28|\28uid=\2a))`,
	} {
		if got := m.userFilter(name); got != want {
			t.Errorf("userFilter(%q) = %s, want %s", name, got, want)
		}
	}
}

func TestLDAPServiceAccountProblems(t *testing.T) {
	_, addr := startDirectory(t)
	m := testLDAP(t, addr, func(c *LDAPConfig) { c.BindPassword = "wrong" })
	if _, err := m.Authenticate(nil, "alice", "alicepw"); err == nil || err == ErrInvalidCredentials {
		t.Fatalf("a broken service account is a server problem, not the user's: %v", err)
	}
	// nothing listening
	m = testLDAP(t, "127.0.0.1:1", nil)
	if _, err := m.Authenticate(nil, "alice", "alicepw"); err == nil || err == ErrInvalidCredentials {
		t.Fatalf("an unreachable directory: %v", err)
	}
}

func TestEnrollOverHTTPWithLDAP(t *testing.T) {
	_, addr := startDirectory(t)
	ts, _ := authServer(t, func(c *EnrollConfig, _ string) {
		c.Auth = &AuthConfig{Methods: []AuthMethod{{
			ID: "dir", Type: "ldap", Label: "Directory",
			LDAP: &LDAPConfig{
				URL: "ldap://" + addr, AllowPlaintext: true, BindDN: "cn=svc,dc=example,dc=com", BindPassword: "svcpw",
				BaseDN: "dc=example,dc=com", RequireGroups: []string{"vpn-users"},
			},
		}}}
	})
	login := func(email, user, pass string, want int) map[string]any {
		csr, _ := testCSR(t, email)
		var out map[string]any
		postJSONTest(t, ts.URL+"/enroll-auth/dir", "", map[string]string{
			"email": email, "csr": string(csr), "username": user, "password": pass,
		}, &out, want)
		return out
	}
	// the e-mail comes back with different capitals in the directory: still matches
	out := login("alice@example.com", "alice", "alicepw", 200)
	if got := certEmail(t, out["certPem"].(string)); got != "alice@example.com" {
		t.Fatalf("certificate for %q", got)
	}
	login("alice@example.com", "alice", "wrong", http.StatusUnauthorized)
	login("bob@example.com", "bob", "bobpw", http.StatusForbidden) // valid, but not in the group
	login("alice@example.com", "nomail", "nomailpw", http.StatusBadGateway)
}
