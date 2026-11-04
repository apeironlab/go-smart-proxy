package relay

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// PasswordConfig is a list of local users. The file has one user per line:
//
//	username:bcrypt-hash[:e-mail[:group,group]]
//
// The e-mail may be left out when the user name already is an address. Lines
// starting with # are comments. The file is re-read when it changes, so users
// can be added or removed without restarting the relay.
type PasswordConfig struct {
	UsersFile     string   `yaml:"users_file"`
	RequireGroups []string `yaml:"require_groups"`
}

func (c *PasswordConfig) validate() error {
	if strings.TrimSpace(c.UsersFile) == "" {
		return errors.New("users_file is required")
	}
	return nil
}

// bcryptCost is the work factor of new hashes (lowered by the tests).
var bcryptCost = bcrypt.DefaultCost

// HashPassword returns the bcrypt hash to put in a users file.
func HashPassword(password string) (string, error) {
	if len(password) < 8 {
		return "", errors.New("the password must be at least 8 characters")
	}
	if len(password) > 72 {
		return "", errors.New("bcrypt uses at most 72 bytes of the password")
	}
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	return string(b), err
}

// AddPasswordUser appends a user to a users file (creating it with mode 0600).
func AddPasswordUser(path, username, password, email string, groups ...string) error {
	username = strings.TrimSpace(username)
	if username == "" || strings.ContainsAny(username, ":\n\r\t ") {
		return errors.New("invalid user name")
	}
	if email == "" {
		email = username
	}
	email, ok := NormalizeEmail(email)
	if !ok {
		return errors.New("invalid e-mail address")
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s:%s:%s:%s\n", strings.ToLower(username), hash, email, strings.Join(groups, ","))
	return err
}

type passwordUser struct {
	hash   []byte
	email  string
	groups []string
}

type passwordMethod struct {
	cfg *PasswordConfig

	mu    sync.Mutex
	mtime time.Time
	size  int64
	users map[string]passwordUser
}

func newPasswordMethod(cfg *PasswordConfig) (*passwordMethod, error) {
	m := &passwordMethod{cfg: cfg}
	if _, err := m.load(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *passwordMethod) load() (map[string]passwordUser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	info, err := os.Stat(m.cfg.UsersFile)
	if err != nil {
		return nil, err
	}
	if m.users != nil && info.ModTime().Equal(m.mtime) && info.Size() == m.size {
		return m.users, nil
	}
	f, err := os.Open(m.cfg.UsersFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	users := map[string]passwordUser{}
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			return nil, fmt.Errorf("%s:%d: expected username:hash[:email[:groups]]", m.cfg.UsersFile, n)
		}
		name := strings.ToLower(strings.TrimSpace(parts[0]))
		u := passwordUser{hash: []byte(parts[1])}
		email := name
		if len(parts) > 2 && strings.TrimSpace(parts[2]) != "" {
			email = parts[2]
		}
		var ok bool
		if u.email, ok = NormalizeEmail(email); !ok {
			return nil, fmt.Errorf("%s:%d: %q has no valid e-mail address", m.cfg.UsersFile, n, name)
		}
		if len(parts) > 3 {
			for _, g := range strings.Split(parts[3], ",") {
				if g = strings.TrimSpace(g); g != "" {
					u.groups = append(u.groups, g)
				}
			}
		}
		users[name] = u
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	m.users, m.mtime, m.size = users, info.ModTime(), info.Size()
	return users, nil
}

// dummyHash is compared against when the user does not exist, so that an
// unknown user and a wrong password take the same time.
var (
	dummyOnce sync.Once
	dummyHash []byte
)

func dummyPasswordHash() []byte {
	dummyOnce.Do(func() { dummyHash, _ = bcrypt.GenerateFromPassword([]byte("not a real password"), bcryptCost) })
	return dummyHash
}

func (m *passwordMethod) Authenticate(_ context.Context, username, password string) (Identity, error) {
	users, err := m.load()
	if err != nil {
		return Identity{}, fmt.Errorf("users file: %w", err)
	}
	u, ok := users[strings.ToLower(strings.TrimSpace(username))]
	hash := u.hash
	if !ok {
		hash = dummyPasswordHash()
	}
	if err := bcrypt.CompareHashAndPassword(hash, []byte(password)); err != nil || !ok {
		return Identity{}, ErrInvalidCredentials
	}
	return Identity{Email: u.email, Groups: u.groups}, nil
}
