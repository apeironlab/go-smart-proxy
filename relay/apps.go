package relay

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// An application is something behind the relay that users open through the
// proxy: the relay holds the catalog and tells each user only the applications
// that user may open (name, description and the host name to use); where the
// application really is stays between the relay and its gateway.
//
// A gateway is a small program (one per application, or per site) that is
// installed next to the application and connects to the relay with a service
// certificate. The relay sends it the applications it serves, and it connects
// to their backends when an authorised user opens one.

// App is a catalog entry.
type App struct {
	// ID names the application in URLs and the audit log (lowercase letters,
	// digits, - and _).
	ID          string `json:"id" yaml:"id"`
	Name        string `json:"name" yaml:"name"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Host is the name users type (in the browser, in an RDP client...). The
	// proxy routes it to the relay automatically; it need not exist in DNS.
	Host string `json:"host" yaml:"host"`
	// Kind is "tcp" (the gateway passes bytes to Target) or "http" (the gateway
	// is a reverse proxy to the URL in Target).
	Kind string `json:"kind" yaml:"kind"`
	// Gateway is the id of the gateway that serves it.
	Gateway string `json:"gateway" yaml:"gateway"`
	// Target is host:port for tcp, an http:// or https:// URL for http. Users
	// never see it.
	Target string `json:"target" yaml:"target"`
	// Who may open it: everybody who signed in, these addresses, or members of
	// these groups. An application with none of the three is open to nobody.
	Everyone bool     `json:"everyone,omitempty" yaml:"everyone,omitempty"`
	Emails   []string `json:"emails,omitempty" yaml:"emails,omitempty"`
	Groups   []string `json:"groups,omitempty" yaml:"groups,omitempty"`
	// SetHeaders are added to every request to an http application (for
	// instance an identity header the backend trusts).
	SetHeaders map[string]string `json:"setHeaders,omitempty" yaml:"set_headers,omitempty"`
	Disabled   bool              `json:"disabled,omitempty" yaml:"disabled,omitempty"`
}

var hostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// Validate checks one entry.
func (a *App) Validate() error {
	if !authIDRe.MatchString(a.ID) {
		return fmt.Errorf("application %q: invalid id (lowercase letters, digits, - and _)", a.ID)
	}
	a.Name = strings.TrimSpace(a.Name)
	if a.Name == "" || len(a.Name) > 80 {
		return fmt.Errorf("application %q: a name of up to 80 characters is required", a.ID)
	}
	if len(a.Description) > 300 {
		return fmt.Errorf("application %q: description too long", a.ID)
	}
	a.Host = strings.ToLower(strings.TrimSpace(a.Host))
	if len(a.Host) > 253 || !hostRe.MatchString(a.Host) || net.ParseIP(a.Host) != nil {
		return fmt.Errorf("application %q: host must be a host name, not an address", a.ID)
	}
	if a.Kind == "" {
		a.Kind = "tcp"
	}
	if !authIDRe.MatchString(a.Gateway) {
		return fmt.Errorf("application %q: invalid gateway id", a.ID)
	}
	switch a.Kind {
	case "tcp":
		if !validTarget(a.Target) {
			return fmt.Errorf("application %q: target must be host:port", a.ID)
		}
		if len(a.SetHeaders) > 0 {
			return fmt.Errorf("application %q: headers only apply to http applications", a.ID)
		}
	case "http":
		u, err := url.Parse(a.Target)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
			return fmt.Errorf("application %q: target must be an http:// or https:// URL", a.ID)
		}
		for k, v := range a.SetHeaders {
			if k == "" || strings.ContainsAny(k, " :\r\n") || strings.ContainsAny(v, "\r\n") || strings.EqualFold(k, "Host") {
				return fmt.Errorf("application %q: invalid header %q", a.ID, k)
			}
		}
	default:
		return fmt.Errorf("application %q: kind must be tcp or http", a.ID)
	}
	for _, e := range a.Emails {
		if _, ok := NormalizeEmail(e); !ok {
			return fmt.Errorf("application %q: invalid address %q", a.ID, e)
		}
	}
	return nil
}

// Allows reports whether the user may open the application.
func (a *App) Allows(email string, groups []string) bool {
	if a.Disabled {
		return false
	}
	if a.Everyone {
		return true
	}
	for _, e := range a.Emails {
		if n, ok := NormalizeEmail(e); ok && n == email {
			return true
		}
	}
	return len(a.Groups) > 0 && groupMatches(groups, a.Groups)
}

// AppInfo is what a user is told about an application.
type AppInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Host        string `json:"host"`
	Kind        string `json:"kind"`
	Online      bool   `json:"online"` // its gateway is connected
}

// GatewayApp is what a gateway is told about an application it serves.
type GatewayApp struct {
	ID         string            `json:"id"`
	Host       string            `json:"host"`
	Kind       string            `json:"kind"`
	Target     string            `json:"target"`
	SetHeaders map[string]string `json:"setHeaders,omitempty"`
}

// GatewayState is pushed to a gateway whenever the catalog changes.
type GatewayState struct {
	T    string       `json:"t"`
	Apps []GatewayApp `json:"apps"`
}

// ValidateApps checks a whole catalog: each entry, and that ids and host names
// are unique.
func ValidateApps(apps []App) error {
	ids, hosts := map[string]bool{}, map[string]bool{}
	for i := range apps {
		if err := apps[i].Validate(); err != nil {
			return err
		}
		if ids[apps[i].ID] {
			return fmt.Errorf("application %q: duplicate id", apps[i].ID)
		}
		if hosts[apps[i].Host] {
			return fmt.Errorf("application %q: the host %s is used by another application", apps[i].ID, apps[i].Host)
		}
		ids[apps[i].ID], hosts[apps[i].Host] = true, true
	}
	return nil
}

// Catalog is the list of applications. It comes from a YAML file (re-read when
// it changes) or is edited by the management interface, which keeps it in its
// database.
type Catalog struct {
	mu      sync.Mutex
	apps    []App
	path    string
	mtime   time.Time
	size    int64
	persist func([]App) error // set when the interface owns the catalog
	subs    []func()
	stop    chan struct{}
}

// NewCatalog returns an empty catalog, to be filled with Set.
func NewCatalog() *Catalog { return &Catalog{} }

type catalogFile struct {
	Apps []App `yaml:"apps"`
}

// LoadCatalogFile reads the catalog from path and keeps watching it: changes
// are applied (and pushed to users and gateways) within a few seconds. A file
// that does not parse leaves the previous catalog in place.
func LoadCatalogFile(path string) (*Catalog, error) {
	c := &Catalog{path: path, stop: make(chan struct{})}
	if _, err := c.reload(); err != nil {
		return nil, err
	}
	stop := c.stop
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				c.reload() // an error keeps the previous catalog
			}
		}
	}()
	return c, nil
}

// Close stops watching the file.
func (c *Catalog) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stop != nil {
		close(c.stop)
		c.stop = nil
	}
}

func (c *Catalog) reload() (bool, error) {
	info, err := os.Stat(c.path)
	if err != nil {
		return false, err
	}
	c.mu.Lock()
	same := info.ModTime().Equal(c.mtime) && info.Size() == c.size
	c.mu.Unlock()
	if same {
		return false, nil
	}
	b, err := os.ReadFile(c.path)
	if err != nil {
		return false, err
	}
	var f catalogFile
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("%s: %w", c.path, err)
	}
	if err := ValidateApps(f.Apps); err != nil {
		return false, fmt.Errorf("%s: %w", c.path, err)
	}
	c.mu.Lock()
	c.apps, c.mtime, c.size = f.Apps, info.ModTime(), info.Size()
	subs := append([]func(){}, c.subs...)
	c.mu.Unlock()
	for _, fn := range subs {
		fn()
	}
	return true, nil
}

// Apps returns a copy of the catalog.
func (c *Catalog) Apps() []App {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]App{}, c.apps...)
}

// ReadOnly reports whether the catalog is edited in a file.
func (c *Catalog) ReadOnly() bool { return c.path != "" }

// Set replaces the catalog (not allowed for a catalog read from a file).
func (c *Catalog) Set(apps []App) error {
	if c.path != "" {
		return errors.New("the catalog is read from a file: edit the file")
	}
	apps = append([]App{}, apps...)
	if err := ValidateApps(apps); err != nil {
		return err
	}
	sort.Slice(apps, func(i, j int) bool { return apps[i].ID < apps[j].ID })
	c.mu.Lock()
	persist := c.persist
	c.mu.Unlock()
	if persist != nil {
		if err := persist(apps); err != nil {
			return err
		}
	}
	c.mu.Lock()
	c.apps = apps
	subs := append([]func(){}, c.subs...)
	c.mu.Unlock()
	for _, fn := range subs {
		fn()
	}
	return nil
}

// applyStored takes a catalog another relay saved: it replaces the one in
// memory (and tells the users) without saving it again.
func (c *Catalog) applyStored(apps []App) {
	if c.path != "" || ValidateApps(apps) != nil {
		return
	}
	apps = append([]App{}, apps...)
	sort.Slice(apps, func(i, j int) bool { return apps[i].ID < apps[j].ID })
	c.mu.Lock()
	a, _ := json.Marshal(c.apps)
	b, _ := json.Marshal(apps)
	if string(a) == string(b) {
		c.mu.Unlock()
		return
	}
	c.apps = apps
	subs := append([]func(){}, c.subs...)
	c.mu.Unlock()
	for _, fn := range subs {
		fn()
	}
}

// OnChange registers a function called after every change.
func (c *Catalog) OnChange(fn func()) {
	c.mu.Lock()
	c.subs = append(c.subs, fn)
	c.mu.Unlock()
}

// ByID finds an application.
func (c *Catalog) ByID(id string) (App, bool) {
	for _, a := range c.Apps() {
		if a.ID == id {
			return a, true
		}
	}
	return App{}, false
}

// ForGateway lists what a gateway serves.
func (c *Catalog) ForGateway(id string) []GatewayApp {
	out := []GatewayApp{}
	for _, a := range c.Apps() {
		if a.Gateway == id && !a.Disabled {
			out = append(out, GatewayApp{ID: a.ID, Host: a.Host, Kind: a.Kind, Target: a.Target, SetHeaders: a.SetHeaders})
		}
	}
	return out
}
