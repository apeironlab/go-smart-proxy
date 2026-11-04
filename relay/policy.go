package relay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"proxy/blocklist"
)

// A policy says which hosts the relay does not want reached: rules written by
// the administrator and lists downloaded from the Internet (hosts files, domain
// lists, adblock lists: what pfBlockerNG uses).
//
// Each rule and list is *mandatory* or *recommended*:
//
//   - mandatory ones are enforced by the relay on the connections that go
//     through it (a contact's network) and by every proxy on all its traffic,
//     which cannot switch them off. The user is only told that the
//     organization blocks a host, not what the rules are;
//   - recommended ones are offered to the proxies, whose users may turn them
//     off.
//
// The relay sends proxies the rules and the addresses of the lists; each proxy
// downloads the lists itself.

// PolicyRule is a handful of hosts written inline.
type PolicyRule struct {
	ID        string   `json:"id" yaml:"id"`
	Name      string   `json:"name" yaml:"name"`
	Mandatory bool     `json:"mandatory,omitempty" yaml:"mandatory,omitempty"`
	Domains   []string `json:"domains,omitempty" yaml:"domains,omitempty"` // a domain blocks its subdomains too
	Nets      []string `json:"nets,omitempty" yaml:"nets,omitempty"`       // addresses or CIDR networks
	Disabled  bool     `json:"disabled,omitempty" yaml:"disabled,omitempty"`
}

// PolicyList is a list downloaded from a URL.
type PolicyList struct {
	ID        string `json:"id" yaml:"id"`
	Name      string `json:"name" yaml:"name"`
	URL       string `json:"url" yaml:"url"`
	Format    string `json:"format,omitempty" yaml:"format,omitempty"` // auto, hosts, domains, abp
	Mandatory bool   `json:"mandatory,omitempty" yaml:"mandatory,omitempty"`
	Disabled  bool   `json:"disabled,omitempty" yaml:"disabled,omitempty"`
}

// PolicyConfig is what an administrator writes.
type PolicyConfig struct {
	Rules []PolicyRule `json:"rules" yaml:"rules"`
	Lists []PolicyList `json:"lists" yaml:"lists"`
	// Allow lists domains the relay's rules never block (the fix for a list
	// that blocks something it should not).
	Allow []string `json:"allow" yaml:"allow"`
	// RefreshHours is how often lists are downloaded again (default 24).
	RefreshHours int `json:"refreshHours,omitempty" yaml:"refresh_hours,omitempty"`
	// RequireLocalAuth makes every proxy protect its web interface and API with
	// an access token; the user cannot switch it off.
	RequireLocalAuth bool `json:"requireLocalAuth,omitempty" yaml:"require_local_auth,omitempty"`
}

// PolicyPush is what a proxy is told.
type PolicyPush struct {
	Rev   string       `json:"rev"`
	Rules []PolicyRule `json:"rules,omitempty"`
	Lists []PolicyList `json:"lists,omitempty"`
	Allow []string     `json:"allow,omitempty"`
	// RequireLocalAuth: the proxy must protect its interface with a token.
	RequireLocalAuth bool `json:"requireLocalAuth,omitempty"`
}

const (
	maxPolicyLists   = 40
	maxPolicyRules   = 200
	maxInlineEntries = 20000
)

func parseFormat(s string) blocklist.Format { return blocklist.Format(s) }

// Validate checks and normalizes the configuration.
func (c *PolicyConfig) Validate() error {
	if len(c.Lists) > maxPolicyLists || len(c.Rules) > maxPolicyRules {
		return errors.New("too many rules or lists")
	}
	ids := map[string]bool{}
	inline := 0
	for i := range c.Rules {
		r := &c.Rules[i]
		if !authIDRe.MatchString(r.ID) || ids[r.ID] {
			return fmt.Errorf("rule %q: invalid or duplicate id", r.ID)
		}
		ids[r.ID] = true
		if r.Name = strings.TrimSpace(r.Name); r.Name == "" || len(r.Name) > 80 {
			return fmt.Errorf("rule %q: a name of up to 80 characters is required", r.ID)
		}
		var doms []string
		for _, d := range r.Domains {
			nd, ok := blocklist.NormalizeDomain(d)
			if !ok {
				return fmt.Errorf("rule %q: %q is not a domain", r.ID, d)
			}
			doms = append(doms, nd)
		}
		r.Domains = doms
		for _, n := range r.Nets {
			if _, err := parsePolicyNet(n); err != nil {
				return fmt.Errorf("rule %q: %q is not an address or network", r.ID, n)
			}
		}
		inline += len(r.Domains) + len(r.Nets)
	}
	if inline > maxInlineEntries {
		return errors.New("too many inline entries: put big collections in a list")
	}
	for i := range c.Lists {
		l := &c.Lists[i]
		if !authIDRe.MatchString(l.ID) || ids[l.ID] {
			return fmt.Errorf("list %q: invalid or duplicate id", l.ID)
		}
		ids[l.ID] = true
		if l.Name = strings.TrimSpace(l.Name); l.Name == "" || len(l.Name) > 80 {
			return fmt.Errorf("list %q: a name of up to 80 characters is required", l.ID)
		}
		if err := blocklist.CheckURL(l.URL); err != nil {
			return fmt.Errorf("list %q: %w", l.ID, err)
		}
		if !parseFormat(l.Format).Valid() {
			return fmt.Errorf("list %q: unknown format %q", l.ID, l.Format)
		}
	}
	var allow []string
	for _, d := range c.Allow {
		nd, ok := blocklist.NormalizeDomain(d)
		if !ok {
			return fmt.Errorf("allow: %q is not a domain", d)
		}
		allow = append(allow, nd)
	}
	c.Allow = allow
	if c.RefreshHours < 0 || c.RefreshHours > 24*30 {
		return errors.New("refresh_hours must be between 1 and 720")
	}
	return nil
}

func parsePolicyNet(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// ListStatus is the state of one downloaded list.
type ListStatus struct {
	ID      string    `json:"id"`
	Entries int       `json:"entries"`
	Fetched time.Time `json:"fetched,omitempty"`
	Error   string    `json:"error,omitempty"`
}

// BlockEvent is a connection the relay refused.
type BlockEvent struct {
	Time   time.Time `json:"time"`
	Email  string    `json:"email"`
	Host   string    `json:"host"`
	Source string    `json:"source"`
}

// Policy holds the policy, downloads its lists and answers "is this host
// blocked?". Like the catalog it comes from a YAML file, or from the
// management interface which keeps it in its database.
type Policy struct {
	mu      sync.Mutex
	cfg     PolicyConfig
	path    string
	mtime   time.Time
	size    int64
	persist func(PolicyConfig) error
	subs    []func()
	stop    chan struct{}

	fetcher   *blocklist.Fetcher
	mandatory *blocklist.Matcher // enforced everywhere
	allow     *blocklist.Matcher
	status    map[string]ListStatus
	rev       string

	counts map[string]int
	recent []BlockEvent
	seen   map[string]time.Time // dedupe of audit events
}

// NewPolicy returns an empty policy that keeps downloaded lists in dir.
func NewPolicy(dir string) *Policy {
	return &Policy{
		fetcher: &blocklist.Fetcher{Dir: dir, DenyPrivate: true},
		status:  map[string]ListStatus{}, counts: map[string]int{}, seen: map[string]time.Time{},
		mandatory: blocklist.NewBuilder().Build(), allow: blocklist.NewBuilder().Build(),
	}
}

type policyFile struct {
	PolicyConfig `yaml:",inline"`
}

// LoadPolicyFile reads the policy from a YAML file, watched for changes.
func LoadPolicyFile(path, dir string) (*Policy, error) {
	p := NewPolicy(dir)
	p.path = path
	if _, err := p.reloadFile(); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Policy) reloadFile() (bool, error) {
	info, err := os.Stat(p.path)
	if err != nil {
		return false, err
	}
	p.mu.Lock()
	same := info.ModTime().Equal(p.mtime) && info.Size() == p.size
	p.mu.Unlock()
	if same {
		return false, nil
	}
	b, err := os.ReadFile(p.path)
	if err != nil {
		return false, err
	}
	var f policyFile
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("%s: %w", p.path, err)
	}
	if err := f.PolicyConfig.Validate(); err != nil {
		return false, fmt.Errorf("%s: %w", p.path, err)
	}
	p.mu.Lock()
	p.cfg, p.mtime, p.size = f.PolicyConfig, info.ModTime(), info.Size()
	p.mu.Unlock()
	p.rebuild()
	p.notify()
	return true, nil
}

// ReadOnly reports whether the policy is edited in a file.
func (p *Policy) ReadOnly() bool { return p.path != "" }

// Config returns a copy of the configuration.
func (p *Policy) Config() PolicyConfig {
	p.mu.Lock()
	defer p.mu.Unlock()
	b, _ := json.Marshal(p.cfg)
	var c PolicyConfig
	json.Unmarshal(b, &c)
	if c.Rules == nil {
		c.Rules = []PolicyRule{}
	}
	if c.Lists == nil {
		c.Lists = []PolicyList{}
	}
	if c.Allow == nil {
		c.Allow = []string{}
	}
	return c
}

// Set replaces the configuration (not for a policy read from a file).
func (p *Policy) Set(c PolicyConfig) error {
	if p.path != "" {
		return errors.New("the policy is read from a file: edit the file")
	}
	// Work on a copy: the caller keeps its slices, and the policy is read by
	// other goroutines.
	b, _ := json.Marshal(c)
	c = PolicyConfig{}
	json.Unmarshal(b, &c)
	if err := c.Validate(); err != nil {
		return err
	}
	p.mu.Lock()
	persist := p.persist
	p.mu.Unlock()
	if persist != nil {
		if err := persist(c); err != nil {
			return err
		}
	}
	p.mu.Lock()
	p.cfg = c
	p.mu.Unlock()
	p.rebuild()
	p.notify()
	go p.Refresh(context.Background()) // fetch what is new
	return nil
}

// applyStored takes a policy another relay saved, without saving it again.
func (p *Policy) applyStored(c PolicyConfig) {
	if p.path != "" || c.Validate() != nil {
		return
	}
	p.mu.Lock()
	a, _ := json.Marshal(p.cfg)
	b, _ := json.Marshal(c)
	if string(a) == string(b) {
		p.mu.Unlock()
		return
	}
	p.cfg = c
	p.mu.Unlock()
	p.rebuild()
	p.notify()
	go p.Refresh(context.Background())
}

// OnChange registers a function called whenever what proxies are told changes.
func (p *Policy) OnChange(fn func()) {
	p.mu.Lock()
	p.subs = append(p.subs, fn)
	p.mu.Unlock()
}

func (p *Policy) notify() {
	p.mu.Lock()
	subs := append([]func(){}, p.subs...)
	p.mu.Unlock()
	for _, fn := range subs {
		fn()
	}
}

func (p *Policy) source(l PolicyList) blocklist.Source {
	return blocklist.Source{ID: l.ID, Name: l.Name, URL: l.URL, Format: parseFormat(l.Format)}
}

// rebuild makes the matchers from the inline rules and the cached lists.
func (p *Policy) rebuild() {
	p.mu.Lock()
	cfg := p.cfg
	p.mu.Unlock()
	mand := blocklist.NewBuilder()
	allow := blocklist.NewBuilder()
	allow.Add("allow", cfg.Allow, nil)
	status := map[string]ListStatus{}
	for _, r := range cfg.Rules {
		if r.Disabled || !r.Mandatory {
			continue
		}
		var nets []netip.Prefix
		for _, n := range r.Nets {
			if pr, err := parsePolicyNet(n); err == nil {
				nets = append(nets, pr)
			}
		}
		mand.Add(r.Name, r.Domains, nets)
	}
	for _, l := range cfg.Lists {
		if l.Disabled {
			continue
		}
		d, n, fetched, err := p.fetcher.Load(p.source(l))
		st := ListStatus{ID: l.ID, Entries: len(d) + len(n), Fetched: fetched}
		if err != nil {
			st.Error = "not downloaded yet"
		}
		p.mu.Lock()
		if old, ok := p.status[l.ID]; ok && old.Error != "" && err != nil {
			st.Error = old.Error
		}
		p.mu.Unlock()
		status[l.ID] = st
		if l.Mandatory && err == nil {
			mand.Add(l.Name, d, n)
		}
	}
	h := sha256.New()
	b, _ := json.Marshal(struct {
		C PolicyConfig
		S map[string]ListStatus
	}{cfg, status})
	h.Write(b)
	rev := hex.EncodeToString(h.Sum(nil)[:8])
	p.mu.Lock()
	p.mandatory, p.allow, p.status, p.rev = mand.Build(), allow.Build(), status, rev
	p.mu.Unlock()
}

// Refresh downloads the lists again and rebuilds. A list that fails keeps its
// previous copy and its error is shown in the status.
func (p *Policy) Refresh(ctx context.Context) {
	cfg := p.Config()
	errs := map[string]string{}
	for _, l := range cfg.Lists {
		if l.Disabled {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
		_, err := p.fetcher.Update(cctx, p.source(l))
		cancel()
		if err != nil {
			errs[l.ID] = err.Error()
			CounterInc("gsp_relay_policy_fetch_total", "result", "failed")
		} else {
			CounterInc("gsp_relay_policy_fetch_total", "result", "ok")
		}
	}
	p.mu.Lock()
	for id, e := range errs {
		st := p.status[id]
		st.ID, st.Error = id, e
		p.status[id] = st
	}
	oldRev := p.rev
	p.mu.Unlock()
	p.rebuild()
	p.mu.Lock()
	for id, e := range errs {
		st := p.status[id]
		st.Error = e
		p.status[id] = st
	}
	changed := p.rev != oldRev
	p.mu.Unlock()
	if changed {
		p.notify()
	}
}

// Run keeps the lists up to date (and re-reads the policy file) until ctx ends.
func (p *Policy) Run(ctx context.Context) {
	p.rebuild()
	go p.Refresh(ctx)
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	last := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if p.path != "" {
				if changed, _ := p.reloadFile(); changed {
					go p.Refresh(ctx)
				}
			}
			hours := p.Config().RefreshHours
			if hours <= 0 {
				hours = 24
			}
			if time.Since(last) >= time.Duration(hours)*time.Hour {
				last = time.Now()
				p.Refresh(ctx)
			}
		}
	}
}

// Check says whether the relay refuses a connection to host: only the
// mandatory rules are enforced here.
func (p *Policy) Check(host string) (blocklist.Hit, bool) {
	if p == nil {
		return blocklist.Hit{}, false
	}
	p.mu.Lock()
	mand, allow := p.mandatory, p.allow
	p.mu.Unlock()
	if _, ok := allow.Match(host); ok {
		return blocklist.Hit{}, false
	}
	return mand.Match(host)
}

// Push is what proxies are told.
func (p *Policy) Push() *PolicyPush {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	out := &PolicyPush{Rev: p.rev, Allow: append([]string{}, p.cfg.Allow...), RequireLocalAuth: p.cfg.RequireLocalAuth}
	for _, r := range p.cfg.Rules {
		if !r.Disabled {
			out.Rules = append(out.Rules, r)
		}
	}
	for _, l := range p.cfg.Lists {
		if !l.Disabled {
			out.Lists = append(out.Lists, l)
		}
	}
	if len(out.Rules) == 0 && len(out.Lists) == 0 && !out.RequireLocalAuth {
		return nil
	}
	return out
}

// Status returns the state of the lists, the refusals counted by rule or list
// and the most recent refusals.
func (p *Policy) Status() (lists []ListStatus, counts map[string]int, recent []BlockEvent) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, l := range p.cfg.Lists {
		if st, ok := p.status[l.ID]; ok {
			lists = append(lists, st)
		}
	}
	counts = map[string]int{}
	for k, v := range p.counts {
		counts[k] = v
	}
	recent = append([]BlockEvent{}, p.recent...)
	sort.Slice(recent, func(i, j int) bool { return recent[i].Time.After(recent[j].Time) })
	return lists, counts, recent
}

// record counts a refusal and reports whether it is worth an audit entry (the
// same user and host are written once per ten minutes).
func (p *Policy) record(email, host, source string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.counts[source]++
	p.recent = append(p.recent, BlockEvent{Time: time.Now(), Email: email, Host: host, Source: source})
	if len(p.recent) > 50 {
		p.recent = p.recent[len(p.recent)-50:]
	}
	key := email + "\x00" + host
	now := time.Now()
	for k, t := range p.seen {
		if now.Sub(t) > 10*time.Minute {
			delete(p.seen, k)
		}
	}
	if _, ok := p.seen[key]; ok {
		return false
	}
	if len(p.seen) < 5000 {
		p.seen[key] = now
	}
	return true
}
