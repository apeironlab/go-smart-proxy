package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"proxy/blocklist"
	"proxy/relay"
)

// The proxy can block hosts (ads, trackers, malware) before any connection is
// made, whatever route would have been used, with or without a relay.
//
// What is blocked comes from, strongest first:
//
//  1. the relay's mandatory rules and lists (the organization): the user
//     cannot switch them off or see what they are, only that a host is blocked
//     by the organization;
//  2. the user's own allow list, which lets a host through ...
//  3. ... unless it is on the user's lists (presets, URLs, custom hosts) or on
//     the relay's recommended rules, which the user can switch off.
//
// Applications a relay publishes are never blocked.

// BlockList is a list the user subscribes to.
type BlockList struct {
	Name    string `yaml:"Name" json:"name"`
	URL     string `yaml:"URL" json:"url"`
	Format  string `yaml:"Format,omitempty" json:"format"`
	Enabled bool   `yaml:"Enabled" json:"enabled"`
}

// BlockingConfig is the user's blocking setup.
type BlockingConfig struct {
	Enabled bool `yaml:"Enabled" json:"enabled"`
	// Presets are the ids of the built-in lists that are on.
	Presets []string    `yaml:"Presets,omitempty" json:"presets"`
	Lists   []BlockList `yaml:"Lists,omitempty" json:"lists"`
	// Block are hosts, domains (their subdomains too), addresses or networks.
	Block []string `yaml:"Block,omitempty" json:"block"`
	// Allow are domains that are never blocked by the user's lists.
	Allow []string `yaml:"Allow,omitempty" json:"allow"`
	// RelayOff are the relay rules the user switched off ("relay/ruleid"); only
	// the recommended ones can be.
	RelayOff     []string `yaml:"RelayOff,omitempty" json:"relayOff"`
	RefreshHours int      `yaml:"RefreshHours,omitempty" json:"refreshHours"`
}

// blockPreset is a well-known list the user can switch on with a click.
type blockPreset struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	URL         string `json:"url"`
	Format      string `json:"format"`
}

var blockPresets = []blockPreset{
	{"stevenblack", "StevenBlack unified hosts", "Ads, trackers and malware, a widely used hosts file.", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "hosts"},
	{"yoyo", "Peter Lowe's ad servers", "A compact list of advertising and tracking servers.", "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext", "hosts"},
	{"urlhaus", "abuse.ch URLhaus", "Hosts currently serving malware.", "https://urlhaus.abuse.ch/downloads/hostfile/", "hosts"},
}

func presetByID(id string) (blockPreset, bool) {
	for _, p := range blockPresets {
		if p.ID == id {
			return p, true
		}
	}
	return blockPreset{}, false
}

const (
	maxUserLists   = 30
	maxUserEntries = 20000
)

// Normalize checks the configuration and cleans it.
func (c *BlockingConfig) Normalize() error {
	if len(c.Lists) > maxUserLists || len(c.Block)+len(c.Allow) > maxUserEntries {
		return errors.New("too many lists or entries")
	}
	var presets []string
	seen := map[string]bool{}
	for _, id := range c.Presets {
		if _, ok := presetByID(id); !ok {
			return fmt.Errorf("unknown preset %q", id)
		}
		if !seen[id] {
			presets = append(presets, id)
			seen[id] = true
		}
	}
	c.Presets = presets
	urls := map[string]bool{}
	for i := range c.Lists {
		l := &c.Lists[i]
		l.Name = strings.TrimSpace(l.Name)
		l.URL = strings.TrimSpace(l.URL)
		if l.Name == "" || len(l.Name) > 80 {
			return errors.New("every list needs a name of up to 80 characters")
		}
		if err := blocklist.CheckURL(l.URL); err != nil {
			return fmt.Errorf("list %q: %w", l.Name, err)
		}
		if !blocklist.Format(l.Format).Valid() {
			return fmt.Errorf("list %q: unknown format %q", l.Name, l.Format)
		}
		if urls[l.URL] {
			return fmt.Errorf("list %q: the same address is listed twice", l.Name)
		}
		urls[l.URL] = true
	}
	var err error
	if c.Block, err = cleanHostEntries(c.Block, true); err != nil {
		return err
	}
	if c.Allow, err = cleanHostEntries(c.Allow, false); err != nil {
		return err
	}
	if c.RefreshHours < 0 || c.RefreshHours > 24*30 {
		return errors.New("the update interval must be between 1 hour and 30 days")
	}
	return nil
}

// cleanHostEntries normalizes domains (and, if nets, addresses and networks).
func cleanHostEntries(in []string, nets bool) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, e := range in {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		var norm string
		if d, ok := blocklist.NormalizeDomain(e); ok {
			norm = d
		} else if nets {
			if p, err := netip.ParsePrefix(e); err == nil {
				norm = p.Masked().String()
			} else if a, err := netip.ParseAddr(e); err == nil {
				norm = a.String()
			}
		}
		if norm == "" {
			return nil, fmt.Errorf("%q is not a valid host name", e)
		}
		if !seen[norm] {
			seen[norm] = true
			out = append(out, norm)
		}
	}
	return out, nil
}

// ---- engine -----------------------------------------------------------

// blockStatus is the state of one downloaded list.
type blockStatus struct {
	Key     string    `json:"key"`
	Name    string    `json:"name"`
	Entries int       `json:"entries"`
	Fetched time.Time `json:"fetched"`
	Error   string    `json:"error"`
}

type relayLayer struct {
	allow *blocklist.Matcher
	mand  *blocklist.Matcher
}

// BlockedEvent is a refused connection.
type BlockedEvent struct {
	Time   time.Time `json:"time"`
	Host   string    `json:"host"`
	Source string    `json:"source"`
	Client string    `json:"client"`
}

type blockEngine struct {
	mu      sync.Mutex
	cfg     BlockingConfig
	fetcher *blocklist.Fetcher

	user     *blocklist.Matcher   // the user's lists and custom hosts
	allow    *blocklist.Matcher   // the user's allow list
	relays   []relayLayer         // mandatory relay rules, one layer per relay
	relayOp  []*blocklist.Matcher // recommended relay rules that are on
	status   []blockStatus
	updMu    sync.Mutex // one download round at a time
	updating atomic.Bool

	total  int
	bySrc  map[string]int
	byHost map[string]int
	recent []BlockedEvent
}

var blocker = &blockEngine{
	fetcher: &blocklist.Fetcher{Dir: "blocklists"},
	bySrc:   map[string]int{}, byHost: map[string]int{},
}

const orgSource = "your organization"

func (e *blockEngine) config() BlockingConfig {
	e.mu.Lock()
	defer e.mu.Unlock()
	c := e.cfg
	c.Presets = append([]string{}, c.Presets...)
	c.Lists = append([]BlockList{}, c.Lists...)
	c.Block = append([]string{}, c.Block...)
	c.Allow = append([]string{}, c.Allow...)
	c.RelayOff = append([]string{}, c.RelayOff...)
	return c
}

func (e *blockEngine) setConfig(c BlockingConfig) {
	e.mu.Lock()
	e.cfg = c
	e.mu.Unlock()
}

// userSources lists the lists the user wants: presets and own lists.
func userSources(c BlockingConfig) []blocklist.Source {
	var out []blocklist.Source
	for _, id := range c.Presets {
		if p, ok := presetByID(id); ok {
			out = append(out, blocklist.Source{ID: p.ID, Name: p.Name, URL: p.URL, Format: blocklist.Format(p.Format)})
		}
	}
	for _, l := range c.Lists {
		if l.Enabled {
			out = append(out, blocklist.Source{ID: "u", Name: l.Name, URL: l.URL, Format: blocklist.Format(l.Format)})
		}
	}
	return out
}

// relayPolicies returns the policy each connected relay pushed.
func relayPolicies() map[string]*relay.PolicyPush {
	out := map[string]*relay.PolicyPush{}
	for _, c := range relayHub.list() {
		c.mu.Lock()
		p := c.state.Policy
		c.mu.Unlock()
		if p != nil {
			out[c.name] = p
		}
	}
	return out
}

func relaySource(l relay.PolicyList) blocklist.Source {
	return blocklist.Source{ID: l.ID, Name: l.Name, URL: l.URL, Format: blocklist.Format(l.Format)}
}

// allSources is every list that must be on disk now.
func (e *blockEngine) allSources() []blocklist.Source {
	c := e.config()
	var out []blocklist.Source
	if c.Enabled {
		out = append(out, userSources(c)...)
	}
	for _, p := range relayPolicies() {
		for _, l := range p.Lists {
			out = append(out, relaySource(l))
		}
	}
	return out
}

func inList(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// reload rebuilds the matchers from the configuration, the relays' policies
// and the lists in the cache.
func (e *blockEngine) reload() {
	c := e.config()
	var status []blockStatus

	user := blocklist.NewBuilder()
	if c.Enabled {
		for _, s := range userSources(c) {
			d, n, fetched, err := e.fetcher.Load(s)
			st := blockStatus{Key: s.URL, Name: s.Name, Entries: len(d) + len(n), Fetched: fetched}
			if err != nil {
				st.Error = "not downloaded yet"
			} else {
				user.Add(s.Name, d, n)
			}
			status = append(status, st)
		}
		var nets []netip.Prefix
		var doms []string
		for _, b := range c.Block {
			if p, err := netip.ParsePrefix(b); err == nil {
				nets = append(nets, p)
			} else if a, err := netip.ParseAddr(b); err == nil {
				nets = append(nets, netip.PrefixFrom(a, a.BitLen()))
			} else {
				doms = append(doms, b)
			}
		}
		user.Add("your own list", doms, nets)
	}
	allow := blocklist.NewBuilder()
	allow.Add("allow", c.Allow, nil)

	var layers []relayLayer
	var optional []*blocklist.Matcher
	for name, p := range relayPolicies() {
		mand := blocklist.NewBuilder()
		ra := blocklist.NewBuilder()
		ra.Add("allow", p.Allow, nil)
		for _, r := range p.Rules {
			var nets []netip.Prefix
			for _, n := range r.Nets {
				if pr, err := netip.ParsePrefix(n); err == nil {
					nets = append(nets, pr)
				} else if a, err := netip.ParseAddr(n); err == nil {
					nets = append(nets, netip.PrefixFrom(a, a.BitLen()))
				}
			}
			switch {
			case r.Mandatory:
				mand.Add(orgSource, r.Domains, nets)
			case c.Enabled && !inList(c.RelayOff, name+"/"+r.ID):
				b := blocklist.NewBuilder()
				b.Add(r.Name, r.Domains, nets)
				optional = append(optional, b.Build())
			}
		}
		for _, l := range p.Lists {
			if !l.Mandatory && (!c.Enabled || inList(c.RelayOff, name+"/"+l.ID)) {
				continue
			}
			d, n, _, err := e.fetcher.Load(relaySource(l))
			if err != nil {
				continue
			}
			if l.Mandatory {
				mand.Add(orgSource, d, n)
			} else {
				b := blocklist.NewBuilder()
				b.Add(l.Name, d, n)
				optional = append(optional, b.Build())
			}
		}
		layers = append(layers, relayLayer{allow: ra.Build(), mand: mand.Build()})
	}

	um := user.Build()
	e.mu.Lock()
	e.user, e.allow, e.relays, e.relayOp, e.status = um, allow.Build(), layers, optional, status
	e.mu.Unlock()
}

// update downloads the lists that are needed and rebuilds. A list that cannot
// be downloaded keeps its previous copy.
func (e *blockEngine) update(ctx context.Context) {
	e.updMu.Lock()
	defer e.updMu.Unlock()
	e.updating.Store(true)
	defer e.updating.Store(false)
	errs := map[string]string{}
	for _, s := range e.allSources() {
		cctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
		_, err := e.fetcher.Update(cctx, s)
		cancel()
		if err != nil {
			errs[s.URL] = err.Error()
			log.Printf("blocking: list %q: %v", s.Name, err)
		}
	}
	e.reload()
	e.mu.Lock()
	for i := range e.status {
		e.status[i].Error = errs[e.status[i].Key]
	}
	e.mu.Unlock()
}

// check decides about host. Applications published by a relay are never blocked.
func (e *blockEngine) check(host string) blocklist.Decision {
	e.mu.Lock()
	enabled := e.cfg.Enabled
	layers := e.relays
	user, allow, optional := e.user, e.allow, e.relayOp
	e.mu.Unlock()

	if _, _, ok := relayHub.appForHost(host); ok {
		return blocklist.Decision{}
	}
	// The organization's rules apply even when the user switched blocking off.
	for _, l := range layers {
		if _, ok := l.allow.Match(host); ok {
			continue
		}
		if hit, ok := l.mand.Match(host); ok {
			return blocklist.Decision{Blocked: true, Mandatory: true, Hit: hit}
		}
	}
	if !enabled {
		return blocklist.Decision{}
	}
	return blocklist.Decide(host, nil, allow, append([]*blocklist.Matcher{user}, optional...))
}

// blockedError is returned by dialTarget for a host the proxy refuses.
type blockedError struct {
	Host      string
	Source    string
	Mandatory bool
}

func (b *blockedError) Error() string {
	if b.Mandatory {
		return "blocked by your organization"
	}
	return "blocked: " + b.Source
}

// refuse is called for a blocked connection: it keeps the statistics and the
// entry in the connections list. client is the address of the program asking.
func (e *blockEngine) refuse(kind, client, host, port, method, rawURL string, d blocklist.Decision) *blockedError {
	src := d.Hit.Source
	if d.Mandatory {
		src = orgSource
	}
	e.mu.Lock()
	e.total++
	e.bySrc[src]++
	if len(e.byHost) < 2000 || e.byHost[host] > 0 {
		e.byHost[host]++
	}
	e.recent = append(e.recent, BlockedEvent{Time: time.Now(), Host: host, Source: src, Client: client})
	if len(e.recent) > 100 {
		e.recent = e.recent[len(e.recent)-100:]
	}
	e.mu.Unlock()
	rec := connReg.newConn(kind, client, host, net.JoinHostPort(host, port), "", "Blocked", "", method, rawURL)
	rec.event("blocked: " + src)
	rec.setError("blocked: " + src)
	rec.finish(StateBlocked)
	return &blockedError{Host: host, Source: src, Mandatory: d.Mandatory}
}

// blockCheck is what the dialers call first.
func blockCheck(kind, client, host, port, method, rawURL string) error {
	if d := blocker.check(host); d.Blocked {
		return blocker.refuse(kind, client, host, port, method, rawURL, d)
	}
	return nil
}

// blockedPage is the answer to a browser asking for a blocked host.
func blockedPage(w http.ResponseWriter, err error) {
	var be *blockedError
	reason := "blocked"
	if errors.As(err, &be) {
		reason = be.Error()
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Blocked-By", "go-smart-proxy")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><title>Blocked</title><body style="font-family:system-ui,sans-serif;max-width:32rem;margin:15vh auto;padding:0 1.5rem"><h1 style="font-size:1.3rem">Blocked</h1><p>%s</p></body>`, htmlEscape(reason))
}

func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

// ---- stats ------------------------------------------------------------

type blockStats struct {
	Total  int            `json:"total"`
	BySrc  map[string]int `json:"bySource"`
	Top    []hostCount    `json:"top"`
	Recent []BlockedEvent `json:"recent"`
}

type hostCount struct {
	Host  string `json:"host"`
	Count int    `json:"count"`
}

func (e *blockEngine) stats() blockStats {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := blockStats{Total: e.total, BySrc: map[string]int{}, Recent: []BlockedEvent{}, Top: []hostCount{}}
	for k, v := range e.bySrc {
		s.BySrc[k] = v
	}
	for h, n := range e.byHost {
		s.Top = append(s.Top, hostCount{h, n})
	}
	sort.Slice(s.Top, func(i, j int) bool {
		if s.Top[i].Count != s.Top[j].Count {
			return s.Top[i].Count > s.Top[j].Count
		}
		return s.Top[i].Host < s.Top[j].Host
	})
	if len(s.Top) > 15 {
		s.Top = s.Top[:15]
	}
	for i := len(e.recent) - 1; i >= 0 && len(s.Recent) < 30; i-- {
		s.Recent = append(s.Recent, e.recent[i])
	}
	return s
}

func (e *blockEngine) resetStats() {
	e.mu.Lock()
	e.total, e.bySrc, e.byHost, e.recent = 0, map[string]int{}, map[string]int{}, nil
	e.mu.Unlock()
}

// ---- lifecycle --------------------------------------------------------

var (
	relayPolicyRev   = map[string]string{}
	relayPolicyRevMu sync.Mutex
)

// blockingRelayState is called when a relay sent its state: when its policy
// changed, the lists are fetched again.
func blockingRelayState(relayName string, p *relay.PolicyPush) {
	rev := ""
	if p != nil {
		rev = p.Rev
	}
	relayPolicyRevMu.Lock()
	changed := relayPolicyRev[relayName] != rev
	relayPolicyRev[relayName] = rev
	relayPolicyRevMu.Unlock()
	if changed {
		go blocker.update(context.Background())
	}
}

// blockingStart loads the configuration, the cached lists, and keeps them fresh.
func blockingStart() {
	configMu.Lock()
	c := configuration.Blocking
	configMu.Unlock()
	if c.Normalize() != nil {
		c = BlockingConfig{}
	}
	blocker.setConfig(c)
	blocker.reload()
	go func() {
		blocker.update(context.Background())
		for {
			hours := blocker.config().RefreshHours
			if hours <= 0 {
				hours = 24
			}
			time.Sleep(time.Duration(hours) * time.Hour)
			blocker.update(context.Background())
		}
	}()
}
