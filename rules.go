package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
)

// ConfigRule sends the traffic for some destinations through a given route.
// Rules are evaluated in order, the first one that matches (and whose route is
// applicable on the current network) wins; otherwise the usual route selection applies.
type ConfigRule struct {
	Name string `yaml:"Name" json:"name"`
	// Domains match the domain and all its subdomains (example.com, *.example.com, .example.com).
	Domains []string `yaml:"Domains,omitempty" json:"domains"`
	// Hosts match exactly one host name.
	Hosts []string `yaml:"Hosts,omitempty" json:"hosts"`
	// Networks are IP addresses or CIDR blocks (10.0.0.0/8). Host names are resolved to be checked.
	Networks []string `yaml:"Networks,omitempty" json:"networks"`
	// Route is the name of the route to use ("Direct" for no proxy).
	Route string `yaml:"Route" json:"route"`
	// ExitVPN and ExitLabel are optional conditions on where the exit of the
	// route's relay hop is: "up" or "down" for whether its device is on a VPN,
	// and a label (comma-separated names or globs) it shares. The rule only
	// applies while they hold, so another rule or the automatic selection can
	// take over otherwise.
	ExitVPN   string `yaml:"ExitVPN,omitempty" json:"exitVpn"`
	ExitLabel string `yaml:"ExitLabel,omitempty" json:"exitLabel"`
}

type routingRule struct {
	name    string
	domains []string
	hosts   map[string]bool
	nets    []*net.IPNet
	route   string

	exitVPN   string
	exitLabel string
}

var (
	rulesMu    sync.RWMutex
	routeRules []*routingRule
)

func normHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

func compileRule(c ConfigRule) (*routingRule, error) {
	r := &routingRule{
		name: c.Name, hosts: map[string]bool{}, route: strings.TrimSpace(c.Route),
		exitVPN:   strings.ToLower(strings.TrimSpace(c.ExitVPN)),
		exitLabel: strings.TrimSpace(c.ExitLabel),
	}
	if r.route == "" {
		return nil, fmt.Errorf("rule %q: route is required", c.Name)
	}
	if !validExitVPN(r.exitVPN) {
		return nil, fmt.Errorf("rule %q: ExitVPN must be empty, \"up\" or \"down\"", c.Name)
	}
	if !validLabelPattern(r.exitLabel) {
		return nil, fmt.Errorf("rule %q: invalid ExitLabel %q", c.Name, c.ExitLabel)
	}
	for _, d := range c.Domains {
		d = strings.TrimLeft(normHost(d), "*.")
		if d == "" {
			continue
		}
		r.domains = append(r.domains, d)
	}
	for _, h := range c.Hosts {
		if h = normHost(h); h != "" {
			r.hosts[h] = true
		}
	}
	for _, n := range c.Networks {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if ip := net.ParseIP(n); ip != nil {
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			r.nets = append(r.nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, ipn, err := net.ParseCIDR(n)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %q is neither an IP address nor a CIDR", c.Name, n)
		}
		r.nets = append(r.nets, ipn)
	}
	if len(r.domains)+len(r.hosts)+len(r.nets) == 0 {
		return nil, fmt.Errorf("rule %q: no domain, host or network", c.Name)
	}
	return r, nil
}

func compileRules(cfg []ConfigRule) ([]*routingRule, error) {
	out := make([]*routingRule, 0, len(cfg))
	for _, c := range cfg {
		r, err := compileRule(c)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func (r *routingRule) matches(host string, ip func() net.IP) bool {
	if r.hosts[host] {
		return true
	}
	for _, d := range r.domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	if len(r.nets) > 0 {
		if a := ip(); a != nil {
			for _, n := range r.nets {
				if n.Contains(a) {
					return true
				}
			}
		}
	}
	return false
}

// firstRuleRoute returns the route selected by the first destination rule that
// matches host and whose route is applicable on the current network. It ignores
// the forced route and the automatic selection.
func firstRuleRoute(host string) (*ProxyRoute, string) {
	rulesMu.RLock()
	rules := routeRules
	rulesMu.RUnlock()
	if len(rules) == 0 {
		return nil, ""
	}
	host = normHost(host)
	var resolved net.IP
	done := false
	ip := func() net.IP {
		if !done {
			done = true
			if p := net.ParseIP(host); p != nil {
				resolved = p
			} else if s := resolveHost(host); s != "" {
				resolved = net.ParseIP(s)
			}
		}
		return resolved
	}
	st := getNetState()
	for _, rule := range rules {
		if !rule.matches(host, ip) {
			continue
		}
		for _, rt := range getRoutes() {
			if rt.name != rule.route || !rt.isApplicable(st) {
				continue
			}
			if ok, _ := exitConditionsMet(rt, rule.exitVPN, rule.exitLabel); !ok {
				continue
			}
			return rt, rule.name
		}
	}
	return nil, ""
}

// routeFor picks the route for a destination: the forced route first, then the
// destination rules, then the default selection. The second value is the name
// of the matching rule, if any.
func routeFor(host string) (*ProxyRoute, string) {
	// An application published by a relay always goes to that relay: not even
	// a forced route or a rule sends it elsewhere, since nothing else could
	// reach it.
	if rt, name := appRoute(host); rt != nil {
		return rt, "application " + name
	}
	if getForceRoute() == nil {
		if rt, rule := firstRuleRoute(host); rt != nil {
			// A rule selects the route explicitly: use the whole chain,
			// including the RulesOnly hops.
			return rt, rule
		}
	}
	route := GetApplicableRoute()
	if route == nil {
		return nil, ""
	}
	// No destination rule matched: the chain stops before the first hop
	// marked RulesOnly.
	return route.autoRoute(), ""
}

func (c ConfigRule) validate() error {
	_, err := compileRule(c)
	return err
}

// normalized replaces the nil lists with empty ones, so that JSON clients
// always receive arrays instead of null.
func (c ConfigRule) normalized() ConfigRule {
	if c.Domains == nil {
		c.Domains = []string{}
	}
	if c.Hosts == nil {
		c.Hosts = []string{}
	}
	if c.Networks == nil {
		c.Networks = []string{}
	}
	c.ExitVPN = strings.ToLower(strings.TrimSpace(c.ExitVPN))
	c.ExitLabel = strings.TrimSpace(c.ExitLabel)
	return c
}

// --- web API ---

func registerRuleRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/rules", func(w http.ResponseWriter, r *http.Request) {
		configMu.Lock()
		rules := make([]ConfigRule, 0, len(configuration.Rules))
		for _, rl := range configuration.Rules {
			rules = append(rules, rl.normalized())
		}
		configMu.Unlock()
		writeJSON(w, rules)
	})
	m.HandleFunc("POST /api/rules", func(w http.ResponseWriter, r *http.Request) {
		var rules []ConfigRule
		if err := readJSON(r, &rules); err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid body")
			return
		}
		if _, err := compileRules(rules); err != nil {
			writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		for i := range rules {
			rules[i] = rules[i].normalized()
		}
		configMu.Lock()
		known := map[string]bool{}
		for _, rt := range configuration.Routes {
			known[rt.Name] = true
		}
		for _, rl := range rules {
			if rl.Route != "Direct" && !known[rl.Route] {
				configMu.Unlock()
				writeAPIError(w, http.StatusBadRequest, fmt.Sprintf("rule %q: route %q does not exist", rl.Name, rl.Route))
				return
			}
		}
		configuration.Rules = rules
		err := persistConfigurationLocked()
		if err == nil {
			reapplyRoutesLocked()
		}
		configMu.Unlock()
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, map[string]string{"status": "ok"})
	})
	// Which route would be used for a destination (e.g. "10.1.2.3", "www.example.com")?
	m.HandleFunc("GET /api/rules/test", func(w http.ResponseWriter, r *http.Request) {
		host := normHost(r.URL.Query().Get("host"))
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if host == "" {
			writeAPIError(w, http.StatusBadRequest, "host is required")
			return
		}
		route, rule := routeFor(host)
		res := map[string]string{"rule": rule, "ip": resolveHost(host)}
		if route != nil {
			res["route"] = route.name
		}
		writeJSON(w, res)
	})
}
