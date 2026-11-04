package main

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"sync"

	"proxy/relay"
)

// This file holds the set of relay servers the installation is connected to.
// Each relay is a relayClient with its own identity, address book, approvals
// and network labels; the registry only keeps them together and resolves which
// one a request is about.

var relayNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,29}$`)

// validRelayName reports whether s can name a relay.
func validRelayName(s string) bool { return relayNameRe.MatchString(s) }

const defaultRelayName = "default"

// allRelayConfigs returns every configured relay, including a legacy
// single-relay entry that has not been migrated yet.
func allRelayConfigs() []*RelayConfig {
	out := append([]*RelayConfig(nil), configuration.Relays...)
	if configuration.Relay != nil {
		out = append(out, configuration.Relay)
	}
	return out
}

// migrateRelayConfigs moves a legacy Relay entry into Relays (named "default")
// and gives every relay a unique, valid name. It reports whether anything
// changed, so the caller can persist the configuration.
func migrateRelayConfigs() bool {
	changed := false
	if configuration.Relay != nil {
		legacy := configuration.Relay
		configuration.Relay = nil
		if legacy.Name == "" {
			legacy.Name = defaultRelayName
		}
		configuration.Relays = append([]*RelayConfig{legacy}, configuration.Relays...)
		changed = true
	}
	seen := map[string]bool{}
	for i, cfg := range configuration.Relays {
		name := cfg.Name
		if !validRelayName(name) || seen[name] {
			name = fmt.Sprintf("relay-%d", i+1)
			for seen[name] {
				name += "x"
			}
			cfg.Name = name
			changed = true
		}
		seen[name] = true
	}
	return changed
}

// findRelayConfigLocked returns the configuration of the named relay. The
// caller holds configMu.
func findRelayConfigLocked(name string) *RelayConfig {
	for _, cfg := range configuration.Relays {
		if cfg.Name == name {
			return cfg
		}
	}
	return nil
}

// relayRegistry holds the running relay clients, in configuration order.
type relayRegistry struct {
	mu      sync.Mutex
	clients map[string]*relayClient
	order   []string
}

var relayHub = &relayRegistry{clients: map[string]*relayClient{}}

func newRelayClient(name string) *relayClient {
	return &relayClient{name: name, approvals: map[int64]*relayApproval{}}
}

// startAll starts a client for every configured relay.
func (h *relayRegistry) startAll() {
	configMu.Lock()
	cfgs := append([]*RelayConfig(nil), configuration.Relays...)
	configMu.Unlock()
	for _, cfg := range cfgs {
		h.apply(cfg)
	}
}

// apply creates the client of a relay or, when it exists, gives it the new
// configuration (which makes it reconnect).
func (h *relayRegistry) apply(cfg *RelayConfig) *relayClient {
	if cfg == nil || cfg.Address == "" || cfg.Name == "" {
		return nil
	}
	h.mu.Lock()
	c := h.clients[cfg.Name]
	if c == nil {
		c = newRelayClient(cfg.Name)
		h.clients[cfg.Name] = c
		h.order = append(h.order, cfg.Name)
	}
	h.mu.Unlock()
	c.start(cfg)
	return c
}

// put registers an existing client under name (used by tests).
func (h *relayRegistry) put(name string, c *relayClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	c.name = name
	if h.clients[name] == nil {
		h.order = append(h.order, name)
	}
	h.clients[name] = c
}

// remove disconnects and forgets a relay.
func (h *relayRegistry) remove(name string) {
	h.mu.Lock()
	c := h.clients[name]
	delete(h.clients, name)
	kept := h.order[:0]
	for _, n := range h.order {
		if n != name {
			kept = append(kept, n)
		}
	}
	h.order = kept
	h.mu.Unlock()
	if c != nil {
		c.stop()
	}
}

// reset forgets every relay without stopping it (used by tests).
func (h *relayRegistry) reset() {
	h.mu.Lock()
	h.clients, h.order = map[string]*relayClient{}, nil
	h.mu.Unlock()
}

func (h *relayRegistry) get(name string) *relayClient {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.clients[name]
}

// list returns the clients in configuration order.
func (h *relayRegistry) list() []*relayClient {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]*relayClient, 0, len(h.order))
	for _, n := range h.order {
		out = append(out, h.clients[n])
	}
	return out
}

// pick returns the named relay; an empty name means the first one. ok is false
// when there is no such relay (or none at all).
func (h *relayRegistry) pick(name string) (*relayClient, bool) {
	if name != "" {
		c := h.get(name)
		return c, c != nil
	}
	l := h.list()
	if len(l) == 0 {
		return nil, false
	}
	return l[0], true
}

// forContact finds the relay a relay hop refers to. An explicit name wins.
// Without one, the relay that knows the contact (or is the user's own account)
// is used, which makes hops keep working when a second relay is added; if
// several relays know it the hop must say which.
func (h *relayRegistry) forContact(name, email, device string) (*relayClient, error) {
	if name != "" {
		c := h.get(name)
		if c == nil {
			return nil, fmt.Errorf("relay %q is not configured", name)
		}
		return c, nil
	}
	all := h.list()
	switch len(all) {
	case 0:
		return nil, errors.New("not connected to any relay")
	case 1:
		return all[0], nil
	}
	var known []*relayClient
	for _, c := range all {
		if c.knows(email) {
			known = append(known, c)
		}
	}
	switch len(known) {
	case 1:
		return known[0], nil
	case 0:
		return nil, fmt.Errorf("%s is not a contact on any relay", email)
	}
	names := ""
	for i, c := range known {
		if i > 0 {
			names += ", "
		}
		names += c.name
	}
	return nil, fmt.Errorf("%s is known on several relays (%s): add ?relay=name to the hop", email, names)
}

// Dial opens a connection through the network of a contact, on the relay the
// hop refers to.
func (h *relayRegistry) Dial(relayName, email, device, target string) (net.Conn, error) {
	c, err := h.forContact(relayName, email, device)
	if err != nil {
		return nil, err
	}
	return c.Dial(email, device, target)
}

// exitContexts returns the shared network context of the devices a relay hop
// would use, on the relay it refers to.
func (h *relayRegistry) exitContexts(relayName, email, device string) ([]relay.NetContext, string) {
	c, err := h.forContact(relayName, email, device)
	if err != nil {
		return nil, err.Error()
	}
	return c.exitContexts(email, device)
}

// PublishContext tells every relay's contacts about the current network.
func (h *relayRegistry) PublishContext() {
	for _, c := range h.list() {
		c.PublishContext()
	}
}

// knows reports whether email is the user's own account or one of the
// contacts on this relay.
func (r *relayClient) knows(email string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if email == r.state.Email {
		return true
	}
	for _, c := range r.state.Contacts {
		if c.Email == email {
			return true
		}
	}
	return false
}
