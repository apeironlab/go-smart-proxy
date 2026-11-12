package main

import (
	"fmt"
	"path"
	"strings"

	"github.com/apeironlab/go-smart-proxy/relay"
)

// This file connects the network context that relay devices share (a label the
// user chose and whether a VPN is active) to route selection: a route or a
// destination rule can require that the exit of the route's relay hop is on a
// VPN, or carries a given label.

// labelForNetwork picks the label shared with a relay's contacts: the first
// NetworkLabels entry whose conditions hold on the current network, otherwise
// the default NetworkLabel. matched is the index of the entry, or -1.
func labelForNetwork(cfg *RelayConfig, st netState) (label string, matched int) {
	for i, nl := range cfg.NetworkLabels {
		c := nl.criteria()
		if c.isEmpty() || strings.TrimSpace(nl.Label) == "" {
			continue
		}
		if ok, _ := c.match(st); ok {
			return nl.Label, i
		}
	}
	return cfg.NetworkLabel, -1
}

// sharedContextFor builds the context to share with a relay's contacts: nil
// when the user turned sharing off. Only a label and a VPN yes/no ever leave the
// machine: no addresses, no host names, no domains. The caller holds configMu.
func sharedContextFor(cfg *RelayConfig) (ctx *relay.NetContext, matched int) {
	if cfg == nil || (cfg.ShareContext != nil && !*cfg.ShareContext) {
		return nil, -1
	}
	st := getNetState()
	label, matched := labelForNetwork(cfg, st)
	return relay.SanitizeContext(&relay.NetContext{Label: label, VPN: len(st.analysis.VPN) > 0}), matched
}

// sharedContext is the context this device tells the contacts of the relay it
// is connected to, or nil when sharing is off.
func (r *relayClient) sharedContext() *relay.NetContext {
	configMu.Lock()
	defer configMu.Unlock()
	ctx, _ := sharedContextFor(r.cfg)
	return ctx
}

// validateNetworkLabels checks and normalizes the label table sent by the UI.
func validateNetworkLabels(in []NetworkLabel) ([]NetworkLabel, error) {
	if len(in) > 30 {
		return nil, fmt.Errorf("too many network labels (at most 30)")
	}
	out := make([]NetworkLabel, 0, len(in))
	for i, nl := range in {
		sc := relay.SanitizeContext(&relay.NetContext{Label: nl.Label})
		nl.Label = sc.Label
		nl.VPN = strings.ToLower(strings.TrimSpace(nl.VPN))
		nl.IFaceUp, nl.IFace = strings.TrimSpace(nl.IFaceUp), strings.TrimSpace(nl.IFace)
		nl.Net, nl.Gateway = strings.TrimSpace(nl.Net), strings.TrimSpace(nl.Gateway)
		if nl.Label == "" {
			return nil, fmt.Errorf("network label %d: the label is empty", i+1)
		}
		c := nl.criteria()
		if c.isEmpty() {
			return nil, fmt.Errorf("network label %q: set at least one condition (VPN, interface in use, network...)", nl.Label)
		}
		if err := c.validate(); err != nil {
			return nil, fmt.Errorf("network label %q: %w", nl.Label, err)
		}
		out = append(out, nl)
	}
	return out, nil
}

// PublishContext sends the current context to the relay. It is called after
// every network change and whenever the settings change; without a connection
// it does nothing (the context also goes out with the hello of the next one).
func (r *relayClient) PublishContext() {
	r.mu.Lock()
	connected := r.ctrl != nil && r.connected
	r.mu.Unlock()
	if !connected {
		return
	}
	if err := r.send(relay.ClientMsg{T: relay.TContext, Context: r.sharedContext()}); err != nil {
		return
	}
}

// exitContexts returns the shared context of the devices a relay hop would
// use. why explains an empty result.
func (r *relayClient) exitContexts(email, device string) (ctxs []relay.NetContext, why string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if email == r.state.Email {
		for _, d := range r.state.MyDevices {
			if !d.Online || d.ID == r.device || (device != "" && d.ID != device) {
				continue
			}
			if d.Context == nil {
				return nil, fmt.Sprintf("device %s does not share its network context", d.ID)
			}
			ctxs = append(ctxs, *d.Context)
		}
		if len(ctxs) == 0 {
			why = "no other device of yours is online"
		}
		return ctxs, why
	}
	for _, c := range r.state.Contacts {
		if c.Email != email {
			continue
		}
		if !c.Online {
			return nil, email + " is offline"
		}
		devices := c.Devices
		if device != "" {
			devices = []string{device}
		}
		if len(devices) == 0 {
			return nil, email + " does not share its network context"
		}
		for _, d := range devices {
			ctx, ok := c.Context[d]
			if !ok {
				return nil, fmt.Sprintf("%s/%s does not share its network context", email, d)
			}
			ctxs = append(ctxs, ctx)
		}
		return ctxs, ""
	}
	return nil, email + " is not a contact (or the relay is not connected)"
}

// relayHop returns the relay hop of the route, if it has one.
func (p *ProxyRoute) relayHop() *chainHop {
	for _, h := range p.chain {
		if h.scheme == "relay" {
			return h
		}
	}
	return nil
}

// validExitVPN reports whether v is an accepted ExitVPN value.
func validExitVPN(v string) bool { return v == "" || v == "up" || v == "down" }

// validLabelPattern reports whether the comma-separated glob patterns are valid.
func validLabelPattern(patterns string) bool {
	for _, p := range strings.Split(patterns, ",") {
		if _, err := path.Match(strings.ToLower(strings.TrimSpace(p)), ""); err != nil {
			return false
		}
	}
	return true
}

// exitConditionsMet checks the conditions on the exit of the route's relay hop:
// vpn is "", "up" or "down", label is a comma-separated list of names or globs.
// When the route has several exit devices (no device chosen and several
// online) every one of them must satisfy the conditions, because the relay
// refuses to choose between them.
func exitConditionsMet(rt *ProxyRoute, vpn, label string) (bool, string) {
	if vpn == "" && label == "" {
		return true, ""
	}
	hop := rt.relayHop()
	if hop == nil {
		return false, "the route has no relay hop"
	}
	ctxs, why := relayHub.exitContexts(hop.relayName, hop.addr, hop.device)
	if len(ctxs) == 0 {
		return false, why
	}
	for _, c := range ctxs {
		switch {
		case vpn == "up" && !c.VPN:
			return false, fmt.Sprintf("the exit %s is not on a VPN", hop.addr)
		case vpn == "down" && c.VPN:
			return false, fmt.Sprintf("the exit %s is on a VPN", hop.addr)
		case label != "" && !matchIface(label, c.Label):
			return false, fmt.Sprintf("the exit %s is labelled %q, not %q", hop.addr, c.Label, label)
		}
	}
	return true, ""
}
