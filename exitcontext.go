package main

import (
	"fmt"
	"path"
	"strings"

	"proxy/relay"
)

// This file connects the network context that relay devices share (a label the
// user chose and whether a VPN is active) to route selection: a route or a
// destination rule can require that the exit of the route's relay hop is on a
// VPN, or carries a given label.

// sharedContext is the context this device tells its contacts, or nil when the
// user turned sharing off. Only a label and a VPN yes/no ever leave the
// machine: no addresses, no host names, no domains.
func (r *relayClient) sharedContext() *relay.NetContext {
	configMu.Lock()
	cfg := r.cfg
	var label string
	share := true
	if cfg != nil {
		label = cfg.NetworkLabel
		if cfg.ShareContext != nil {
			share = *cfg.ShareContext
		}
	}
	configMu.Unlock()
	if !share {
		return nil
	}
	return relay.SanitizeContext(&relay.NetContext{
		Label: label,
		VPN:   len(getNetState().analysis.VPN) > 0,
	})
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
	ctxs, why := relayMgr.exitContexts(hop.addr, hop.device)
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
