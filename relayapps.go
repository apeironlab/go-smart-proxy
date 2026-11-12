package main

import (
	"errors"
	"github.com/apeironlab/go-smart-proxy/relay"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// Applications published by a relay. The relay tells the proxy which
// applications the user may open (name, description, host name); the proxy
// sends connections to those host names to the relay by itself, without any
// route or rule being set up, and the relay takes them to the gateway that
// serves the application. Where the application is stays on the relay.

// appEntry is an application of one relay.
type appEntry struct {
	Relay string `json:"relay"`
	relay.AppInfo
}

func normalizeAppHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

// allApps lists the applications of every relay.
func (h *relayRegistry) allApps() []appEntry {
	var out []appEntry
	for _, c := range h.list() {
		for _, a := range c.appInfos() {
			out = append(out, appEntry{Relay: c.name, AppInfo: a})
		}
	}
	return out
}

// appForHost finds the application a host name belongs to.
func (h *relayRegistry) appForHost(host string) (*relayClient, relay.AppInfo, bool) {
	host = normalizeAppHost(host)
	if host == "" {
		return nil, relay.AppInfo{}, false
	}
	for _, c := range h.list() {
		for _, a := range c.appInfos() {
			if a.Host == host {
				return c, a, true
			}
		}
	}
	return nil, relay.AppInfo{}, false
}

// DialApp opens an application on the named relay.
func (h *relayRegistry) DialApp(relayName, id string) (net.Conn, error) {
	c := h.get(relayName)
	if c == nil {
		return nil, errors.New("relay " + relayName + " is not configured")
	}
	return c.DialApp(id)
}

var (
	appRouteMu sync.Mutex
	appRoutes  = map[string]*ProxyRoute{}
)

// appRoute returns the route for an application host: a route whose only hop
// is the application on its relay. Routes are kept, so that connections are
// reused.
func appRoute(host string) (*ProxyRoute, string) {
	c, a, ok := relayHub.appForHost(host)
	if !ok {
		return nil, ""
	}
	key := c.name + "/" + a.ID
	appRouteMu.Lock()
	defer appRouteMu.Unlock()
	rt := appRoutes[key]
	if rt == nil {
		rt = &ProxyRoute{
			name:  "App: " + a.Name,
			chain: []*chainHop{{scheme: "relayapp", addr: "app:" + a.ID, device: a.ID, relayName: c.name}},
		}
		appRoutes[key] = rt
	}
	return rt, a.Name
}

// appURL is the address a user opens an application at: http applications are
// reached with http:// (the gateway speaks to the backend); for the others the
// host name is what a client (RDP, SSH, a database tool) is pointed at.
func appURL(a appEntry) string {
	if a.Kind != "http" {
		return ""
	}
	return (&url.URL{Scheme: "http", Host: a.Host, Path: "/"}).String()
}

type appJSON struct {
	Relay       string `json:"relay"`
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Host        string `json:"host"`
	Kind        string `json:"kind"`
	Online      bool   `json:"online"`
	URL         string `json:"url"`
}

func appsHandler(w http.ResponseWriter, r *http.Request) {
	out := []appJSON{}
	for _, a := range relayHub.allApps() {
		out = append(out, appJSON{Relay: a.Relay, ID: a.ID, Name: a.Name, Description: a.Description, Host: a.Host, Kind: a.Kind, Online: a.Online, URL: appURL(a)})
	}
	writeJSON(w, out)
}
