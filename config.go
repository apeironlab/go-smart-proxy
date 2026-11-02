package main

import (
	"log"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type ConfigCredential struct {
	Name     string `yaml:"Name" json:"name"`
	User     string `yaml:"User" json:"user"`
	Password string `yaml:"Password" json:"password"`
}

type ConfigRoute struct {
	Name       string `yaml:"Name"`
	Gateway    string `yaml:"Gateway"`
	IFace      string `yaml:"IFace"`
	Net        string `yaml:"Net"`
	PacUrl     string `yaml:"PacUrl"`
	ProxyUrl   string `yaml:"ProxyUrl"`
	Credential string `yaml:"Credential"`
	// Chain is an ordered list of upstream proxies (first = the one dialed directly).
	// When present it takes precedence over PacUrl and ProxyUrl.
	Chain []ConfigHop `yaml:"Chain,omitempty"`
	// RulesOnly restricts the route to the destination rules: it is never
	// picked as the automatic (default) route. For the connection to the relay
	// only the hops before a relay hop are used.
	RulesOnly bool `yaml:"RulesOnly,omitempty"`
}

// ConfigHop is one proxy of a chain. ProxyUrl accepts http://host:port and socks5://host:port.
type ConfigHop struct {
	ProxyUrl   string `yaml:"ProxyUrl" json:"proxyUrl"`
	Credential string `yaml:"Credential" json:"credential"`
}

// RelayConfig connects this proxy to a relay (see cmd/proxyrelay) so that it can
// reach, and be reached by, the contacts in the address book.
type RelayConfig struct {
	Address string `yaml:"Address"` // host[:port] of the relay (default port 8443)
	Cert    string `yaml:"Cert"`    // client certificate (its e-mail identifies you)
	Key     string `yaml:"Key"`
	CA      string `yaml:"CA"` // CA that signed the relay certificate (empty: system roots)
	// Route is the name of the route used to reach the relay; empty means the
	// currently applicable one (direct, proxy, chain...).
	Route string `yaml:"Route"`
	// AllowLocal lets contacts reach services bound to this machine (off by default).
	AllowLocal bool `yaml:"AllowLocal"`
}

type Configuration struct {
	Relay              *RelayConfig       `yaml:"Relay,omitempty"`
	Address            string             `yaml:"Address"`
	Credentials        []ConfigCredential `yaml:"Credentials"`
	Routes             []ConfigRoute      `yaml:"Routes"`
	Rules              []ConfigRule       `yaml:"Rules,omitempty"`
	SystemProxy        bool               `yaml:"SystemProxy"`
	SystemProxyExclude []string           `yaml:"SystemProxyExclude"`
	PacHijack          bool               `yaml:"PacHijack"`
	PacHijackHost      string             `yaml:"PacHijackHost"`
	ForceChrome        bool               `yaml:"ForceChrome"`
	// Hosts maps a hostname to the IP address it must be dialed at, whatever the system DNS says
	// (for instance when a VPN hands out a resolver that does not know an internal name).
	Hosts map[string]string `yaml:"Hosts"`
}

var configuration Configuration

func loadConfiguration() {
	cfg, err := os.Open("config.yml")
	if err != nil {
		log.Fatal(err)
	}
	defer cfg.Close()
	if err := yaml.NewDecoder(cfg).Decode(&configuration); err != nil {
		log.Fatal(err)
	}

	hosts := map[string]string{}
	for host, address := range configuration.Hosts {
		if net.ParseIP(address) == nil {
			log.Fatalf("config.yml: Hosts[%s]: %q is not an IP address", host, address)
		}
		hosts[strings.ToLower(host)] = address
	}
	configuration.Hosts = hosts

	loadRoutes()
}

func GetCredential(name string) *ConfigCredential {
	for _, v := range configuration.Credentials {
		if v.Name == name {
			return &v
		}
	}
	return nil
}

func GetCacheDir() string {
	err := os.MkdirAll("./cache", 0755)
	if err != nil {
		return os.TempDir()
	}
	return "./cache"
}
