package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

type ConfigCredential struct {
	Name     string `yaml:"Name" json:"name"`
	User     string `yaml:"User" json:"user"`
	Password string `yaml:"Password" json:"password"`
}

type ConfigRoute struct {
	Name    string `yaml:"Name"`
	Gateway string `yaml:"Gateway"`
	IFace   string `yaml:"IFace"`
	Net     string `yaml:"Net"`
	// IFaceUp makes the route applicable only while a matching network
	// interface is in use (up, with an address and carrying routes). Unlike
	// IFace, which looks at the default route only, it also sees split-tunnel
	// VPNs that leave the default route alone. Comma-separated names or globs
	// ("utun4", "tun*", "Pulse*").
	IFaceUp string `yaml:"IFaceUp,omitempty"`
	// VPN restricts the route to "up" (a VPN is active) or "down" (none is).
	VPN string `yaml:"VPN,omitempty"`
	// ExitVPN and ExitLabel are conditions on the exit of the route's relay hop:
	// whether the contact's device is on a VPN, and the label it shares
	// (comma-separated names or globs).
	ExitVPN   string `yaml:"ExitVPN,omitempty"`
	ExitLabel string `yaml:"ExitLabel,omitempty"`
	// PacUrl, ProxyUrl and Credential are legacy route-level upstream fields.
	// They are migrated to a single hop in Chain when the configuration is
	// loaded, and the current UI no longer writes them.
	PacUrl     string      `yaml:"PacUrl,omitempty"`
	ProxyUrl   string      `yaml:"ProxyUrl,omitempty"`
	Credential string      `yaml:"Credential,omitempty"`
	Chain      []ConfigHop `yaml:"Chain,omitempty"`
	// RulesOnly restricts the route to the destination rules: it is never
	// picked as the automatic (default) route. For the connection to the relay
	// only the hops before a relay hop are used.
	RulesOnly bool `yaml:"RulesOnly,omitempty"`
}

// ConfigHop is one hop of a chain: a proxy/relay (ProxyUrl), a PAC (PacUrl,
// which must be the only hop of the chain), or a dynamic routing point
// (Dynamic, which must be the last hop and applies the route selected by the
// destination rules).
type ConfigHop struct {
	ProxyUrl   string `yaml:"ProxyUrl,omitempty" json:"proxyUrl,omitempty"`
	PacUrl     string `yaml:"PacUrl,omitempty" json:"pacUrl,omitempty"`
	Dynamic    bool   `yaml:"Dynamic,omitempty" json:"dynamic,omitempty"`
	Credential string `yaml:"Credential,omitempty" json:"credential,omitempty"`
	// RulesOnly makes this hop a boundary: the chain stops before it unless
	// the route was selected by a destination rule.
	RulesOnly bool `yaml:"RulesOnly,omitempty" json:"rulesOnly"`
}

// RelayConfig connects this proxy to a relay (see cmd/proxyrelay) so that it can
// reach, and be reached by, the contacts in the address book.
// NetworkLabel gives a name to a network, recognised by local conditions. Every
// condition that is set must hold (at least one must be set).
type NetworkLabel struct {
	Label   string `yaml:"Label" json:"label"`
	VPN     string `yaml:"VPN,omitempty" json:"vpn"`         // "up" or "down"
	IFaceUp string `yaml:"IFaceUp,omitempty" json:"ifaceUp"` // an interface in use (names or globs)
	IFace   string `yaml:"IFace,omitempty" json:"iface"`     // the default interface
	Net     string `yaml:"Net,omitempty" json:"net"`         // a local network (CIDR)
	Gateway string `yaml:"Gateway,omitempty" json:"gateway"` // the default gateway
}

func (n NetworkLabel) criteria() netCriteria {
	return netCriteria{Gateway: n.Gateway, IFace: n.IFace, Net: n.Net, IFaceUp: n.IFaceUp, VPN: strings.ToLower(strings.TrimSpace(n.VPN))}
}

type RelayConfig struct {
	// Name identifies the relay among the ones this installation is connected
	// to: lowercase letters, digits, "-" and "_". Hops choose a relay with
	// relay://contact@example.com?relay=name. The relay migrated from a
	// single-relay configuration is called "default".
	Name    string `yaml:"Name,omitempty"`
	Address string `yaml:"Address"` // host[:port] of the relay (default port 8443)
	Cert    string `yaml:"Cert"`    // client certificate (its e-mail identifies you)
	Key     string `yaml:"Key"`
	CA      string `yaml:"CA"` // CA that signed the relay certificate (empty: system roots)
	// CertPEM, KeyPEM and CAPEM hold the relay material inside the encrypted
	// configuration, so they no longer need to exist as files.
	CertPEM string `yaml:"CertPEM,omitempty"`
	KeyPEM  string `yaml:"KeyPEM,omitempty"`
	CAPEM   string `yaml:"CAPEM,omitempty"`
	// Route is the name of the route used to reach the relay; empty means the
	// currently applicable one (direct, proxy, chain...).
	Route string `yaml:"Route"`
	// Device identifies this installation among the user's machines. It is
	// generated automatically and can be changed from the Relay page.
	Device string `yaml:"Device,omitempty"`
	// EnrollURL is the enrollment endpoint used to obtain the certificate; it
	// is kept so the Relay page can pre-fill it for a renewal.
	EnrollURL string `yaml:"EnrollURL,omitempty"`
	// AllowLocal lets contacts reach services bound to this machine (off by default).
	AllowLocal bool `yaml:"AllowLocal"`
	// NetworkLabel is a name you choose for the network this device is on (for
	// instance "office-vpn"). It is shared with your approved contacts, together
	// with whether a VPN is active, so routes and rules can pick an exit by
	// where it is. Nothing else about your network is shared.
	NetworkLabel string `yaml:"NetworkLabel,omitempty"`
	// NetworkLabels name the network this device is on, by what it detects:
	// the first entry whose conditions all hold gives the label shared with
	// this relay's contacts; NetworkLabel is the fallback. Being part of the
	// relay's own configuration, each relay can show its contacts a different
	// label for the same network.
	NetworkLabels []NetworkLabel `yaml:"NetworkLabels,omitempty"`
	// ShareContext turns that sharing off when false. Unset means on.
	ShareContext *bool `yaml:"ShareContext,omitempty"`
}

type Configuration struct {
	// Relay is the legacy single-relay setting. It is moved into Relays when the
	// configuration is loaded and not written back.
	Relay *RelayConfig `yaml:"Relay,omitempty"`
	// Relays are the relay servers this installation connects to, all at once.
	// Each has its own identity, address book, approvals and network labels.
	Relays             []*RelayConfig     `yaml:"Relays,omitempty"`
	Address            string             `yaml:"Address"`
	SocksAddress       string             `yaml:"SocksAddress,omitempty"` // optional SOCKS5 listener, empty = disabled
	Credentials        []ConfigCredential `yaml:"Credentials"`
	Routes             []ConfigRoute      `yaml:"Routes"`
	Rules              []ConfigRule       `yaml:"Rules,omitempty"`
	SystemProxy        bool               `yaml:"SystemProxy"`
	SystemProxyExclude []string           `yaml:"SystemProxyExclude"`
	ForceChrome        bool               `yaml:"ForceChrome"`
	// AllowRemoteClients lets machines other than this one use the HTTP and
	// SOCKS5 listeners. The proxy has no client authentication and forwards with
	// your upstream credentials, so it is off unless you explicitly enable it.
	AllowRemoteClients bool `yaml:"AllowRemoteClients"`
	// OnboardingDone is nil for legacy configurations (treated as done) and
	// false for a freshly bootstrapped configuration until the web onboarding
	// is completed.
	OnboardingDone *bool `yaml:"OnboardingDone,omitempty"`
	// Hosts maps a hostname to the IP address it must be dialed at, whatever the system DNS says
	// (for instance when a VPN hands out a resolver that does not know an internal name).
	Hosts map[string]string `yaml:"Hosts"`
	// Blocking turns the proxy into an ad, tracker and malware blocker (see
	// blocking.go); it works with or without a relay.
	Blocking BlockingConfig `yaml:"Blocking,omitempty"`
}

var configuration Configuration

var hostsMu sync.RWMutex

// hostOverride returns the configured fixed IP for a hostname.
func hostOverride(host string) (string, bool) {
	hostsMu.RLock()
	defer hostsMu.RUnlock()
	address, ok := configuration.Hosts[strings.ToLower(host)]
	return address, ok
}

func boolPtr(v bool) *bool { return &v }

// secureConfigFile restricts a file containing secrets to the current user.
// It is best effort: the process may not be allowed to change the permissions
// (in that case a warning is logged and the file is still used).
func secureConfigFile(path string) {
	if runtime.GOOS == "windows" {
		// On Windows the file ACLs are inherited from the directory; the
		// Unix mode bits are not meaningful here.
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	if info.Mode().Perm()&0o077 == 0 {
		return
	}
	if err := os.Chmod(path, 0o600); err != nil {
		log.Printf("WARNING: %s contains credentials but is readable by other users (%v); fix its permissions manually", path, err)
		return
	}
	log.Printf("%s contains credentials: permissions restricted to 0600", path)
}

func loadConfiguration() {
	if data, err := os.ReadFile(encryptedConfig); err == nil {
		secureConfigFile(encryptedConfig)
		plain, err := unlockConfigStored(data)
		if err != nil {
			if !errors.Is(err, errConfigLocked) {
				log.Fatal(err)
			}
			// No stored key: use the terminal when available, otherwise open
			// the unlock page in the browser. A GUI app has no usable stdin,
			// which is why this must not fail with a silent log.Fatal.
			if hasTerminal() {
				plain, err = unlockConfigInteractive(data)
				if err != nil {
					log.Fatal(err)
				}
			} else {
				if err := runUnlockWizard(data); err != nil {
					log.Fatal(err)
				}
				return
			}
		}
		if err := finishEncryptedConfiguration(plain); err != nil {
			log.Fatal(err)
		}
	} else if os.IsNotExist(err) {
		// Legacy plaintext configuration: load it and migrate automatically to
		// the encrypted format, embedding the relay certificate and key.
		data, err := os.ReadFile(plainConfig)
		if err != nil {
			log.Fatalf("no configuration found (%s or %s)", encryptedConfig, plainConfig)
		}
		secureConfigFile(plainConfig)
		if err := applyConfigurationPlaintext(data, plainConfig); err != nil {
			log.Fatal(err)
		}
		if err := runMigrationWizard(); err != nil {
			log.Fatal(err)
		}
	} else {
		log.Fatal(err)
	}
}

// finishEncryptedConfiguration applies a successfully decrypted configuration,
// removes plaintext leftovers and initializes the runtime state.
func finishEncryptedConfiguration(plain []byte) error {
	if err := applyConfigurationPlaintext(plain, encryptedConfig); err != nil {
		return err
	}
	// The encrypted file is valid: any plaintext leftover is a leak.
	removePlaintextLeftovers()
	finalizeConfiguration()
	return nil
}

// applyConfigurationPlaintext parses a configuration and marks legacy ones as
// already onboarded.
func applyConfigurationPlaintext(plain []byte, source string) error {
	if err := yaml.Unmarshal(plain, &configuration); err != nil {
		return fmt.Errorf("%s: %w", source, err)
	}
	if configuration.OnboardingDone == nil {
		// Existing configurations predate onboarding: do not show it.
		configuration.OnboardingDone = boolPtr(true)
	}
	return nil
}

// finalizeConfiguration validates and applies a configuration that has already
// been loaded (or created by the first-run web setup).
func finalizeConfiguration() {
	hosts := map[string]string{}
	for host, address := range configuration.Hosts {
		if net.ParseIP(address) == nil {
			log.Fatalf("configuration: Hosts[%s]: %q is not an IP address", host, address)
		}
		hosts[strings.ToLower(host)] = address
	}
	configuration.Hosts = hosts

	if migrateRelayConfigs() {
		if err := persistConfigurationLocked(); err != nil {
			log.Printf("WARNING: cannot persist the relay migration: %v", err)
		}
	}
	ensureRelayDevice()
	enforceRemotePolicy()
	if migrateRouteUpstreams() {
		if err := persistConfigurationLocked(); err != nil {
			log.Printf("WARNING: cannot persist the route upstream migration: %v", err)
		}
	}
	loadRoutes()
}

// migrateToEncrypted converts the legacy plaintext configuration into the
// encrypted one, asking for a new master password interactively (or from the
// environment).
func migrateToEncrypted() error {
	log.Printf("Encrypting the configuration: choose a master password and keep it safe, it cannot be recovered")
	pass, err := newMasterPassword()
	if err != nil {
		return err
	}
	return migrateToEncryptedWithPassword(pass)
}

// migrateToEncryptedWithPassword performs the legacy migration with a master
// password supplied by the web setup page or the environment.
func migrateToEncryptedWithPassword(pass string) error {
	if len(pass) < minPasswordLen {
		return fmt.Errorf("the master password must be at least %d characters", minPasswordLen)
	}
	for _, cfg := range allRelayConfigs() {
		if cfg.Address == "" {
			continue
		}
		certPEM, keyPEM, err := readRelayPEM(cfg)
		if err != nil {
			return fmt.Errorf("relay certificate/key: %w", err)
		}
		cfg.CertPEM = string(certPEM)
		cfg.KeyPEM = string(keyPEM)
		if cfg.CA != "" {
			caPEM, err := os.ReadFile(cfg.CA)
			if err != nil {
				return fmt.Errorf("relay CA: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caPEM) {
				return fmt.Errorf("relay CA %s: no certificates found", cfg.CA)
			}
			cfg.CAPEM = string(caPEM)
		}
	}

	plain, err := yaml.Marshal(configuration)
	if err != nil {
		return err
	}
	salt, err := newSecretSalt()
	if err != nil {
		return err
	}
	key, err := deriveSecretKey(pass, salt)
	if err != nil {
		return err
	}
	enc, err := encryptWithKey(key, salt, plain)
	if err != nil {
		return err
	}
	if _, err := decryptWithKey(key, enc); err != nil {
		return fmt.Errorf("verifying the encrypted file: %w", err)
	}
	if err := writeSecretFileAtomic(encryptedConfig, enc); err != nil {
		return err
	}
	setConfigCrypto(key, salt)
	saveKeyToKeychain(key, salt)
	removePlaintextLeftovers()
	log.Printf("Configuration migrated to %s: credentials and relay key are encrypted inside it", encryptedConfig)
	return nil
}

// removePlaintextLeftovers deletes the legacy files that would keep secrets in
// clear text once the encrypted configuration is in use.
func removePlaintextLeftovers() {
	for _, path := range []string{plainConfig, plainConfig + ".tmp"} {
		if err := os.Remove(path); err == nil {
			log.Printf("Removed plaintext configuration %s", path)
		} else if !os.IsNotExist(err) {
			log.Printf("WARNING: cannot remove %s: %v", path, err)
		}
	}
	for _, cfg := range allRelayConfigs() {
		if cfg.KeyPEM == "" || cfg.Key == "" {
			continue
		}
		if err := os.Remove(cfg.Key); err == nil {
			log.Printf("Removed plaintext relay key %s (now embedded in %s)", cfg.Key, encryptedConfig)
		} else if !os.IsNotExist(err) {
			log.Printf("WARNING: cannot remove relay private key %s: %v", cfg.Key, err)
		}
	}
}

// readRelayPEM returns the relay certificate and private key, either from the
// encrypted configuration (embedded PEMs) or from the legacy files.
func readRelayPEM(cfg *RelayConfig) (certPEM, keyPEM []byte, err error) {
	if cfg.CertPEM != "" && cfg.KeyPEM != "" {
		certPEM, keyPEM = []byte(cfg.CertPEM), []byte(cfg.KeyPEM)
	} else {
		if cfg.Cert == "" || cfg.Key == "" {
			return nil, nil, errors.New("relay certificate/key not configured")
		}
		if certPEM, err = os.ReadFile(cfg.Cert); err != nil {
			return nil, nil, err
		}
		if keyPEM, err = os.ReadFile(cfg.Key); err != nil {
			return nil, nil, err
		}
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return nil, nil, err
	}
	return certPEM, keyPEM, nil
}

func relayCertificate(cfg *RelayConfig) (tls.Certificate, error) {
	certPEM, keyPEM, err := readRelayPEM(cfg)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
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
