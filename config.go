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
	// RulesOnly makes this hop a boundary: the chain stops before it unless
	// the route was selected by a destination rule.
	RulesOnly bool `yaml:"RulesOnly,omitempty" json:"rulesOnly"`
}

// RelayConfig connects this proxy to a relay (see cmd/proxyrelay) so that it can
// reach, and be reached by, the contacts in the address book.
type RelayConfig struct {
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
}

type Configuration struct {
	Relay              *RelayConfig       `yaml:"Relay,omitempty"`
	Address            string             `yaml:"Address"`
	SocksAddress       string             `yaml:"SocksAddress,omitempty"` // optional SOCKS5 listener, empty = disabled
	Credentials        []ConfigCredential `yaml:"Credentials"`
	Routes             []ConfigRoute      `yaml:"Routes"`
	Rules              []ConfigRule       `yaml:"Rules,omitempty"`
	SystemProxy        bool               `yaml:"SystemProxy"`
	SystemProxyExclude []string           `yaml:"SystemProxyExclude"`
	PacHijack          bool               `yaml:"PacHijack"`
	PacHijackHost      string             `yaml:"PacHijackHost"`
	ForceChrome        bool               `yaml:"ForceChrome"`
	// OnboardingDone is nil for legacy configurations (treated as done) and
	// false for a freshly bootstrapped configuration until the web onboarding
	// is completed.
	OnboardingDone *bool `yaml:"OnboardingDone,omitempty"`
	// Hosts maps a hostname to the IP address it must be dialed at, whatever the system DNS says
	// (for instance when a VPN hands out a resolver that does not know an internal name).
	Hosts map[string]string `yaml:"Hosts"`
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
		plain, err := unlockConfig(data)
		if err != nil {
			log.Fatal(err)
		}
		if err := yaml.Unmarshal(plain, &configuration); err != nil {
			log.Fatalf("%s: %v", encryptedConfig, err)
		}
		if configuration.OnboardingDone == nil {
			// Existing configurations predate onboarding: do not show it.
			configuration.OnboardingDone = boolPtr(true)
		}
		// The encrypted file is valid: any plaintext leftover is a leak.
		removePlaintextLeftovers()
	} else if os.IsNotExist(err) {
		// Legacy plaintext configuration: load it and migrate automatically to
		// the encrypted format, embedding the relay certificate and key.
		data, err := os.ReadFile(plainConfig)
		if err != nil {
			log.Fatalf("no configuration found (%s or %s)", encryptedConfig, plainConfig)
		}
		secureConfigFile(plainConfig)
		if err := yaml.Unmarshal(data, &configuration); err != nil {
			log.Fatalf("%s: %v", plainConfig, err)
		}
		if configuration.OnboardingDone == nil {
			// Existing configurations predate onboarding: do not show it.
			configuration.OnboardingDone = boolPtr(true)
		}
		if err := migrateToEncrypted(); err != nil {
			log.Fatalf("cannot migrate %s to %s: %v", plainConfig, encryptedConfig, err)
		}
	} else {
		log.Fatal(err)
	}

	finalizeConfiguration()
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

	ensureRelayDevice()
	loadRoutes()
}

// migrateToEncrypted converts the legacy plaintext configuration into the
// encrypted one, moving the relay certificate and private key inside it and
// removing the files that would otherwise keep the secrets in clear text.
func migrateToEncrypted() error {
	log.Printf("Encrypting the configuration: choose a master password and keep it safe, it cannot be recovered")
	pass, err := newMasterPassword()
	if err != nil {
		return err
	}
	if cfg := configuration.Relay; cfg != nil && cfg.Address != "" {
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
	if cfg := configuration.Relay; cfg != nil && cfg.KeyPEM != "" && cfg.Key != "" {
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
