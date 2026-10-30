package main

import (
	"log"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type ConfigCredential struct {
	Name     string `yaml:"Name"`
	User     string `yaml:"User"`
	Password string `yaml:"Password"`
}

type ConfigRoute struct {
	Name       string `yaml:"Name"`
	Gateway    string `yaml:"Gateway"`
	IFace      string `yaml:"IFace"`
	Net        string `yaml:"Net"`
	PacUrl     string `yaml:"PacUrl"`
	ProxyUrl   string `yaml:"ProxyUrl"`
	Credential string `yaml:"Credential"`
}

type Configuration struct {
	Address            string             `yaml:"Address"`
	Credentials        []ConfigCredential `yaml:"Credentials"`
	Routes             []ConfigRoute      `yaml:"Routes"`
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
