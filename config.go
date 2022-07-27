package main

import (
	"log"
	"os"

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
	PacUrl     string `yaml:"PacUrl"`
	ProxyUrl   string `yaml:"ProxyUrl"`
	Credential string `yaml:"Credential"`
}

type Configuration struct {
	Address     string             `yaml:"Address"`
	Credentials []ConfigCredential `yaml:"Credentials"`
	Routes      []ConfigRoute      `yaml:"Routes"`
}

var configuration Configuration

func loadConfiguration() {
	cfg, err := os.Open("config.yml")
	if err != nil {
		log.Fatal(err)
	}
	yaml.NewDecoder(cfg).Decode(&configuration)

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
