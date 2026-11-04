// Command proxygateway is the application gateway of a relay: run it next to an
// application (or on the network that reaches it). It connects out to the
// relay with its own certificate, is told which applications it serves, and
// connects only to their backends when an authorised user opens one.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"proxy/relay"
)

func main() {
	var cfg relay.GatewayConfig
	flag.StringVar(&cfg.Address, "relay", os.Getenv("GATEWAY_RELAY"), "relay mTLS address, host:port")
	flag.StringVar(&cfg.CertFile, "cert", "gateway.pem", "gateway certificate")
	flag.StringVar(&cfg.KeyFile, "key", "gateway-key.pem", "gateway private key")
	flag.StringVar(&cfg.CAFile, "ca", "ca.pem", "CA that signed the relay's server certificate")
	flag.StringVar(&cfg.ServerName, "server-name", "", "name in the relay's certificate (default: host of -relay)")
	flag.Parse()

	g, err := relay.NewGateway(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("proxygateway: connecting to %s", cfg.Address)
	g.Run(ctx)
}
