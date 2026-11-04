// proxyrelay is the rendezvous relay for the proxy, plus the tooling to
// manage the certificate authority that identifies its clients.
//
//	proxyrelay ca init   -dir ca
//	proxyrelay ca server -dir ca -out server -host relay.example.com
//	proxyrelay ca client -dir ca -out alice -email alice@example.com
//	proxyrelay serve -listen :8443 -cert server/server.pem -key server/server-key.pem -ca ca/ca.pem -state relay-state.json
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"proxy/relay"
)

func usage() {
	fmt.Fprint(os.Stderr, `usage:
  proxyrelay ca init   -dir DIR
  proxyrelay ca server -dir DIR -out DIR -host NAME[,NAME...]
  proxyrelay ca client -dir DIR -out DIR -email ADDRESS
  proxyrelay serve -listen ADDR -cert FILE -key FILE -ca FILE [-state FILE]
                   [-enroll-listen ADDR -public-relay HOST:PORT -smtp-addr HOST:PORT
                    -smtp-from ADDRESS [-public-url URL] [-download-url URL]
                    [-allow-domains DOMAIN[,DOMAIN...]] [-smtp-user USER -smtp-pass PASS]
                    [-smtp-auth auto|plain|login|none] [-smtp-tls starttls|tls|none]
                    [-ca-dir DIR] [-enroll-state FILE] [-enroll-plain]]
  proxyrelay invite -email ADDRESS -public-url URL -smtp-addr HOST:PORT -smtp-from ADDRESS
                    [-download-url URL] [-smtp-user USER] [-smtp-pass PASS]
                    [-smtp-auth auto|plain|login|none] [-smtp-tls starttls|tls|none]
`)
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "ca":
		runCA(os.Args[2:])
	case "serve":
		runServe(os.Args[2:])
	case "invite":
		runInvite(os.Args[2:])
	default:
		usage()
	}
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func runCA(args []string) {
	if len(args) < 1 {
		usage()
	}
	fs := flag.NewFlagSet("ca "+args[0], flag.ExitOnError)
	dir := fs.String("dir", "ca", "CA directory")
	out := fs.String("out", "", "output directory")
	host := fs.String("host", "", "server host names / IPs, comma separated")
	email := fs.String("email", "", "client e-mail address")
	fs.Parse(args[1:])

	switch args[0] {
	case "init":
		check(relay.InitCA(*dir))
		fmt.Println("CA created in", *dir, "- keep ca-key.pem secret")
	case "server":
		if *out == "" {
			usage()
		}
		check(relay.IssueServer(*dir, *out, strings.Split(*host, ",")))
		fmt.Println("server certificate written to", *out)
	case "client":
		if *out == "" || *email == "" {
			usage()
		}
		check(relay.IssueClient(*dir, *out, *email))
		fmt.Println("client certificate for", *email, "written to", *out, "(client.pem, client-key.pem, ca.pem)")
	default:
		usage()
	}
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", ":8443", "listen address")
	cert := fs.String("cert", "", "server certificate")
	key := fs.String("key", "", "server key")
	ca := fs.String("ca", "", "CA certificate that signs the clients")
	state := fs.String("state", "relay-state.json", "address book file")
	enrollListen := fs.String("enroll-listen", "", "HTTPS enrollment listen address (empty disables enrollment)")
	enrollPlain := fs.Bool("enroll-plain", false, "serve enrollment over plain HTTP (only behind a trusted TLS proxy)")
	publicRelay := fs.String("public-relay", "", "relay host:port clients connect to with mTLS")
	publicURL := fs.String("public-url", "", "public enrollment URL shown in emails")
	downloadURL := fs.String("download-url", "", "proxy download URL shown in invitation emails")
	allowDomains := fs.String("allow-domains", "", "comma-separated e-mail domains allowed to enroll (empty = all)")
	smtpAddr := fs.String("smtp-addr", "", "SMTP server host:port")
	smtpUser := fs.String("smtp-user", "", "SMTP username")
	smtpPass := fs.String("smtp-pass", "", "SMTP password")
	smtpFrom := fs.String("smtp-from", "", "From: address for enrollment emails")
	smtpTLS := fs.String("smtp-tls", "starttls", "SMTP security: starttls, tls or none")
	smtpAuth := fs.String("smtp-auth", "auto", "SMTP authentication: auto, plain, login or none")
	caDir := fs.String("ca-dir", "", "CA directory with ca.pem and ca-key.pem (default: directory of -ca)")
	enrollState := fs.String("enroll-state", "relay-enroll.json", "pending enrollment file")
	certTTL := fs.Duration("cert-ttl", 90*24*time.Hour, "client certificate lifetime")
	fs.Parse(args)
	envString(smtpAddr, "PROXYRELAY_SMTP_ADDR")
	envString(smtpFrom, "PROXYRELAY_SMTP_FROM")
	envString(smtpUser, "PROXYRELAY_SMTP_USER")
	envString(smtpPass, "PROXYRELAY_SMTP_PASS")
	if v := os.Getenv("PROXYRELAY_SMTP_TLS"); v != "" {
		*smtpTLS = v
	}
	if v := os.Getenv("PROXYRELAY_SMTP_AUTH"); v != "" {
		*smtpAuth = v
	}
	if *cert == "" || *key == "" || *ca == "" {
		usage()
	}

	cfg, err := relay.TLSConfig(*cert, *key, *ca)
	check(err)
	store, err := relay.NewStore(*state)
	check(err)
	relayCAPEM, err := os.ReadFile(*ca)
	check(err)

	if *enrollListen != "" {
		if *publicRelay == "" || *smtpAddr == "" || *smtpFrom == "" {
			log.Printf("enrollment disabled: missing public relay or SMTP configuration (fill the SMTP secret and restart)")
		} else {
			dir := *caDir
			if dir == "" {
				dir = filepath.Dir(*ca)
			}
			es, err := relay.NewEnrollServer(relay.EnrollConfig{
				CADir:          dir,
				PublicRelay:    *publicRelay,
				PublicURL:      *publicURL,
				DownloadURL:    *downloadURL,
				RelayCAPEM:     string(relayCAPEM),
				AllowedDomains: splitList(*allowDomains),
				SMTPAddr:       *smtpAddr,
				SMTPUser:       *smtpUser,
				SMTPPass:       *smtpPass,
				SMTPFrom:       *smtpFrom,
				SMTPTLS:        *smtpTLS,
				SMTPAuth:       *smtpAuth,
				StatePath:      *enrollState,
				CertTTL:        *certTTL,
			})
			if err != nil {
				log.Printf("enrollment disabled: %v", err)
			} else {
				eln, err := net.Listen("tcp", *enrollListen)
				check(err)
				srv := &http.Server{
					Handler:           es.Handler(),
					ReadHeaderTimeout: 10 * time.Second,
					ReadTimeout:       30 * time.Second,
					WriteTimeout:      30 * time.Second,
					IdleTimeout:       60 * time.Second,
				}
				if *enrollPlain {
					log.Printf("enrollment listening on %s (plain HTTP, trusted proxy only)", *enrollListen)
					go func() { log.Fatal(srv.Serve(eln)) }()
				} else {
					serverCert, err := tls.LoadX509KeyPair(*cert, *key)
					check(err)
					log.Printf("enrollment listening on %s", *enrollListen)
					go func() {
						log.Fatal(srv.Serve(tls.NewListener(eln, &tls.Config{
							Certificates: []tls.Certificate{serverCert},
							MinVersion:   tls.VersionTLS12,
						})))
					}()
				}
			}
		}
	}

	ln, err := net.Listen("tcp", *listen)
	check(err)
	log.Printf("relay listening on %s", *listen)
	check(relay.NewServer(store).Serve(tls.NewListener(ln, cfg)))
}

func envString(p *string, key string) {
	if *p == "" {
		if v := os.Getenv(key); v != "" {
			*p = v
		}
	}
}

func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func runInvite(args []string) {
	fs := flag.NewFlagSet("invite", flag.ExitOnError)
	email := fs.String("email", "", "address to invite")
	publicURL := fs.String("public-url", "", "enrollment URL shown in the e-mail")
	downloadURL := fs.String("download-url", "", "proxy download URL")
	smtpAddr := fs.String("smtp-addr", "", "SMTP server host:port")
	smtpUser := fs.String("smtp-user", "", "SMTP username")
	smtpPass := fs.String("smtp-pass", "", "SMTP password (or PROXYRELAY_SMTP_PASS)")
	smtpFrom := fs.String("smtp-from", "", "From: address")
	smtpTLS := fs.String("smtp-tls", "starttls", "SMTP security: starttls, tls or none")
	smtpAuth := fs.String("smtp-auth", "auto", "SMTP authentication: auto, plain, login or none")
	fs.Parse(args)
	envString(smtpAddr, "PROXYRELAY_SMTP_ADDR")
	envString(smtpFrom, "PROXYRELAY_SMTP_FROM")
	envString(smtpUser, "PROXYRELAY_SMTP_USER")
	envString(smtpPass, "PROXYRELAY_SMTP_PASS")
	if v := os.Getenv("PROXYRELAY_SMTP_TLS"); v != "" {
		*smtpTLS = v
	}
	if v := os.Getenv("PROXYRELAY_SMTP_AUTH"); v != "" {
		*smtpAuth = v
	}
	if *email == "" || *publicURL == "" || *smtpAddr == "" || *smtpFrom == "" {
		usage()
	}
	check(relay.SendInvite(relay.EnrollConfig{
		PublicURL:   *publicURL,
		DownloadURL: *downloadURL,
		SMTPAddr:    *smtpAddr,
		SMTPUser:    *smtpUser,
		SMTPPass:    *smtpPass,
		SMTPFrom:    *smtpFrom,
		SMTPTLS:     *smtpTLS,
		SMTPAuth:    *smtpAuth,
	}, *email))
	fmt.Println("invitation sent to", *email)
}
