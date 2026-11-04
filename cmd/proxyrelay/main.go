// Command proxyrelay is the relay server of Go Smart Proxy: the rendezvous
// between proxies, with enrollment, optional sign-in methods, an optional
// management interface and the applications catalog.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"proxy/relay"
)

const usage = `usage: proxyrelay <command> [flags]

commands:
  ca init -dir DIR                          create a certificate authority
  ca server -dir DIR -out DIR -host H,H     issue the relay's server certificate
  ca client -dir DIR -out DIR -email E      issue a client certificate (manual provisioning)
  ca gateway -dir DIR -out DIR -id ID       issue an application gateway certificate
  serve [flags]                             run the relay (see -h)
  invite -email E [flags]                   e-mail an invitation
  revoke [-file F] ENTRY...                 revoke an e-mail address or "serial:HEX"
  unrevoke [-file F] ENTRY...               lift a revocation
  user add -file F -name N [-email E] [-groups G,G]
                                            add a user to a password users file
  admin user -db DB -name N [-email E] [-groups G,G]
                                            create or update a local user in the
                                            management interface database
`

func main() {
	log.SetFlags(log.LstdFlags)
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "ca":
		err = runCA(os.Args[2:])
	case "serve":
		err = runServe(os.Args[2:])
	case "invite":
		err = runInvite(os.Args[2:])
	case "revoke":
		err = runRevoke(os.Args[2:], true)
	case "unrevoke":
		err = runRevoke(os.Args[2:], false)
	case "user":
		err = runUser(os.Args[2:])
	case "admin":
		err = runAdminUser(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "proxyrelay:", err)
		os.Exit(1)
	}
}

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseTTL accepts a Go duration ("720h") or a number of days ("90d").
func parseTTL(s string) (time.Duration, error) {
	if d, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(d)
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("invalid lifetime %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// ---- ca ---------------------------------------------------------------

func runCA(args []string) error {
	if len(args) == 0 {
		return errors.New("ca: init, server, client or gateway")
	}
	fs := flag.NewFlagSet("ca "+args[0], flag.ExitOnError)
	dir := fs.String("dir", "ca", "CA directory")
	out := fs.String("out", "", "output directory")
	hosts := fs.String("host", "", "server: comma-separated host names and IPs")
	email := fs.String("email", "", "client: e-mail address")
	id := fs.String("id", "", "gateway: identifier")
	fs.Parse(args[1:])
	switch args[0] {
	case "init":
		return relay.InitCA(*dir)
	case "server":
		if *out == "" || *hosts == "" {
			return errors.New("ca server needs -out and -host")
		}
		return relay.IssueServer(*dir, *out, splitList(*hosts))
	case "client":
		if *out == "" || *email == "" {
			return errors.New("ca client needs -out and -email")
		}
		return relay.IssueClient(*dir, *out, *email)
	case "gateway":
		if *out == "" || *id == "" {
			return errors.New("ca gateway needs -out and -id")
		}
		return relay.IssueGateway(*dir, *out, *id)
	}
	return fmt.Errorf("ca: unknown command %q", args[0])
}

// ---- serve ------------------------------------------------------------

type smtpFlags struct {
	addr, user, pass, from, tls, auth *string
}

func addSMTPFlags(fs *flag.FlagSet) smtpFlags {
	return smtpFlags{
		addr: fs.String("smtp-addr", env("PROXYRELAY_SMTP_ADDR", ""), "SMTP server host:port"),
		user: fs.String("smtp-user", env("PROXYRELAY_SMTP_USER", ""), "SMTP user"),
		pass: fs.String("smtp-pass", env("PROXYRELAY_SMTP_PASS", ""), "SMTP password (prefer PROXYRELAY_SMTP_PASS)"),
		from: fs.String("smtp-from", env("PROXYRELAY_SMTP_FROM", ""), "From address"),
		tls:  fs.String("smtp-tls", "starttls", "starttls, tls or none (PROXYRELAY_SMTP_TLS, when set, wins)"),
		auth: fs.String("smtp-auth", "auto", "auto, plain, login or none (PROXYRELAY_SMTP_AUTH, when set, wins)"),
	}
}

func (f smtpFlags) apply(c *relay.EnrollConfig) {
	// As before: for these two the environment, when set, wins over the flag.
	if v := os.Getenv("PROXYRELAY_SMTP_TLS"); v != "" {
		*f.tls = v
	}
	if v := os.Getenv("PROXYRELAY_SMTP_AUTH"); v != "" {
		*f.auth = v
	}
	c.SMTPAddr, c.SMTPUser, c.SMTPPass, c.SMTPFrom, c.SMTPTLS, c.SMTPAuth = *f.addr, *f.user, *f.pass, *f.from, *f.tls, *f.auth
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", ":8443", "mTLS relay listen address")
	certFile := fs.String("cert", "server/server.pem", "server certificate")
	keyFile := fs.String("key", "server/server-key.pem", "server key")
	caFile := fs.String("ca", "ca/ca.pem", "CA that signs and verifies client certificates")
	statePath := fs.String("state", "relay-state.json", "address book state file")
	enrollListen := fs.String("enroll-listen", "", "HTTPS enrollment listen address (empty disables enrollment)")
	enrollPlain := fs.Bool("enroll-plain", false, "serve enrollment over HTTP behind a trusted TLS proxy")
	publicRelay := fs.String("public-relay", "", "mTLS address returned to clients, host:port")
	publicURL := fs.String("public-url", "", "enrollment URL (shown in e-mails, used for sign-in callbacks)")
	downloadURL := fs.String("download-url", "", "proxy download URL for invitations")
	allowDomains := fs.String("allow-domains", "", "comma-separated e-mail domains allowed to enroll")
	caDir := fs.String("ca-dir", "", "directory with ca.pem and ca-key.pem (default: dir of -ca)")
	enrollState := fs.String("enroll-state", "relay-enroll.json", "pending enrollment state file")
	certTTL := fs.String("cert-ttl", "90d", "client certificate lifetime (e.g. 90d, 720h)")
	maxRenew := fs.String("max-renew-age", "365d", "how long a device's certificate may be renewed without signing in again")
	revoked := fs.String("revoked", "", "revocation list file, e-mail or serial:HEX per line (default: revoked.txt next to -state)")
	authConfig := fs.String("auth-config", "", "YAML file with the sign-in methods (password, ldap, oidc, saml)")
	trustXFF := fs.Bool("trust-forwarded-for", false, "take the client address from X-Forwarded-For (only behind a trusted proxy)")
	appsFile := fs.String("apps", "", "YAML file with the applications catalog (read-only); without it the interface edits the catalog")
	policyFile := fs.String("policy", "", "YAML file with the blocking policy (read-only); without it the interface edits the policy")
	policyDir := fs.String("policy-dir", "", "where downloaded block lists are kept (default: policy-lists next to -state)")
	metricsListen := fs.String("metrics-listen", "", "serve /healthz, /readyz and /metrics here (e.g. 127.0.0.1:9100); empty disables")
	metricsToken := fs.String("metrics-token", env("PROXYRELAY_METRICS_TOKEN", ""), "bearer token required for /metrics (prefer PROXYRELAY_METRICS_TOKEN)")
	logFormat := fs.String("log-format", env("PROXYRELAY_LOG_FORMAT", "text"), "text or json")
	adminDB := fs.String("admin-db", "", "enable the management interface (/admin/) with this SQLite database")
	adminGroups := fs.String("admin-groups", "", "groups whose members are administrators")
	adminEmails := fs.String("admin-emails", "", "e-mail addresses that are administrators")
	adminMethods := fs.String("admin-methods", "", "sign-in method ids allowed for administrators (default: all)")
	adminSession := fs.String("admin-session", "8h", "administrator session lifetime")
	smtp := addSMTPFlags(fs)
	fs.Parse(args)

	if *certFile == "" || *keyFile == "" || *caFile == "" {
		return errors.New("serve needs -cert, -key and -ca")
	}
	if err := setupLogging(*logFormat); err != nil {
		return err
	}
	ttl, err := parseTTL(*certTTL)
	if err != nil {
		return err
	}
	renewAge, err := parseTTL(*maxRenew)
	if err != nil {
		return fmt.Errorf("-max-renew-age: %w", err)
	}
	tlsCfg, err := relay.TLSConfig(*certFile, *keyFile, *caFile)
	if err != nil {
		return err
	}
	store, err := relay.NewStore(*statePath)
	if err != nil {
		return err
	}
	srv := relay.NewServer(store)
	// Revocation is always on: users revoke their own certificates and the
	// interface edits the same list.
	if *revoked == "" {
		*revoked = filepath.Join(filepath.Dir(*statePath), "revoked.txt")
	}
	rev := relay.NewRevocations(*revoked)
	srv.Revoked = rev

	// Catalog of applications: a file, or the management interface's.
	var catalog *relay.Catalog
	switch {
	case *appsFile != "":
		if catalog, err = relay.LoadCatalogFile(*appsFile); err != nil {
			return err
		}
		defer catalog.Close()
	case *adminDB != "":
		catalog = relay.NewCatalog()
	}
	if catalog != nil {
		srv.AttachCatalog(catalog)
	}

	// Blocking policy: a file, or the management interface's.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var policy *relay.Policy
	if *policyDir == "" {
		*policyDir = filepath.Join(filepath.Dir(*statePath), "policy-lists")
	}
	switch {
	case *policyFile != "":
		if policy, err = relay.LoadPolicyFile(*policyFile, *policyDir); err != nil {
			return err
		}
	case *adminDB != "":
		policy = relay.NewPolicy(*policyDir)
	}
	if policy != nil {
		srv.AttachPolicy(policy)
		go policy.Run(ctx)
	}

	// Management interface.
	var admin *relay.Admin
	if *adminDB != "" {
		sessTTL, err := time.ParseDuration(*adminSession)
		if err != nil {
			return fmt.Errorf("-admin-session: %w", err)
		}
		if admin, err = relay.NewAdmin(relay.AdminConfig{
			DBPath: *adminDB, Groups: splitList(*adminGroups), Emails: splitList(*adminEmails), Methods: splitList(*adminMethods),
			Revoked: rev, SessionTTL: sessTTL,
		}); err != nil {
			return err
		}
		defer admin.Close()
		admin.SetServer(srv)
		if err := admin.SetCatalog(catalog); err != nil {
			return err
		}
		if err := admin.SetPolicy(policy); err != nil {
			return err
		}
	}

	ln, err := tls.Listen("tcp", *listen, tlsCfg)
	if err != nil {
		return err
	}
	log.Printf("relay listening on %s", ln.Addr())
	go func() {
		if err := srv.Serve(ln); err != nil && ctx.Err() == nil {
			log.Fatalf("relay: %v", err)
		}
	}()

	var enrollSrv *http.Server
	var enrollForMetrics *relay.EnrollServer
	if *enrollListen != "" {
		cfg := relay.EnrollConfig{
			CADir: firstNonEmpty(*caDir, filepath.Dir(*caFile)), PublicRelay: *publicRelay, PublicURL: *publicURL, DownloadURL: *downloadURL,
			AllowedDomains: splitList(*allowDomains), StatePath: *enrollState, CertTTL: ttl,
			TrustForwardedFor: *trustXFF, Admin: admin, Store: store, MaxRenewAge: renewAge,
			Revoked: rev, Disconnect: srv.Kick,
		}
		smtp.apply(&cfg)
		if pem, err := os.ReadFile(*caFile); err == nil {
			cfg.RelayCAPEM = string(pem)
		}
		if *authConfig != "" {
			if cfg.Auth, err = relay.LoadAuthConfig(*authConfig); err != nil {
				return err
			}
		}
		es, err := relay.NewEnrollServer(cfg)
		if err != nil {
			// A broken enrollment must not take the relay down with it: the
			// SMTP secret may be filled in later.
			log.Printf("enrollment disabled: %v", err)
			if admin != nil {
				log.Printf("the management interface is served by the enrollment listener and is disabled too")
			}
		} else {
			srv.SetRenewer(es.RenewCertificate)
			enrollForMetrics = es
			enrollSrv = &http.Server{
				Addr: *enrollListen, Handler: es.Handler(),
				ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
				WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
			}
			go func() {
				var err error
				if *enrollPlain {
					log.Printf("enrollment listening on %s (plain HTTP: put a TLS proxy in front)", *enrollListen)
					err = enrollSrv.ListenAndServe()
				} else {
					cert, cerr := tls.LoadX509KeyPair(*certFile, *keyFile)
					if cerr != nil {
						log.Fatalf("enrollment: %v", cerr)
					}
					enrollSrv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
					log.Printf("enrollment listening on %s", *enrollListen)
					err = enrollSrv.ListenAndServeTLS("", "")
				}
				if err != nil && !errors.Is(err, http.ErrServerClosed) {
					log.Fatalf("enrollment: %v", err)
				}
			}()
			if admin != nil {
				log.Printf("management interface at %s/admin/", strings.TrimRight(*publicURL, "/"))
			}
		}
	} else if admin != nil {
		log.Printf("WARNING: -admin-db needs -enroll-listen: the interface is served by the enrollment listener")
	}

	if *metricsListen != "" {
		obs := &relay.Observer{Server: srv, Enroll: enrollForMetrics, Admin: admin, Policy: policy, Token: *metricsToken, Started: time.Now(), Version: buildVersion()}
		ms := &http.Server{Addr: *metricsListen, Handler: obs.Handler(), ReadHeaderTimeout: 10 * time.Second}
		go func() {
			log.Printf("metrics and health listening on %s", *metricsListen)
			if err := ms.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("metrics: %v", err)
			}
		}()
		defer ms.Close()
		if *metricsToken == "" && !isLoopbackAddr(*metricsListen) {
			log.Printf("WARNING: /metrics is open on %s: set -metrics-token or listen on 127.0.0.1", *metricsListen)
		}
	}

	<-ctx.Done()
	log.Printf("shutting down")
	ln.Close()
	if enrollSrv != nil {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		enrollSrv.Shutdown(sctx)
	}
	return nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ---- invite -----------------------------------------------------------

func runInvite(args []string) error {
	fs := flag.NewFlagSet("invite", flag.ExitOnError)
	email := fs.String("email", "", "address to invite")
	publicURL := fs.String("public-url", "", "enrollment URL")
	downloadURL := fs.String("download-url", "", "proxy download URL")
	smtp := addSMTPFlags(fs)
	fs.Parse(args)
	if *email == "" || *publicURL == "" {
		return errors.New("invite needs -email and -public-url")
	}
	cfg := relay.EnrollConfig{PublicURL: *publicURL, DownloadURL: *downloadURL}
	smtp.apply(&cfg)
	if cfg.SMTPAddr == "" || cfg.SMTPFrom == "" {
		return errors.New("invite needs -smtp-addr and -smtp-from")
	}
	if err := relay.SendInvite(cfg, *email); err != nil {
		return err
	}
	fmt.Println("invitation sent to", *email)
	return nil
}

// ---- revoke -----------------------------------------------------------

func runRevoke(args []string, add bool) error {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	file := fs.String("file", env("PROXYRELAY_REVOKED", "revoked.txt"), "revocation list file")
	fs.Parse(args)
	if fs.NArg() == 0 {
		return errors.New("name an e-mail address or serial:HEX")
	}
	r := relay.NewRevocations(*file)
	for _, e := range fs.Args() {
		var err error
		if add {
			err = r.Add(e)
		} else {
			err = r.Remove(e)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// ---- users ------------------------------------------------------------

// readPassword takes the password from PROXYRELAY_PASSWORD, a terminal prompt
// or standard input: never from an argument, which others could read.
func readPassword() (string, error) {
	if p := os.Getenv("PROXYRELAY_PASSWORD"); p != "" {
		return p, nil
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Password: ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}

func runUser(args []string) error {
	if len(args) == 0 || args[0] != "add" {
		return errors.New("user add -file F -name N [-email E] [-groups G,G]")
	}
	fs := flag.NewFlagSet("user add", flag.ExitOnError)
	file := fs.String("file", "", "users file")
	name := fs.String("name", "", "user name")
	email := fs.String("email", "", "e-mail address (default: the user name)")
	groups := fs.String("groups", "", "comma-separated groups")
	fs.Parse(args[1:])
	if *file == "" || *name == "" {
		return errors.New("user add needs -file and -name")
	}
	pw, err := readPassword()
	if err != nil {
		return err
	}
	return relay.AddPasswordUser(*file, *name, pw, *email, splitList(*groups)...)
}

func runAdminUser(args []string) error {
	if len(args) == 0 || args[0] != "user" {
		return errors.New("admin user -db DB -name N [-email E] [-groups G,G]")
	}
	fs := flag.NewFlagSet("admin user", flag.ExitOnError)
	db := fs.String("db", "", "management interface database")
	name := fs.String("name", "", "user name")
	email := fs.String("email", "", "e-mail address (default: the user name)")
	groups := fs.String("groups", "", "comma-separated groups (an administrator group, for instance)")
	fs.Parse(args[1:])
	if *db == "" || *name == "" {
		return errors.New("admin user needs -db and -name")
	}
	pw, err := readPassword()
	if err != nil {
		return err
	}
	return relay.AddUserToAdminDB(*db, *name, pw, *email, splitList(*groups)...)
}
