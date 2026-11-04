package relay

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
)

// fakeSMTP is a tiny SMTP server: it advertises the given AUTH mechanisms,
// accepts one message per connection and records what it was sent.
type fakeSMTP struct {
	ln       net.Listener
	auth     string
	mu       sync.Mutex
	messages []string
	logins   []string
}

func newFakeSMTP(t *testing.T, auth string) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln, auth: auth}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeSMTP) addr() string { return f.ln.Addr().String() }

func (f *fakeSMTP) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	say := func(s string) { fmt.Fprint(c, s+"\r\n") }
	read := func() string { l, _ := br.ReadString('\n'); return strings.TrimRight(l, "\r\n") }
	say("220 fake ESMTP")
	var msg strings.Builder
	for {
		line := read()
		if line == "" {
			return
		}
		up := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(up, "EHLO"):
			say("250-fake")
			if f.auth != "" {
				say("250-AUTH " + f.auth)
			}
			say("250 8BITMIME")
		case strings.HasPrefix(up, "AUTH PLAIN"):
			raw, _ := base64.StdEncoding.DecodeString(strings.Fields(line)[2])
			f.mu.Lock()
			f.logins = append(f.logins, "plain:"+strings.ReplaceAll(string(raw), "\x00", "|"))
			f.mu.Unlock()
			say("235 ok")
		case strings.HasPrefix(up, "AUTH LOGIN"):
			say("334 " + base64.StdEncoding.EncodeToString([]byte("Username:")))
			u, _ := base64.StdEncoding.DecodeString(read())
			say("334 " + base64.StdEncoding.EncodeToString([]byte("Password:")))
			p, _ := base64.StdEncoding.DecodeString(read())
			f.mu.Lock()
			f.logins = append(f.logins, "login:"+string(u)+"|"+string(p))
			f.mu.Unlock()
			say("235 ok")
		case strings.HasPrefix(up, "MAIL"), strings.HasPrefix(up, "RCPT"):
			say("250 ok")
		case up == "DATA":
			say("354 go")
			for {
				l := read()
				if l == "." {
					break
				}
				msg.WriteString(l + "\n")
			}
			f.mu.Lock()
			f.messages = append(f.messages, msg.String())
			f.mu.Unlock()
			say("250 queued")
		case up == "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

func TestSendSMTP(t *testing.T) {
	srv := newFakeSMTP(t, "PLAIN LOGIN")
	cfg := EnrollConfig{SMTPAddr: srv.addr(), SMTPFrom: "relay@example.org", SMTPTLS: "none"}
	if err := sendSMTP(cfg, "ann@example.org", "Hello", "Body text"); err != nil {
		t.Fatal(err)
	}
	srv.mu.Lock()
	if len(srv.messages) != 1 || !strings.Contains(srv.messages[0], "Subject: Hello") || !strings.Contains(srv.messages[0], "Body text") {
		t.Errorf("messages = %q", srv.messages)
	}
	srv.mu.Unlock()

	// authentication: auto picks PLAIN, "login" uses LOGIN, "none" skips it
	for mode, want := range map[string]string{"auto": "plain:|bob|s3cret", "plain": "plain:|bob|s3cret", "login": "login:bob|s3cret"} {
		srv.mu.Lock()
		srv.logins = nil
		srv.mu.Unlock()
		c := cfg
		c.SMTPUser, c.SMTPPass, c.SMTPAuth = "bob", "s3cret", mode
		if err := sendSMTP(c, "ann@example.org", "Hi", "x"); err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		srv.mu.Lock()
		if len(srv.logins) != 1 || srv.logins[0] != want {
			t.Errorf("%s: logins = %v, want %s", mode, srv.logins, want)
		}
		srv.mu.Unlock()
	}
	c := cfg
	c.SMTPUser, c.SMTPAuth = "bob", "none"
	if err := sendSMTP(c, "ann@example.org", "Hi", "x"); err != nil {
		t.Errorf("none: %v", err)
	}
	c.SMTPAuth = "kerberos"
	if err := sendSMTP(c, "ann@example.org", "Hi", "x"); err == nil {
		t.Error("an unknown mode was accepted")
	}

	// a server that offers only LOGIN: auto falls back to it, plain refuses
	loginOnly := newFakeSMTP(t, "LOGIN")
	c = EnrollConfig{SMTPAddr: loginOnly.addr(), SMTPFrom: "relay@example.org", SMTPTLS: "none", SMTPUser: "bob", SMTPPass: "pw", SMTPAuth: "auto"}
	if err := sendSMTP(c, "ann@example.org", "Hi", "x"); err != nil {
		t.Errorf("auto with LOGIN only: %v", err)
	}
	c.SMTPAuth = "plain"
	if err := sendSMTP(c, "ann@example.org", "Hi", "x"); err == nil {
		t.Error("PLAIN was used on a server without it")
	}
	// a server without authentication at all
	open := newFakeSMTP(t, "")
	c = EnrollConfig{SMTPAddr: open.addr(), SMTPFrom: "relay@example.org", SMTPTLS: "none", SMTPUser: "bob"}
	if err := sendSMTP(c, "ann@example.org", "Hi", "x"); err == nil {
		t.Error("credentials were configured but the server cannot authenticate")
	}
	// unreachable
	c = EnrollConfig{SMTPAddr: "127.0.0.1:1", SMTPFrom: "relay@example.org", SMTPTLS: "none"}
	if err := sendSMTP(c, "ann@example.org", "Hi", "x"); err == nil {
		t.Error("an unreachable server went unnoticed")
	}
	c.SMTPTLS = "tls"
	if err := sendSMTP(c, "ann@example.org", "Hi", "x"); err == nil {
		t.Error("an unreachable TLS server went unnoticed")
	}
	if smtpHost("mail.example.org:587") != "mail.example.org" || smtpHost("mail.example.org") != "mail.example.org" {
		t.Error("smtpHost")
	}
}

func TestLoginAuthChallenges(t *testing.T) {
	a := &loginAuth{user: "bob", pass: "pw"}
	if name, _, err := a.Start(nil); err != nil || name != "LOGIN" {
		t.Errorf("start: %q %v", name, err)
	}
	if b, _ := a.Next([]byte("Username:"), true); string(b) != "bob" {
		t.Errorf("user = %q", b)
	}
	if b, _ := a.Next([]byte("Password:"), true); string(b) != "pw" {
		t.Errorf("pass = %q", b)
	}
	if _, err := a.Next([]byte("Something else"), true); err == nil {
		t.Error("an unexpected challenge was answered")
	}
	if b, err := a.Next(nil, false); b != nil || err != nil {
		t.Error("nothing to answer when the server is done")
	}
}
