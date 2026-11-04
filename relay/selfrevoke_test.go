package relay

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

type mailbox struct {
	mu   sync.Mutex
	msgs []sentMail
}

type sentMail struct{ to, subject, body string }

func (m *mailbox) send(to, subject, body string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.msgs = append(m.msgs, sentMail{to, subject, body})
	return nil
}

func (m *mailbox) wait(t *testing.T, n int) []sentMail {
	t.Helper()
	for i := 0; i < 100; i++ {
		m.mu.Lock()
		if len(m.msgs) >= n {
			out := append([]sentMail{}, m.msgs...)
			m.mu.Unlock()
			return out
		}
		m.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("expected %d mails, got %d", n, len(m.msgs))
	return nil
}

func (m *mailbox) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.msgs)
}

type selfFixture struct {
	f     *adminFixture
	box   *mailbox
	rev   *Revocations
	kicks *[]string
	ts    string
}

func newSelfFixture(t *testing.T) *selfFixture {
	t.Helper()
	box := &mailbox{}
	rev := NewRevocations(filepath.Join(t.TempDir(), "rev.txt"))
	kicks := &[]string{}
	var kmu sync.Mutex
	path := usersFile(t)
	ts, es := authServer(t, func(c *EnrollConfig, _ string) {
		c.SendMail = box.send
		c.Revoked = rev
		c.Disconnect = func(email, serial string) int {
			kmu.Lock()
			*kicks = append(*kicks, email+"/"+serial)
			kmu.Unlock()
			return 1
		}
		c.Auth = &AuthConfig{Methods: []AuthMethod{{ID: "local", Type: "password", Password: &PasswordConfig{UsersFile: path}}}}
	})
	_ = es
	return &selfFixture{f: &adminFixture{ts: ts, es: es}, box: box, rev: rev, kicks: kicks, ts: ts.URL}
}

func (sf *selfFixture) enroll(t *testing.T, device string) string {
	t.Helper()
	csr, _ := testCSR(t, "alice@example.com")
	body, _ := json.Marshal(map[string]string{"email": "alice@example.com", "csr": string(csr), "username": "alice", "password": "correct horse", "device": device})
	resp, err := http.Post(sf.ts+"/enroll-auth/local", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		CertPEM string `json:"certPem"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != 200 {
		t.Fatalf("enroll: %d", resp.StatusCode)
	}
	return out.CertPEM
}

func postForm(t *testing.T, u string, v url.Values) (int, string) {
	t.Helper()
	resp, err := http.PostForm(u, v)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var b bytes.Buffer
	b.ReadFrom(resp.Body)
	return resp.StatusCode, b.String()
}

func TestEveryAssociationIsNotifiedByMail(t *testing.T) {
	sf := newSelfFixture(t)
	sf.enroll(t, "laptop")
	m := sf.box.wait(t, 1)[0]
	if m.to != "alice@example.com" || !strings.Contains(m.subject, "nuovo dispositivo") {
		t.Fatalf("mail: %+v", m)
	}
	for _, want := range []string{"laptop", "alice@example.com", "127.0.0.1", sf.ts + "/revoke", "NON sei stato tu"} {
		if !strings.Contains(m.body, want) {
			t.Fatalf("the notification lacks %q:\n%s", want, m.body)
		}
	}
	// a second device is a second mail
	sf.enroll(t, "phone")
	ms := sf.box.wait(t, 2)
	if !strings.Contains(ms[1].body, "phone") {
		t.Fatalf("second mail: %s", ms[1].body)
	}
}

func TestEnrollmentByEmailCodeIsNotifiedToo(t *testing.T) {
	box := &mailbox{}
	ts, _ := authServer(t, func(c *EnrollConfig, _ string) {
		c.SendMail = box.send
		c.Revoked = NewRevocations(filepath.Join(t.TempDir(), "r.txt"))
	})
	csr, _ := testCSR(t, "carol@example.com")
	var start struct {
		ID        string `json:"id"`
		PollToken string `json:"pollToken"`
	}
	postJSONTest(t, ts.URL+"/enroll", "", map[string]string{"email": "carol@example.com", "csr": string(csr), "device": "tablet"}, &start, 200)
	code := regexp.MustCompile(`[A-Z2-9]{4}-[A-Z2-9]{4}`).FindString(box.wait(t, 1)[0].body)
	postJSONTest(t, ts.URL+"/enroll/"+start.ID+"/confirm", start.PollToken, map[string]string{"code": code}, nil, 200)
	ms := box.wait(t, 2)
	if ms[1].to != "carol@example.com" || !strings.Contains(ms[1].body, "tablet") {
		t.Fatalf("notification: %+v", ms[1])
	}
}

func TestNoMailProblemBreaksEnrollment(t *testing.T) {
	calls := 0
	var mu sync.Mutex
	ts, _ := authServer(t, func(c *EnrollConfig, _ string) {
		path := usersFile(t)
		c.SendMail = func(string, string, string) error { mu.Lock(); calls++; mu.Unlock(); return http.ErrServerClosed }
		c.Auth = &AuthConfig{Methods: []AuthMethod{{ID: "local", Type: "password", Password: &PasswordConfig{UsersFile: path}}}}
	})
	sf := &selfFixture{ts: ts.URL}
	if sf.enroll(t, "laptop") == "" {
		t.Fatal("no certificate")
	}
}

func revokeLinkFrom(t *testing.T, m sentMail) string {
	t.Helper()
	l := regexp.MustCompile(`https?://\S+/revoke/confirm\?token=\S+`).FindString(m.body)
	if l == "" {
		t.Fatalf("no link in:\n%s", m.body)
	}
	return l
}

func TestUserRevokesTheirCertificatesWithMailConfirmation(t *testing.T) {
	sf := newSelfFixture(t)
	cert1, cert2 := sf.enroll(t, "laptop"), sf.enroll(t, "phone")
	sf.box.wait(t, 2) // the two notifications
	c1, c2 := parseCert(t, cert1), parseCert(t, cert2)

	// the page exists and asks for an address
	resp, _ := http.Get(sf.ts + "/revoke")
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("form: %d %v", resp.StatusCode, resp.Header)
	}

	// asking changes nothing: it only sends a link
	code, page := postForm(t, sf.ts+"/revoke", url.Values{"email": {"Alice@Example.com"}})
	if code != 200 || sf.rev.Revoked(c1) {
		t.Fatalf("request: %d", code)
	}
	mail := sf.box.wait(t, 3)[2]
	if mail.to != "alice@example.com" || !strings.Contains(mail.subject, "revoca") {
		t.Fatalf("mail: %+v", mail)
	}
	link := revokeLinkFrom(t, mail)

	// an address with no certificates gets the same answer and no mail
	_, page2 := postForm(t, sf.ts+"/revoke", url.Values{"email": {"nobody@example.com"}})
	if page != page2 {
		t.Fatal("the answer reveals whether the address has certificates")
	}
	time.Sleep(100 * time.Millisecond)
	if sf.box.count() != 3 {
		t.Fatalf("a mail went to an address with no certificate: %d", sf.box.count())
	}

	// opening the link (what a mail scanner does) shows the devices and revokes nothing
	for i := 0; i < 3; i++ {
		r, err := http.Get(link)
		if err != nil {
			t.Fatal(err)
		}
		var b bytes.Buffer
		b.ReadFrom(r.Body)
		r.Body.Close()
		if r.StatusCode != 200 || !strings.Contains(b.String(), "laptop") || !strings.Contains(b.String(), "phone") || r.Header.Get("Referrer-Policy") != "no-referrer" {
			t.Fatalf("confirm page: %d %s", r.StatusCode, b.String())
		}
	}
	if sf.rev.Revoked(c1) || sf.rev.Revoked(c2) {
		t.Fatal("opening the link revoked something")
	}

	// revoke one device only
	token := link[strings.Index(link, "token=")+6:]
	code, _ = postForm(t, sf.ts+"/revoke/confirm", url.Values{"token": {token}, "serial": {serialHex(c1)}})
	if code != 200 || !sf.rev.Revoked(c1) || sf.rev.Revoked(c2) {
		t.Fatalf("revoke one: %d %v %v", code, sf.rev.Revoked(c1), sf.rev.Revoked(c2))
	}
	if len(*sf.kicks) != 1 || !strings.HasSuffix((*sf.kicks)[0], serialHex(c1)) {
		t.Fatalf("connections were not cut: %v", *sf.kicks)
	}
	conf := sf.box.wait(t, 4)[3]
	if conf.to != "alice@example.com" || !strings.Contains(conf.subject, "revocati") {
		t.Fatalf("confirmation mail: %+v", conf)
	}

	// the link is good once
	if code, _ := postForm(t, sf.ts+"/revoke/confirm", url.Values{"token": {token}, "serial": {serialHex(c2)}}); code != 403 || sf.rev.Revoked(c2) {
		t.Fatalf("link reused: %d", code)
	}
	if r, _ := http.Get(link); r.StatusCode != 403 {
		t.Fatalf("spent link page: %d", r.StatusCode)
	}

	// a new link for what is left
	postForm(t, sf.ts+"/revoke", url.Values{"email": {"alice@example.com"}})
	link2 := revokeLinkFrom(t, sf.box.wait(t, 5)[4])
	token2 := link2[strings.Index(link2, "token=")+6:]
	if code, _ := postForm(t, sf.ts+"/revoke/confirm", url.Values{"token": {token2}}); code != 400 {
		t.Fatalf("nothing selected: %d", code)
	}
	if code, _ := postForm(t, sf.ts+"/revoke/confirm", url.Values{"token": {token2}, "serial": {serialHex(c2)}}); code != 200 || !sf.rev.Revoked(c2) {
		t.Fatalf("revoke the rest: %d", code)
	}
}

func TestRevocationLinksCannotBeForgedOrBorrowed(t *testing.T) {
	sf := newSelfFixture(t)
	cert := sf.enroll(t, "laptop")
	c := parseCert(t, cert)
	sf.box.wait(t, 1)
	// a made-up token, an empty one, and a certificate of someone else
	for _, tok := range []string{"", "abc", strings.Repeat("A", 43)} {
		if code, _ := postForm(t, sf.ts+"/revoke/confirm", url.Values{"token": {tok}, "serial": {serialHex(c)}}); code != 403 {
			t.Fatalf("token %q: %d", tok, code)
		}
	}
	if sf.rev.Revoked(c) {
		t.Fatal("revoked with a forged token")
	}
	// Bob's link cannot revoke Alice's certificates
	bobCSR, _ := testCSR(t, "bob@example.com")
	body, _ := json.Marshal(map[string]string{"email": "bob@example.com", "csr": string(bobCSR), "username": "bob@example.com", "password": "battery staple", "device": "pc"})
	r, _ := http.Post(sf.ts+"/enroll-auth/local", "application/json", bytes.NewReader(body))
	r.Body.Close()
	sf.box.wait(t, 2)
	postForm(t, sf.ts+"/revoke", url.Values{"email": {"bob@example.com"}})
	link := revokeLinkFrom(t, sf.box.wait(t, 3)[2])
	token := link[strings.Index(link, "token=")+6:]
	postForm(t, sf.ts+"/revoke/confirm", url.Values{"token": {token}, "serial": {serialHex(c)}})
	if sf.rev.Revoked(c) {
		t.Fatal("Bob's link revoked Alice's certificate")
	}
}

func TestRevocationRequestsAreRateLimited(t *testing.T) {
	sf := newSelfFixture(t)
	sf.enroll(t, "laptop")
	sf.box.wait(t, 1)
	last := 0
	for i := 0; i < 6; i++ {
		last, _ = postForm(t, sf.ts+"/revoke", url.Values{"email": {"alice@example.com"}})
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("after many requests: %d", last)
	}
	time.Sleep(150 * time.Millisecond)
	if n := sf.box.count(); n > 4 { // the notification and at most 3 links
		t.Fatalf("%d mails: the address can be mail-bombed", n)
	}
}

func TestSelfRevocationNeedsAListAndAPublicAddress(t *testing.T) {
	ts, _ := authServer(t, func(c *EnrollConfig, _ string) { c.SendMail = (&mailbox{}).send })
	if r, _ := http.Get(ts.URL + "/revoke"); r.StatusCode != 404 {
		t.Fatalf("without a revocation list: %d", r.StatusCode)
	}
}

func TestLedgerSurvivesARestartAndForgetsOldCertificates(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "enroll.json")
	mk := func() (*selfFixture, *EnrollServer) {
		box := &mailbox{}
		path := usersFile(t)
		ts, es := authServer(t, func(c *EnrollConfig, _ string) {
			c.SendMail = box.send
			c.StatePath = state
			c.Revoked = NewRevocations(filepath.Join(dir, "rev.txt"))
			c.Auth = &AuthConfig{Methods: []AuthMethod{{ID: "local", Type: "password", Password: &PasswordConfig{UsersFile: path}}}}
		})
		return &selfFixture{ts: ts.URL, box: box}, es
	}
	sf, es := mk()
	sf.enroll(t, "laptop")
	if len(es.activeCerts("alice@example.com")) != 1 {
		t.Fatal("not recorded")
	}
	_, es2 := mk()
	if got := es2.activeCerts("alice@example.com"); len(got) != 1 || got[0].Device != "laptop" {
		t.Fatalf("after restart: %+v", got)
	}
	// long expired certificates leave the ledger
	es2.recordIssued(&IssuedCert{Serial: "1", Email: "old@example.com", Issued: time.Now().Add(-90 * 24 * time.Hour), Expires: time.Now().Add(-60 * 24 * time.Hour)})
	es2.recordIssued(&IssuedCert{Serial: "2", Email: "x@example.com", Issued: time.Now(), Expires: time.Now().Add(time.Hour)})
	es2.mu.Lock()
	for _, c := range es2.certs {
		if c.Serial == "1" {
			es2.mu.Unlock()
			t.Fatal("an old certificate stayed in the ledger")
		}
	}
	es2.mu.Unlock()
}
