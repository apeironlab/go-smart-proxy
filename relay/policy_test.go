package relay

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPolicyValidation(t *testing.T) {
	ok := PolicyConfig{
		Rules: []PolicyRule{{ID: "social", Name: "Social", Mandatory: true, Domains: []string{"Facebook.com", "*.tiktok.com"}, Nets: []string{"203.0.113.0/24", "198.51.100.9"}}},
		Lists: []PolicyList{{ID: "ads", Name: "Ads", URL: "https://example.com/hosts", Format: "hosts"}},
		Allow: []string{"Good.example.com"},
	}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	if ok.Rules[0].Domains[0] != "facebook.com" || ok.Rules[0].Domains[1] != "tiktok.com" || ok.Allow[0] != "good.example.com" {
		t.Fatalf("not normalized: %+v", ok)
	}
	bad := map[string]func(c *PolicyConfig){
		"rule id":      func(c *PolicyConfig) { c.Rules[0].ID = "Bad Id" },
		"rule name":    func(c *PolicyConfig) { c.Rules[0].Name = " " },
		"domain":       func(c *PolicyConfig) { c.Rules[0].Domains = []string{"not a domain"} },
		"net":          func(c *PolicyConfig) { c.Rules[0].Nets = []string{"999.1.1.1"} },
		"list scheme":  func(c *PolicyConfig) { c.Lists[0].URL = "file:///etc/passwd" },
		"list format":  func(c *PolicyConfig) { c.Lists[0].Format = "xml" },
		"duplicate id": func(c *PolicyConfig) { c.Lists[0].ID = "social" },
		"allow":        func(c *PolicyConfig) { c.Allow = []string{"a b"} },
		"refresh":      func(c *PolicyConfig) { c.RefreshHours = 9999 },
		"too many": func(c *PolicyConfig) {
			c.Rules[0].Domains = nil
			for i := 0; i < maxInlineEntries+1; i++ {
				c.Rules[0].Nets = append(c.Rules[0].Nets, "10.0.0.1")
			}
		},
	}
	for name, mod := range bad {
		c := PolicyConfig{
			Rules: []PolicyRule{{ID: "social", Name: "Social", Domains: []string{"a.com"}}},
			Lists: []PolicyList{{ID: "ads", Name: "Ads", URL: "https://example.com/hosts"}},
		}
		mod(&c)
		if c.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func waitPolicy(t *testing.T, p *Policy, cond func() bool) {
	t.Helper()
	waitFor(t, cond)
	_ = p
}

func TestRelayEnforcesMandatoryRulesOnContactConnections(t *testing.T) {
	env, client, _ := newAppRelay(t)
	pol := NewPolicy(t.TempDir())
	pol.fetcher.DenyPrivate = false
	env.srv.AttachPolicy(pol)
	list := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "# malware\n0.0.0.0 evil.example.net\n0.0.0.0 fp.example.net\n")
	}))
	defer list.Close()
	var audit []string
	var amu sync.Mutex
	env.srv.SetAudit(func(kind, actor, subject, detail string) {
		amu.Lock()
		audit = append(audit, kind+" "+actor+" "+subject)
		amu.Unlock()
	})

	alice, bob := client("alice@example.com"), client("bob@example.com")
	WriteLine(alice.ctrl, ClientMsg{T: TContactRequest, Email: "bob@example.com"})
	bob.waitState(t, func(s State) bool { return len(s.Incoming) == 1 })
	WriteLine(bob.ctrl, ClientMsg{T: TContactRespond, Email: "alice@example.com", Accept: true})
	alice.waitState(t, func(s State) bool { return len(s.Contacts) == 1 })
	go func() { // bob opens whatever he is asked
		for {
			s, err := bob.ys.AcceptStream()
			if err != nil {
				return
			}
			go func() {
				br := NewReader(s)
				var req DialReq
				if ReadLine(br, &req) != nil {
					s.Close()
					return
				}
				WriteLine(s, DialResp{OK: true})
				io.Copy(s, br)
				s.Close()
			}()
		}
	}()
	dial := func(target string) DialResp {
		st, _ := alice.ys.OpenStream()
		WriteLine(st, DialReq{T: TDial, Via: "bob@example.com", Target: target})
		var resp DialResp
		st.SetReadDeadline(time.Now().Add(5 * time.Second))
		ReadLine(NewReader(st), &resp)
		st.Close()
		return resp
	}
	if !dial("ads.example.com:443").OK {
		t.Fatal("nothing is blocked yet")
	}

	if err := pol.Set(PolicyConfig{
		Rules: []PolicyRule{
			{ID: "social", Name: "Social networks", Mandatory: true, Domains: []string{"social.example.com"}, Nets: []string{"203.0.113.0/24"}},
			{ID: "ads", Name: "Ads (advice)", Domains: []string{"ads.example.com"}}, // recommended
		},
		Lists: []PolicyList{{ID: "malware", Name: "Malware", URL: list.URL, Format: "hosts", Mandatory: true}},
		Allow: []string{"fp.example.net"},
	}); err != nil {
		t.Fatal(err)
	}
	waitPolicy(t, pol, func() bool { _, ok := pol.Check("evil.example.net"); return ok })

	for _, host := range []string{"social.example.com", "www.social.example.com", "203.0.113.9", "evil.example.net", "x.evil.example.net"} {
		r := dial(host + ":443")
		if r.OK || !strings.Contains(r.Error, "blocked") {
			t.Errorf("%s: %+v", host, r)
		}
	}
	// recommended rules are not enforced by the relay, and the allow list wins
	for _, host := range []string{"ads.example.com", "fp.example.net", "other.example.org"} {
		if r := dial(host + ":443"); !r.OK {
			t.Errorf("%s was refused: %+v", host, r)
		}
	}
	// the refusal does not say which rule matched
	if r := dial("social.example.com:80"); strings.Contains(r.Error, "Social") {
		t.Fatalf("the user is told the rule: %q", r.Error)
	}

	lists, counts, recent := pol.Status()
	if len(lists) != 1 || lists[0].Entries != 2 || lists[0].Error != "" {
		t.Fatalf("lists: %+v", lists)
	}
	if counts["Social networks"] < 3 || counts["Malware"] < 2 || len(recent) == 0 || recent[0].Email != "alice@example.com" {
		t.Fatalf("stats: %v %+v", counts, recent)
	}
	// each user+host is audited once, however often they try
	n := 0
	amu.Lock()
	defer amu.Unlock()
	for _, a := range audit {
		if strings.HasPrefix(a, "policy.block alice@example.com social.example.com") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("audit entries for one host: %d (%v)", n, audit)
	}
}

func TestProxiesAreToldThePolicy(t *testing.T) {
	env, client, _ := newAppRelay(t)
	pol := NewPolicy(t.TempDir())
	env.srv.AttachPolicy(pol)
	alice := client("alice@example.com")
	st := alice.waitState(t, func(s State) bool { return s.Email == "alice@example.com" })
	if st.Policy != nil {
		t.Fatalf("a relay that blocks nothing says nothing: %+v", st.Policy)
	}
	cfg := PolicyConfig{
		Rules: []PolicyRule{{ID: "r", Name: "R", Mandatory: true, Domains: []string{"a.example.com"}}, {ID: "off", Name: "Off", Disabled: true, Domains: []string{"b.example.com"}}},
		Lists: []PolicyList{{ID: "l", Name: "L", URL: "https://lists.invalid/l", Format: "domains"}},
		Allow: []string{"ok.example.com"},
	}
	if err := pol.Set(cfg); err != nil {
		t.Fatal(err)
	}
	st = alice.waitState(t, func(s State) bool { return s.Policy != nil })
	if len(st.Policy.Rules) != 1 || !st.Policy.Rules[0].Mandatory || st.Policy.Rules[0].Domains[0] != "a.example.com" ||
		len(st.Policy.Lists) != 1 || st.Policy.Lists[0].Mandatory || st.Policy.Allow[0] != "ok.example.com" || st.Policy.Rev == "" {
		t.Fatalf("policy: %+v", st.Policy)
	}
	rev := st.Policy.Rev
	cfg.Allow = []string{"ok.example.com", "ok2.example.com"}
	pol.Set(cfg)
	st = alice.waitState(t, func(s State) bool { return s.Policy != nil && s.Policy.Rev != rev })
	if len(st.Policy.Allow) != 2 {
		t.Fatalf("after change: %+v", st.Policy)
	}
}

func TestPolicyFileIsWatchedAndReadOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yml")
	os.WriteFile(path, []byte("rules:\n  - id: a\n    name: A\n    mandatory: true\n    domains: [x.example.com]\n"), 0o600)
	p, err := LoadPolicyFile(path, filepath.Join(dir, "lists"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.Check("x.example.com"); !ok || !p.ReadOnly() {
		t.Fatal("file rule not applied")
	}
	if err := p.Set(PolicyConfig{}); err == nil {
		t.Fatal("a file policy was edited")
	}
	changed := make(chan struct{}, 1)
	p.OnChange(func() {
		select {
		case changed <- struct{}{}:
		default:
		}
	})
	time.Sleep(10 * time.Millisecond)
	os.WriteFile(path, []byte("rules:\n  - id: a\n    name: A\n    mandatory: true\n    domains: [y.example.com]\n"), 0o600)
	if c, err := p.reloadFile(); err != nil || !c {
		t.Fatalf("reload: %v %v", c, err)
	}
	if _, ok := p.Check("x.example.com"); ok {
		t.Fatal("old rule still applies")
	}
	if _, ok := p.Check("y.example.com"); !ok {
		t.Fatal("new rule not applied")
	}
	select {
	case <-changed:
	default:
		t.Fatal("no change notification")
	}
	os.WriteFile(path, []byte("rules:\n  - id: a\n    nme: broken\n"), 0o600)
	time.Sleep(10 * time.Millisecond)
	p.reloadFile()
	if _, ok := p.Check("y.example.com"); !ok {
		t.Fatal("a broken file removed the policy")
	}
	var nilp *Policy
	if _, ok := nilp.Check("a.com"); ok || nilp.Push() != nil {
		t.Fatal("nil policy")
	}
}

func TestAdminManagesThePolicy(t *testing.T) {
	dir := t.TempDir()
	f := newAdminFixture(t, adminOpts{dir: dir})
	pol := NewPolicy(filepath.Join(dir, "lists"))
	if err := f.admin.SetPolicy(pol); err != nil {
		t.Fatal(err)
	}
	b := f.loggedIn(t)
	var got struct {
		Enabled  bool         `json:"enabled"`
		ReadOnly bool         `json:"readOnly"`
		Config   PolicyConfig `json:"config"`
	}
	b.get("/admin/api/policy", &got, 200)
	if !got.Enabled || got.ReadOnly || len(got.Config.Rules) != 0 {
		t.Fatalf("policy: %+v", got)
	}
	cfg := PolicyConfig{Rules: []PolicyRule{{ID: "social", Name: "Social", Mandatory: true, Domains: []string{"social.example.com"}}}, Allow: []string{"ok.example.com"}}
	b.send("PUT", "/admin/api/policy", map[string]any{"config": cfg}, &got, 200)
	if len(got.Config.Rules) != 1 {
		t.Fatalf("saved: %+v", got)
	}
	if _, ok := pol.Check("a.social.example.com"); !ok {
		t.Fatal("not applied")
	}
	bad := cfg
	bad.Rules = []PolicyRule{{ID: "x", Name: "X", Domains: []string{"bad domain"}}}
	b.send("PUT", "/admin/api/policy", map[string]any{"config": bad}, nil, 400)
	if _, ok := pol.Check("a.social.example.com"); !ok {
		t.Fatal("a refused policy changed the live one")
	}
	b.send("POST", "/admin/api/policy/refresh", nil, nil, 200)

	var kinds []Event
	b.get("/admin/api/events?kind=admin.policy.&limit=20", &kinds, 200)
	if len(kinds) != 2 {
		t.Fatalf("events: %+v", kinds)
	}

	// it survives a restart
	f.admin.Close()
	f2 := newAdminFixture(t, adminOpts{dir: dir})
	pol2 := NewPolicy(filepath.Join(dir, "lists"))
	if err := f2.admin.SetPolicy(pol2); err != nil {
		t.Fatal(err)
	}
	if _, ok := pol2.Check("social.example.com"); !ok {
		t.Fatal("the policy was not kept")
	}
}

func TestPolicyIsOffWithoutOne(t *testing.T) {
	f := newAdminFixture(t, adminOpts{})
	b := f.loggedIn(t)
	var got struct {
		Enabled bool `json:"enabled"`
	}
	b.get("/admin/api/policy", &got, 200)
	if got.Enabled {
		t.Fatal("enabled without a policy")
	}
	b.send("PUT", "/admin/api/policy", map[string]any{"config": PolicyConfig{}}, nil, 404)
}

func TestRelayCanRequireTheLocalAccessToken(t *testing.T) {
	env, client, _ := newAppRelay(t)
	pol := NewPolicy(t.TempDir())
	env.srv.AttachPolicy(pol)
	alice := client("alice@example.com")
	alice.waitState(t, func(s State) bool { return s.Email == "alice@example.com" })
	if err := pol.Set(PolicyConfig{RequireLocalAuth: true}); err != nil {
		t.Fatal(err)
	}
	st := alice.waitState(t, func(s State) bool { return s.Policy != nil })
	if !st.Policy.RequireLocalAuth || len(st.Policy.Rules) != 0 || st.Policy.Rev == "" {
		t.Fatalf("policy: %+v", st.Policy)
	}
	pol.Set(PolicyConfig{})
	st = alice.waitState(t, func(s State) bool { return s.Policy == nil })
	if st.Policy != nil {
		t.Fatalf("lifted: %+v", st.Policy)
	}
}
