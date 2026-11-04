package relay

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewEnrollServerRefusesIncompleteConfigurations(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca")
	if err := InitCA(ca); err != nil {
		t.Fatal(err)
	}
	mail := func(string, string, string) error { return nil }
	for name, cfg := range map[string]EnrollConfig{
		"no CA directory": {PublicRelay: "r.example.org:8443", SendMail: mail},
		"no CA":           {CADir: filepath.Join(dir, "none"), PublicRelay: "r.example.org:8443", SendMail: mail},
		"no relay":        {CADir: ca, SendMail: mail},
		"no SMTP":         {CADir: ca, PublicRelay: "r.example.org:8443"},
		"no sender":       {CADir: ca, PublicRelay: "r.example.org:8443", SMTPAddr: "127.0.0.1:25"},
	} {
		if _, err := NewEnrollServer(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// a public relay given as a URL is reduced to host:port
	es, err := NewEnrollServer(EnrollConfig{CADir: ca, PublicRelay: "https://relay.example.org:8443/x", SendMail: mail, StatePath: filepath.Join(dir, "state.json")})
	if err != nil {
		t.Fatal(err)
	}
	if es.cfg.PublicRelay != "relay.example.org:8443" {
		t.Errorf("PublicRelay = %q", es.cfg.PublicRelay)
	}
}

func TestEnrollRequestValidation(t *testing.T) {
	ts, _ := testEnrollServer(t)
	csr, _ := testCSR(t, "alice@example.com")
	badSig := []byte(strings.Replace(string(csr), "A", "B", 3))
	for name, body := range map[string]map[string]string{
		"bad email":  {"email": "nonsense", "csr": string(csr)},
		"bad device": {"email": "alice@example.com", "csr": string(csr), "device": "bad device!"},
		"no csr":     {"email": "alice@example.com", "csr": "nothing"},
		"bad csr":    {"email": "alice@example.com", "csr": string(badSig)},
	} {
		postJSONTest(t, ts.URL+"/enroll", "", body, nil, http.StatusBadRequest)
		_ = name
	}
	// not even JSON
	resp, err := http.Post(ts.URL+"/enroll", "application/json", strings.NewReader("{"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("not json: %d", resp.StatusCode)
	}
	// the confirmation endpoints need the poll token of an existing request
	postJSONTest(t, ts.URL+"/enroll/none/confirm", "", map[string]string{"code": "AAAA-BBBB"}, nil, http.StatusUnauthorized)
	postJSONTest(t, ts.URL+"/enroll/none/confirm", "token", map[string]string{"code": "AAAA-BBBB"}, nil, http.StatusNotFound)
}

func TestEnrollRateLimitAndMailFailure(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca")
	InitCA(ca)
	fail := true
	es, err := NewEnrollServer(EnrollConfig{CADir: ca, PublicRelay: "r.example.org:8443", StatePath: filepath.Join(dir, "state.json"),
		SendMail: func(to, subject, body string) error {
			if fail {
				return errors.New("smtp down")
			}
			return nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	ts := newTestServer(t, es.Handler())
	csr, _ := testCSR(t, "alice@example.com")
	body := map[string]string{"email": "alice@example.com", "csr": string(csr)}
	// mail that cannot be sent: the request is dropped and reported
	postJSONTest(t, ts+"/enroll", "", body, nil, http.StatusBadGateway)
	fail = false
	// and a single address cannot be hammered
	var codes []int
	for i := 0; i < 8; i++ {
		b := strings.NewReader(`{"email":"alice@example.com","csr":` + jsonString(string(csr)) + `}`)
		resp, err := http.Post(ts+"/enroll", "application/json", b)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		codes = append(codes, resp.StatusCode)
	}
	limited := false
	for _, c := range codes {
		if c == http.StatusTooManyRequests {
			limited = true
		}
	}
	if !limited {
		t.Errorf("no rate limit after many requests: %v", codes)
	}
}

func TestEnrollStateIsPersistedAndReloaded(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca")
	InitCA(ca)
	state := filepath.Join(dir, "state.json")
	cfg := EnrollConfig{CADir: ca, PublicRelay: "r.example.org:8443", StatePath: state, SendMail: func(string, string, string) error { return nil }}
	es, err := NewEnrollServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := newTestServer(t, es.Handler())
	csr, _ := testCSR(t, "alice@example.com")
	var created struct {
		ID string `json:"id"`
	}
	postJSONTest(t, ts+"/enroll", "", map[string]string{"email": "alice@example.com", "csr": string(csr)}, &created, http.StatusOK)
	if b, err := os.ReadFile(state); err != nil || !strings.Contains(string(b), created.ID) {
		t.Fatalf("state not saved: %v %s", err, b)
	}
	es2, err := NewEnrollServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	es2.mu.Lock()
	_, ok := es2.items[created.ID]
	es2.mu.Unlock()
	if !ok {
		t.Error("the pending request was not reloaded")
	}
}

func newTestServer(t *testing.T, h http.Handler) string {
	t.Helper()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts.URL
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
