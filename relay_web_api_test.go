package main

import (
	"net/http"
	"testing"
)

func TestRelayConfigValidation(t *testing.T) {
	call := apiFixture(t)
	t.Cleanup(relayHub.reset)
	relayHub.reset()

	for name, body := range map[string]string{
		"not json":       `{`,
		"no address":     `{"address":""}`,
		"bad address":    `{"address":"relay.example.org:x:y"}`,
		"unknown route":  `{"address":"relay.example.org:8443","route":"nowhere"}`,
		"cert alone":     `{"address":"relay.example.org:8443","certPem":"x"}`,
		"bad pair":       `{"address":"relay.example.org:8443","certPem":"x","keyPem":"y"}`,
		"bad ca":         `{"address":"relay.example.org:8443","caPem":"not a pem"}`,
		"bad labels":     `{"address":"relay.example.org:8443","networkLabels":[{"label":"","vpn":"sideways"}]}`,
		"bad relay name": `{"address":"relay.example.org:8443","name":"Not Valid!"}`,
	} {
		if code, out := call("POST", "/api/relay/config", body); code != http.StatusBadRequest {
			t.Errorf("%s: status %d %v", name, code, out)
		}
	}

	// A relay is added by an unknown name, changed by a known one.
	code, out := call("POST", "/api/relay/config", `{"address":"127.0.0.1:1","name":"home","networkLabel":"Laptop","shareContext":false,"allowLocal":true}`)
	if code != 200 || out["name"] != "home" {
		t.Fatalf("add: %d %v", code, out)
	}
	if code, _ := call("POST", "/api/relay/config?relay=home", `{"address":"127.0.0.1:2"}`); code != 200 {
		t.Fatalf("change: %d", code)
	}
	if code, _ := call("POST", "/api/relay/config", `{"address":"127.0.0.1:3","name":"office"}`); code != 200 {
		t.Fatalf("second relay: %d", code)
	}
	if len(configuration.Relays) != 2 || configuration.Relays[1].Device != configuration.Relays[0].Device {
		t.Errorf("a second relay keeps the device name: %+v", configuration.Relays)
	}
	if code, _ := call("POST", "/api/relay/config", `{"address":"127.0.0.1:4","clearCertificate":true}`); code != 200 {
		t.Errorf("clear: %d", code)
	}
	if code, _ := call("GET", "/api/relays/config", ""); code != 200 {
		t.Errorf("list config: %d", code)
	}
	if code, _ := call("GET", "/api/relay/config?relay=office", ""); code != 200 {
		t.Errorf("config of one: %d", code)
	}
	if code, _ := call("GET", "/api/relays", ""); code != 200 {
		t.Errorf("list: %d", code)
	}
	if code, _ := call("GET", "/api/relay?relay=nope", ""); code != http.StatusNotFound {
		t.Errorf("unknown relay: %d", code)
	}
	if code, _ := call("GET", "/api/relay?relay=office", ""); code != 200 {
		t.Errorf("relay status: %d", code)
	}

	// the relay is not connected: commands fail but the input is checked first
	for _, path := range []string{"/api/relay/contacts", "/api/relay/contacts/respond", "/api/relay/contacts/remove"} {
		if code, _ := call("POST", path+"?relay=home", `{`); code != http.StatusBadRequest {
			t.Errorf("%s not json: %d", path, code)
		}
		if code, _ := call("POST", path+"?relay=home", `{"email":"nonsense"}`); code != http.StatusBadRequest {
			t.Errorf("%s bad address: %d", path, code)
		}
		if code, _ := call("POST", path+"?relay=nope", `{"email":"a@example.org"}`); code != http.StatusNotFound {
			t.Errorf("%s unknown relay: %d", path, code)
		}
		if code, _ := call("POST", path+"?relay=home", `{"email":"a@example.org"}`); code != http.StatusServiceUnavailable {
			t.Errorf("%s not connected: %d", path, code)
		}
	}

	// pings
	if code, _ := call("POST", "/api/relay/ping", `{`); code != http.StatusBadRequest {
		t.Errorf("ping not json: %d", code)
	}
	if code, _ := call("POST", "/api/relay/ping", `{"email":"nonsense"}`); code != http.StatusBadRequest {
		t.Errorf("ping address: %d", code)
	}
	if code, _ := call("POST", "/api/relay/ping", `{"device":"!!"}`); code != http.StatusBadRequest {
		t.Errorf("ping device: %d", code)
	}
	if code, out := call("POST", "/api/relay/ping?relay=home", `{}`); code != 200 || out["ok"] != false {
		t.Errorf("ping an unreachable relay: %d %v", code, out)
	}

	// approvals and rules
	if code, _ := call("POST", "/api/relay/approvals/x?relay=home", `{}`); code != http.StatusBadRequest {
		t.Errorf("approval id: %d", code)
	}
	if code, _ := call("POST", "/api/relay/approvals/1?relay=nope", `{"allow":true}`); code != http.StatusNotFound {
		t.Errorf("approval relay: %d", code)
	}
	if code, _ := call("POST", "/api/relay/approvals/1?relay=home", `{"allow":true}`); code != http.StatusNotFound {
		t.Errorf("approval expired: %d", code)
	}
	if code, _ := call("DELETE", "/api/relay/rules/x?relay=home", ""); code != http.StatusBadRequest {
		t.Errorf("rule id: %d", code)
	}
	if code, _ := call("DELETE", "/api/relay/rules/1?relay=nope", ""); code != http.StatusNotFound {
		t.Errorf("rule relay: %d", code)
	}
	if code, _ := call("DELETE", "/api/relay/rules/1?relay=home", ""); code != 200 {
		t.Errorf("rule delete: %d", code)
	}

	// the device name
	if code, _ := call("POST", "/api/relay/device?relay=home", `{`); code != http.StatusBadRequest {
		t.Errorf("device not json: %d", code)
	}
	if code, _ := call("POST", "/api/relay/device?relay=home", `{"device":""}`); code != http.StatusBadRequest {
		t.Errorf("device empty: %d", code)
	}
	if code, _ := call("POST", "/api/relay/device?relay=nope", `{"device":"k7m2p9qx"}`); code != http.StatusNotFound {
		t.Errorf("device relay: %d", code)
	}
	if code, out := call("POST", "/api/relay/device?relay=home", `{"device":"k7m2p9qx"}`); code != 200 || out["device"] != "k7m2p9qx" {
		t.Errorf("device: %d %v", code, out)
	}

	// enrollment: bodies are checked, failures reach the page as errors
	for _, path := range []string{"/api/relay/enroll", "/api/relay/enroll/login", "/api/relay/enroll/start"} {
		if code, _ := call("POST", path, `{`); code != http.StatusBadRequest {
			t.Errorf("%s not json: %d", path, code)
		}
		if code, _ := call("POST", path, `{"address":"127.0.0.1:1","email":"a@example.org","username":"u","password":"p"}`); code < 400 {
			t.Errorf("%s against nothing succeeded: %d", path, code)
		}
	}
	if code, _ := call("POST", "/api/relay/enroll/confirm", `{`); code != http.StatusBadRequest {
		t.Errorf("confirm not json: %d", code)
	}
	if code, _ := call("POST", "/api/relay/enroll/confirm", `{"code":"123456"}`); code != http.StatusBadRequest {
		t.Errorf("confirm without enrollment: %d", code)
	}
	if code, _ := call("GET", "/api/relay/enroll", ""); code != 200 {
		t.Errorf("enroll status: %d", code)
	}
	if code, _ := call("DELETE", "/api/relay/enroll", ""); code != 200 {
		t.Errorf("enroll cancel: %d", code)
	}

	// removing
	if code, _ := call("DELETE", "/api/relay/config", ""); code != http.StatusBadRequest {
		t.Errorf("remove without a name: %d", code)
	}
	if code, _ := call("DELETE", "/api/relay/config?relay=nope", ""); code != http.StatusNotFound {
		t.Errorf("remove unknown: %d", code)
	}
	if code, _ := call("DELETE", "/api/relay/config?relay=office", ""); code != 200 || len(configuration.Relays) != 1 {
		t.Errorf("remove: %d %+v", code, configuration.Relays)
	}
	clearConfigCrypto()
	if code, _ := call("DELETE", "/api/relay/config?relay=home", ""); code != http.StatusInternalServerError {
		t.Errorf("remove while locked: %d", code)
	}
	if code, _ := call("POST", "/api/relay/config", `{"address":"127.0.0.1:9"}`); code != http.StatusInternalServerError {
		t.Errorf("save while locked: %d", code)
	}
}
