package main

import (
	"net/http"
	"testing"
)

func TestRulesAPI(t *testing.T) {
	call := apiFixture(t)
	configuration.Routes = []ConfigRoute{{Name: "office", Chain: []ConfigHop{{ProxyUrl: "http://proxy.example:8080"}}}}
	loadRoutes()

	if code, _ := call("POST", "/api/rules", `{`); code != http.StatusBadRequest {
		t.Errorf("not json: %d", code)
	}
	if code, _ := call("POST", "/api/rules", `[{"name":"bad","route":"office"}]`); code != http.StatusBadRequest {
		t.Errorf("a rule without conditions: %d", code)
	}
	if code, _ := call("POST", "/api/rules", `[{"name":"x","domains":["example.org"],"route":"nowhere"}]`); code != http.StatusBadRequest {
		t.Errorf("an unknown route: %d", code)
	}
	if code, _ := call("POST", "/api/rules", `[{"name":"corp","domains":["*.corp.example"],"route":"office"},{"name":"rest","networks":["192.0.2.0/24"],"route":"Direct"}]`); code != 200 {
		t.Fatalf("save: %d", code)
	}
	if len(configuration.Rules) != 2 || configuration.Rules[0].Hosts == nil {
		t.Errorf("rules = %+v", configuration.Rules)
	}
	if err := (ConfigRule{Name: "x"}).validate(); err == nil {
		t.Error("a rule without conditions validated")
	}
	if err := (ConfigRule{Name: "x", Domains: []string{"a.example"}, Route: "Direct"}).validate(); err != nil {
		t.Errorf("a valid rule: %v", err)
	}

	if code, _ := call("GET", "/api/rules", ""); code != 200 {
		t.Errorf("list: %d", code)
	}
	if code, _ := call("GET", "/api/rules/test?host=", ""); code != http.StatusBadRequest {
		t.Errorf("test without host: %d", code)
	}
	if code, out := call("GET", "/api/rules/test?host=git.corp.example:443", ""); code != 200 || out["route"] != "office" || out["rule"] != "corp" {
		t.Errorf("test: %d %v", code, out)
	}
	if code, out := call("GET", "/api/rules/test?host=192.0.2.7", ""); code != 200 || out["rule"] != "rest" {
		t.Errorf("test network: %d %v", code, out)
	}
	clearConfigCrypto()
	if code, _ := call("POST", "/api/rules", `[{"name":"corp","domains":["*.corp.example"],"route":"office"}]`); code != http.StatusInternalServerError {
		t.Errorf("save while locked: %d", code)
	}
}
