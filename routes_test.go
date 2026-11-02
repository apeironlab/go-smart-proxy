package main

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestLegacyRouteUpstreamMigration(t *testing.T) {
	resetEnv(t,
		[]ConfigCredential{{Name: "corp", User: "alice", Password: "secret"}},
		[]ConfigRoute{{Name: "legacy", ProxyUrl: "http://127.0.0.1:1", Credential: "corp"}},
	)

	cfg := configuration.Routes[0]
	if cfg.ProxyUrl != "" || cfg.PacUrl != "" || cfg.Credential != "" {
		t.Fatalf("legacy route fields were not cleared: %+v", cfg)
	}
	if len(cfg.Chain) != 1 || cfg.Chain[0].ProxyUrl != "http://127.0.0.1:1" || cfg.Chain[0].Credential != "corp" {
		t.Fatalf("unexpected migrated chain: %+v", cfg.Chain)
	}
	route := getRoutes()[0]
	if route.proxyUrl != "127.0.0.1:1" || route.user != "alice" || route.password != "secret" || route.cred != "corp" {
		t.Fatalf("unexpected runtime route: %+v", route)
	}
	if migrateRouteUpstreams() {
		t.Fatal("the migration must be idempotent")
	}
}

func TestLegacyPacMigration(t *testing.T) {
	const pac = "http://config.example/proxy.pac"
	resetEnv(t,
		[]ConfigCredential{{Name: "corp", User: "alice", Password: "secret"}},
		[]ConfigRoute{{
			Name: "legacy", PacUrl: pac, ProxyUrl: "http://127.0.0.1:1", Credential: "corp",
		}},
	)

	cfg := configuration.Routes[0]
	if len(cfg.Chain) != 1 || cfg.Chain[0].PacUrl != pac || cfg.Chain[0].ProxyUrl != "" || cfg.Chain[0].Credential != "corp" {
		t.Fatalf("PAC must win over ProxyUrl during migration: %+v", cfg.Chain)
	}
	route := getRoutes()[0]
	if route.pacUrl != pac || len(route.chain) != 0 || route.user != "alice" || route.password != "secret" {
		t.Fatalf("unexpected PAC route: %+v", route)
	}
}

func TestPacHop(t *testing.T) {
	const pac = "http://config.example/proxy.pac"
	resetEnv(t, nil, []ConfigRoute{{Name: "pac", Chain: []ConfigHop{{PacUrl: pac}}}})

	route := getRoutes()[0]
	if route.pacUrl != pac || len(route.chain) != 0 || len(route.hops) != 1 || route.hops[0].PacUrl != pac {
		t.Fatalf("unexpected PAC route: %+v", route)
	}

	if _, err := buildChain([]ConfigHop{{PacUrl: pac}, {ProxyUrl: "http://127.0.0.1:1"}}); err == nil {
		t.Fatal("a PAC hop must be the only hop of the chain")
	}
	if _, err := buildChain([]ConfigHop{{PacUrl: "file:///tmp/proxy.pac"}}); err == nil {
		t.Fatal("only http/https PAC URLs are supported")
	}
	if _, err := buildChain([]ConfigHop{{PacUrl: pac, ProxyUrl: "http://127.0.0.1:1"}}); err == nil {
		t.Fatal("a hop cannot be both a PAC and a proxy")
	}
}

func TestDynamicHopExpansion(t *testing.T) {
	resetEnv(t, nil, []ConfigRoute{
		{Name: "base", Chain: []ConfigHop{
			{ProxyUrl: "http://127.0.0.1:1"},
			{Dynamic: true},
		}},
		{Name: "corp", Chain: []ConfigHop{
			{ProxyUrl: "http://127.0.0.1:2"},
			{ProxyUrl: "socks5://127.0.0.1:3"},
		}},
	})
	configuration.Rules = []ConfigRule{{Name: "corp", Domains: []string{"corp.local"}, Route: "corp"}}
	loadRoutes()
	t.Cleanup(func() { setForceRoute(nil) })

	base := getRoutes()[0]
	got := chainStrings(expandDynamic(base.chain, base.name, "corp.local", "corp.local:443"))
	want := []string{"http://127.0.0.1:1", "http://127.0.0.1:2", "socks5://127.0.0.1:3"}
	if !slices.Equal(got, want) {
		t.Fatalf("dynamic expansion = %v, want %v", got, want)
	}

	// No matching rule: the prefix is kept and the connection continues
	// directly to the target from that point.
	got = chainStrings(expandDynamic(base.chain, base.name, "other.local", "other.local:443"))
	if len(got) != 1 || got[0] != "http://127.0.0.1:1" {
		t.Fatalf("dynamic expansion without a rule = %v, want only the prefix", got)
	}

	// A rule pointing back to the route with the dynamic hop must stop
	// instead of expanding forever.
	configuration.Rules = []ConfigRule{{Name: "self", Domains: []string{"loop.local"}, Route: "base"}}
	loadRoutes()
	base = getRoutes()[0]
	got = chainStrings(expandDynamic(base.chain, base.name, "loop.local", "loop.local:443"))
	if len(got) != 1 || got[0] != "http://127.0.0.1:1" {
		t.Fatalf("dynamic loop = %v, want only the prefix", got)
	}
}

func TestDynamicHopValidation(t *testing.T) {
	if _, err := buildChain([]ConfigHop{{Dynamic: true}}); err != nil {
		t.Fatalf("a chain with only a dynamic hop must be valid: %v", err)
	}
	if _, err := buildChain([]ConfigHop{{Dynamic: true}, {ProxyUrl: "http://127.0.0.1:1"}}); err == nil {
		t.Fatal("a dynamic hop must be the last hop")
	}
	if _, err := buildChain([]ConfigHop{{Dynamic: true, Credential: "corp"}}); err == nil {
		t.Fatal("a dynamic hop cannot have credentials")
	}
	if _, err := buildChain([]ConfigHop{{Dynamic: true, PacUrl: "http://example.com/pac"}}); err == nil {
		t.Fatal("a dynamic hop cannot also be a PAC")
	}
}

func TestRulesOnlyRouteCannotBeForced(t *testing.T) {
	resetEnv(t, nil, []ConfigRoute{
		{Name: "normal"},
		{Name: "rules", RulesOnly: true},
	})
	t.Cleanup(func() { setForceRoute(nil) })

	setForceRoute(getRoutes()[1])
	if fr := getForceRoute(); fr != nil {
		t.Fatalf("rules-only route was forced: %+v", fr)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/force-route", strings.NewReader(`{"name":"rules"}`))
	apiForceRoute(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("API status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestRulesAreEvaluatedOnlyInAutoMode(t *testing.T) {
	resetEnv(t, nil, []ConfigRoute{
		{Name: "base", Chain: []ConfigHop{{ProxyUrl: "http://127.0.0.1:1"}}},
		{Name: "rule", Chain: []ConfigHop{{ProxyUrl: "http://127.0.0.1:2"}}},
	})
	configuration.Rules = []ConfigRule{{Name: "corp", Domains: []string{"corp.local"}, Route: "rule"}}
	loadRoutes()
	t.Cleanup(func() { setForceRoute(nil) })

	if route, rule := routeFor("corp.local"); route == nil || route.name != "rule" || rule != "corp" {
		t.Fatalf("auto route = %v (%q), want rule (corp)", route, rule)
	}

	setForceRoute(getRoutes()[0])
	if route, rule := routeFor("corp.local"); route == nil || route.name != "base" || rule != "" {
		t.Fatalf("forced route = %v (%q), want base without a rule", route, rule)
	}
}
