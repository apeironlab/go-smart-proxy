package relay

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// dialects lists the databases the tests can reach: SQLite always, and the
// servers named by PROXYRELAY_TEST_POSTGRES and PROXYRELAY_TEST_MYSQL.
func dialects(t *testing.T) map[string]func(t *testing.T) string {
	m := map[string]func(t *testing.T) string{
		"sqlite": func(t *testing.T) string { return filepath.Join(t.TempDir(), "x.db") },
	}
	if os.Getenv("PROXYRELAY_TEST_POSTGRES") != "" {
		m["postgres"] = func(t *testing.T) string {
			t.Setenv("PROXYRELAY_TEST_DB", "postgres")
			return testDBAddr(t, t.TempDir())
		}
	}
	if os.Getenv("PROXYRELAY_TEST_MYSQL") != "" {
		m["mysql"] = func(t *testing.T) string {
			t.Setenv("PROXYRELAY_TEST_DB", "mysql")
			return testDBAddr(t, t.TempDir())
		}
	}
	return m
}

func TestParseDSN(t *testing.T) {
	t.Setenv("DBPW", "s3cret")
	cases := []struct{ in, dia, contains string }{
		{"/data/admin.db", "sqlite", "/data/admin.db"},
		{"sqlite:/data/admin.db", "sqlite", "/data/admin.db"},
		{"sqlite:///data/admin.db", "sqlite", "/data/admin.db"},
		{"postgres://u:${DBPW}@db:5432/relay?sslmode=require", "postgres", "u:s3cret@db"},
		{"postgresql://u@db/relay", "postgres", "u@db"},
		{"mysql://u:${DBPW}@db:3306/relay", "mysql", "u:s3cret@tcp(db:3306)/relay"},
		{"mariadb://u:pw@db/relay", "mysql", "tcp(db:3306)/relay"},
	}
	for _, c := range cases {
		dia, _, dsn, err := parseDSN(c.in)
		if err != nil || dia != c.dia || !strings.Contains(dsn, c.contains) {
			t.Errorf("%q: %s %q %v", c.in, dia, dsn, err)
		}
	}
	for _, bad := range []string{"", "  ", "mysql://u:pw@db", "mysql:///x"} {
		if _, _, _, err := parseDSN(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	// pgx and mysql expect different placeholders
	if got := (&dbConn{dia: dialPostgres}).rb("SELECT a FROM t WHERE x = ? AND y = ?"); got != "SELECT a FROM t WHERE x = $1 AND y = $2" {
		t.Fatalf("rebind: %s", got)
	}
	if got := (&dbConn{dia: dialMySQL}).rb("x = ?"); got != "x = ?" {
		t.Fatalf("mysql rebind: %s", got)
	}
}

func TestAdminDatabaseOnEveryDialect(t *testing.T) {
	for name, addr := range dialects(t) {
		t.Run(name, func(t *testing.T) {
			db, err := openAdminDB(addr(t))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()

			// users: add, duplicate, groups (a reserved word in some dialects), update, delete
			if err := db.addUser("Alice", "a long password", "alice@example.com", []string{"staff", "vpn"}); err != nil {
				t.Fatal(err)
			}
			if err := db.addUser("alice", "a long password", "alice@example.com", nil); err != errUserExists {
				t.Fatalf("duplicate: %v", err)
			}
			u, ok, err := db.lookupUser("alice")
			if err != nil || !ok || u.email != "alice@example.com" || strings.Join(u.groups, ",") != "staff,vpn" {
				t.Fatalf("lookup: %+v %v %v", u, ok, err)
			}
			if err := db.updateUser("alice", "", "alice2@example.com", []string{"admin"}); err != nil {
				t.Fatal(err)
			}
			if us, _ := db.listUsers(); len(us) != 1 || us[0].Email != "alice2@example.com" || us[0].Groups[0] != "admin" {
				t.Fatalf("users: %+v", us)
			}
			if err := db.deleteUser("alice"); err != nil {
				t.Fatal(err)
			}
			if err := db.deleteUser("alice"); err == nil {
				t.Fatal("deleting a missing user")
			}

			// certificates: recording again must not undo a revocation
			now := time.Now()
			c := CertRecord{Serial: "ab12", Email: "bob@example.com", Device: "laptop", Method: "password", Issued: now, Expires: now.Add(time.Hour)}
			if err := db.recordCert(c); err != nil {
				t.Fatal(err)
			}
			db.markCert("ab12", true, "root@example.com")
			c.Device = "phone"
			if err := db.recordCert(c); err != nil {
				t.Fatal(err)
			}
			got, ok, err := db.cert("ab12")
			if err != nil || !ok || !got.Revoked || got.RevokedBy != "root@example.com" || got.Device != "phone" {
				t.Fatalf("cert: %+v %v %v", got, ok, err)
			}
			if cs, _ := db.certs("bob@example.com"); len(cs) != 1 {
				t.Fatalf("certs: %+v", cs)
			}

			// gateways
			if err := db.recordGateway(GatewayCert{Serial: "ff", ID: "hq", Issued: now, Expires: now.Add(time.Hour)}); err != nil {
				t.Fatal(err)
			}
			db.markGateway("ff", "root@example.com")
			if gs, _ := db.gatewayCerts(); len(gs) != 1 || !gs[0].Revoked {
				t.Fatalf("gateways: %+v", gs)
			}

			// settings: written twice, read back
			if err := db.setSetting("k", map[string]int{"a": 1}); err != nil {
				t.Fatal(err)
			}
			if err := db.setSetting("k", map[string]int{"a": 2}); err != nil {
				t.Fatal(err)
			}
			var v map[string]int
			if ok, err := db.getSetting("k", &v); err != nil || !ok || v["a"] != 2 {
				t.Fatalf("setting: %v %v %v", v, ok, err)
			}
			if ok, _ := db.getSetting("missing", &v); ok {
				t.Fatal("a missing setting was found")
			}

			// events: order, filters, wildcards in the search, paging, pruning
			for i, e := range []struct{ k, a, s, d string }{
				{"admin.login", "root@example.com", "local", ""},
				{"enroll.issued", "bob@example.com", "ab12", "password"},
				{"admin.revoke", "root@example.com", "bob@example.com", "100% done_x"},
				{"session.open", "bob@example.com", "phone", "127.0.0.1"},
			} {
				if err := db.addEvent(e.k, e.a, e.s, e.d); err != nil {
					t.Fatalf("event %d: %v", i, err)
				}
			}
			evs, err := db.events(EventFilter{})
			if err != nil || len(evs) != 4 || evs[0].Kind != "session.open" || evs[3].Kind != "admin.login" {
				t.Fatalf("events: %+v %v", evs, err)
			}
			if evs, _ := db.events(EventFilter{Kind: "admin."}); len(evs) != 2 {
				t.Fatalf("prefix filter: %+v", evs)
			}
			if evs, _ := db.events(EventFilter{Kind: "admin.login"}); len(evs) != 1 {
				t.Fatalf("exact filter: %+v", evs)
			}
			if evs, _ := db.events(EventFilter{Search: "bob@"}); len(evs) != 3 {
				t.Fatalf("search: %+v", evs)
			}
			if evs, _ := db.events(EventFilter{Search: "100%"}); len(evs) != 1 {
				t.Fatalf("a percent sign in the search: %+v", evs)
			}
			if evs, _ := db.events(EventFilter{Search: "%"}); len(evs) != 1 { // only the one that really contains %
				t.Fatalf("a bare percent matched %d", len(evs))
			}
			if evs, _ := db.events(EventFilter{Search: "done_x"}); len(evs) != 1 {
				t.Fatalf("an underscore in the search: %+v", evs)
			}
			if evs, _ := db.events(EventFilter{Search: "doneZx"}); len(evs) != 0 {
				t.Fatalf("an underscore acted as a wildcard: %+v", evs)
			}
			p1, _ := db.events(EventFilter{Limit: 2})
			p2, _ := db.events(EventFilter{Limit: 2, Before: p1[1].ID})
			if len(p1) != 2 || len(p2) != 2 || p2[0].ID >= p1[1].ID {
				t.Fatalf("paging: %+v %+v", p1, p2)
			}
			db.pruneEvents() // far fewer than the limit: nothing goes
			if evs, _ := db.events(EventFilter{Limit: 100}); len(evs) != 4 {
				t.Fatalf("prune removed events: %d", len(evs))
			}
		})
	}
}

// Relays that start together all create the tables.
func TestSeveralRelaysCreateTheTablesTogether(t *testing.T) {
	for name, addr := range dialects(t) {
		t.Run(name, func(t *testing.T) {
			a := addr(t)
			if name == "sqlite" {
				t.Skip("a SQLite file belongs to one process")
			}
			errs := make(chan error, 6)
			for i := 0; i < 6; i++ {
				go func() {
					sh, err := OpenShared(a, "")
					if err == nil {
						sh.Close()
					}
					errs <- err
				}()
			}
			for i := 0; i < 6; i++ {
				if err := <-errs; err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
