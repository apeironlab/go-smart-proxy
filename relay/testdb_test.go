package relay

import (
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testDBAddr is the database address the admin tests use in dir. By default it
// is a SQLite file. With PROXYRELAY_TEST_DB=postgres or mysql (and the address
// of a server that may create schemas in PROXYRELAY_TEST_POSTGRES or
// PROXYRELAY_TEST_MYSQL) the same tests run on that database, each test in a
// schema of its own, dropped afterwards. The same dir gives the same address,
// so that a "restart" in a test finds its data.
func testDBAddr(t testing.TB, dir string) string {
	t.Helper()
	switch os.Getenv("PROXYRELAY_TEST_DB") {
	case "postgres":
		base := os.Getenv("PROXYRELAY_TEST_POSTGRES")
		name := schemaName(dir)
		admin, err := sql.Open("pgx", base)
		if err != nil {
			t.Fatal(err)
		}
		defer admin.Close()
		if _, err := admin.Exec(`CREATE SCHEMA IF NOT EXISTS ` + name); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			a, err := sql.Open("pgx", base)
			if err == nil {
				a.Exec(`DROP SCHEMA IF EXISTS ` + name + ` CASCADE`)
				a.Close()
			}
		})
		u, _ := url.Parse(base)
		q := u.Query()
		q.Set("search_path", name)
		u.RawQuery = q.Encode()
		return u.String()
	case "mysql":
		base := os.Getenv("PROXYRELAY_TEST_MYSQL") // mysql://user:pw@host:port/ (database name ignored)
		name := schemaName(dir)
		_, driver, dsn, err := parseDSN(strings.TrimSuffix(base, "/") + "/mysql")
		if err != nil {
			t.Fatal(err)
		}
		admin, err := sql.Open(driver, dsn)
		if err != nil {
			t.Fatal(err)
		}
		defer admin.Close()
		if _, err := admin.Exec("CREATE DATABASE IF NOT EXISTS `" + name + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if a, err := sql.Open(driver, dsn); err == nil {
				a.Exec("DROP DATABASE IF EXISTS `" + name + "`")
				a.Close()
			}
		})
		return strings.TrimSuffix(base, "/") + "/" + name
	}
	return filepath.Join(dir, "admin.db")
}

func schemaName(dir string) string {
	h := sha1.Sum([]byte(dir))
	return "t_" + hex.EncodeToString(h[:6])
}
