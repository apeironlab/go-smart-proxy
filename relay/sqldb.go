package relay

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql" // MySQL and MariaDB
	_ "github.com/jackc/pgx/v5/stdlib" // PostgreSQL
	_ "modernc.org/sqlite"             // SQLite, in pure Go
)

// The relay keeps its data in SQLite by default (a file), and can use
// PostgreSQL or MySQL/MariaDB instead, which is what lets several relays share
// it. The database is named by one address:
//
//	/data/admin.db                         SQLite file (also sqlite:/data/admin.db)
//	postgres://user:pass@host:5432/dbname?sslmode=require
//	mysql://user:pass@host:3306/dbname     (also mariadb://)
//
// ${VAR} in the address is replaced with the environment variable, so that
// passwords need not be written in a command line.

const (
	dialSQLite   = "sqlite"
	dialPostgres = "postgres"
	dialMySQL    = "mysql"
)

// dbConn is a database connection that speaks one dialect: queries are written
// with ? placeholders and rebound for the driver.
type dbConn struct {
	*sql.DB
	dia string
}

// ParseDSN says which dialect an address is for and returns the driver name and
// connection string.
func parseDSN(addr string) (dia, driver, dsn string, err error) {
	addr = strings.TrimSpace(os.ExpandEnv(addr))
	if addr == "" {
		return "", "", "", errors.New("the database address is required")
	}
	lower := strings.ToLower(addr)
	switch {
	case strings.HasPrefix(lower, "postgres://"), strings.HasPrefix(lower, "postgresql://"):
		return dialPostgres, "pgx", addr, nil
	case strings.HasPrefix(lower, "mysql://"), strings.HasPrefix(lower, "mariadb://"):
		u, err := url.Parse(addr)
		if err != nil || u.Host == "" {
			return "", "", "", errors.New("invalid mysql:// address")
		}
		name := strings.TrimPrefix(u.Path, "/")
		if name == "" {
			return "", "", "", errors.New("the mysql:// address needs a database name")
		}
		host := u.Host
		if u.Port() == "" {
			host = u.Hostname() + ":3306"
		}
		auth := ""
		if u.User != nil {
			pw, _ := u.User.Password()
			auth = u.User.Username() + ":" + pw + "@"
		}
		q := u.Query()
		q.Set("parseTime", "false")
		q.Set("charset", "utf8mb4")
		if q.Get("collation") == "" {
			q.Set("collation", "utf8mb4_bin") // case-sensitive keys, like the other databases
		}
		q.Set("sql_mode", "'STRICT_TRANS_TABLES,NO_BACKSLASH_ESCAPES'")
		return dialMySQL, "mysql", fmt.Sprintf("%stcp(%s)/%s?%s", auth, host, name, q.Encode()), nil
	}
	path := strings.TrimPrefix(strings.TrimPrefix(addr, "sqlite://"), "sqlite:")
	return dialSQLite, "sqlite", path, nil
}

// openDB opens the database named by addr and checks that it answers.
func openDB(addr string) (*dbConn, error) {
	dia, driver, dsn, err := parseDSN(addr)
	if err != nil {
		return nil, err
	}
	if dia == dialSQLite {
		// Create the file private before the driver does: it holds password
		// hashes and the SMTP password.
		f, err := os.OpenFile(dsn, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return nil, err
		}
		f.Close()
		dsn = "file:" + dsn + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, err
	}
	if dia == dialSQLite {
		db.SetMaxOpenConns(1)
	} else {
		db.SetMaxOpenConns(12)
		db.SetMaxIdleConns(4)
		db.SetConnMaxLifetime(30 * time.Minute)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("cannot reach the database: %w", err)
	}
	return &dbConn{DB: db, dia: dia}, nil
}

// rb rebinds ? placeholders for PostgreSQL ($1, $2...).
func (c *dbConn) rb(q string) string {
	if c.dia != dialPostgres {
		return q
	}
	var b strings.Builder
	n := 0
	for i := 0; i < len(q); i++ {
		if q[i] == '?' {
			n++
			b.WriteString("$" + strconv.Itoa(n))
		} else {
			b.WriteByte(q[i])
		}
	}
	return b.String()
}

func (c *dbConn) Exec(q string, args ...any) (sql.Result, error) { return c.DB.Exec(c.rb(q), args...) }
func (c *dbConn) Query(q string, args ...any) (*sql.Rows, error) { return c.DB.Query(c.rb(q), args...) }
func (c *dbConn) QueryRow(q string, args ...any) *sql.Row        { return c.DB.QueryRow(c.rb(q), args...) }

// q quotes an identifier that is a reserved word in some dialect.
func (c *dbConn) q(ident string) string {
	if c.dia == dialMySQL {
		return "`" + ident + "`"
	}
	return `"` + ident + `"`
}

// upsert inserts a row or, when one with the same key exists, updates the
// listed columns.
func (c *dbConn) upsert(table, key string, cols []string, update []string, args ...any) error {
	ph := strings.TrimSuffix(strings.Repeat("?,", len(cols)), ",")
	qcols := make([]string, len(cols))
	for i, x := range cols {
		qcols[i] = c.q(x)
	}
	sqlText := fmt.Sprintf("INSERT INTO %s(%s) VALUES(%s)", table, strings.Join(qcols, ","), ph)
	var sets []string
	switch c.dia {
	case dialMySQL:
		for _, u := range update {
			sets = append(sets, c.q(u)+"=VALUES("+c.q(u)+")")
		}
		sqlText += " ON DUPLICATE KEY UPDATE " + strings.Join(sets, ",")
	default:
		for _, u := range update {
			sets = append(sets, c.q(u)+"=excluded."+c.q(u))
		}
		sqlText += fmt.Sprintf(" ON CONFLICT(%s) DO UPDATE SET %s", c.q(key), strings.Join(sets, ","))
	}
	_, err := c.Exec(sqlText, args...)
	return err
}

// isDuplicate reports whether err is a violation of a unique key, in any dialect.
func isDuplicate(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "UNIQUE constraint failed") || strings.Contains(s, "duplicate key value") ||
		strings.Contains(s, "Duplicate entry") || strings.Contains(s, "SQLSTATE 23505")
}

// schema returns the statements that create the tables, one by one: some
// drivers run only one statement per call.
func (c *dbConn) schema(tables []tableDef) []string {
	var out []string
	for _, t := range tables {
		cols := make([]string, 0, len(t.cols)+1)
		for _, col := range t.cols {
			cols = append(cols, c.q(col.name)+" "+c.typeOf(col))
		}
		if t.pk != "" {
			cols = append(cols, "PRIMARY KEY ("+c.q(t.pk)+")")
		}
		if len(t.pkCols) > 0 {
			q := make([]string, len(t.pkCols))
			for i, x := range t.pkCols {
				q[i] = c.q(x)
			}
			cols = append(cols, "PRIMARY KEY ("+strings.Join(q, ", ")+")")
		}
		stmt := "CREATE TABLE IF NOT EXISTS " + t.name + " (" + strings.Join(cols, ", ") + ")"
		if c.dia == dialMySQL {
			stmt += " ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin"
		}
		out = append(out, stmt)
		for _, ix := range t.indexes {
			name := t.name + "_" + strings.Join(ix, "_")
			q := make([]string, len(ix))
			for i, x := range ix {
				q[i] = c.q(x)
			}
			if c.dia == dialMySQL {
				// MySQL has no IF NOT EXISTS for indexes: add them with the table's creation only
				out = append(out, "\x00"+"CREATE INDEX "+name+" ON "+t.name+" ("+strings.Join(q, ", ")+")")
			} else {
				out = append(out, "CREATE INDEX IF NOT EXISTS "+name+" ON "+t.name+" ("+strings.Join(q, ", ")+")")
			}
		}
	}
	return out
}

// column kinds
const (
	kText   = iota // free text
	kKey           // short text that is indexed or a key
	kInt           // 64-bit integer
	kSerial        // auto-increment 64-bit integer, the primary key
)

type colDef struct {
	name string
	kind int
	def  string // default, as SQL ("" for none)
}

type tableDef struct {
	name    string
	cols    []colDef
	pk      string
	pkCols  []string
	indexes [][]string
}

func (c *dbConn) typeOf(col colDef) string {
	var t string
	switch col.kind {
	case kKey:
		t = "VARCHAR(255) NOT NULL"
		if c.dia == dialSQLite {
			t = "TEXT NOT NULL"
		}
	case kInt:
		t = "BIGINT NOT NULL"
	case kSerial:
		switch c.dia {
		case dialPostgres:
			return "BIGSERIAL"
		case dialMySQL:
			return "BIGINT AUTO_INCREMENT"
		default:
			return "INTEGER"
		}
	default:
		t = "TEXT NOT NULL"
	}
	if col.def != "" {
		t += " DEFAULT " + col.def
	}
	return t
}

// migrate creates the tables. Index creation errors "already exists" are not
// errors.
func (c *dbConn) migrate(tables []tableDef) error {
	for _, stmt := range c.schema(tables) {
		isIndex := false
		if strings.HasPrefix(stmt, "\x00") {
			stmt, isIndex = stmt[1:], true
		}
		if _, err := c.DB.Exec(stmt); err != nil {
			if isIndex && (strings.Contains(err.Error(), "Duplicate key name") || strings.Contains(err.Error(), "already exists")) {
				continue
			}
			return fmt.Errorf("%s: %w", firstWords(stmt), err)
		}
	}
	return nil
}

func firstWords(s string) string {
	if len(s) > 60 {
		return s[:60] + "..."
	}
	return s
}
