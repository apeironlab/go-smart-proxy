package relay

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Shared is the database several relays can use together: the address book,
// revocations, enrollments in progress, the certificates issued, who is
// connected where, and the settings edited in the management interface. With
// it a relay holds no state of its own besides the connections it serves, so any
// number of relays behind a load balancer behave as one.
//
// Without it (the default) the relay keeps its state in files and must run
// alone.
type Shared struct {
	db    *dbConn
	admin *adminDB
	// ReplicaID names this relay among the ones sharing the database.
	ReplicaID string
}

var sharedTables = []tableDef{
	{name: "contacts", pkCols: []string{"a", "b"}, cols: []colDef{{"a", kKey, ""}, {"b", kKey, ""}}},
	{name: "pending", pkCols: []string{"to_email", "from_email"}, cols: []colDef{{"to_email", kKey, ""}, {"from_email", kKey, ""}}},
	{name: "devices", pkCols: []string{"email", "device"}, cols: []colDef{{"email", kKey, ""}, {"device", kKey, ""}}},
	{name: "last_seen", pk: "email", cols: []colDef{{"email", kKey, ""}, {"ts", kInt, ""}}},
	{name: "groups_of", pk: "email", cols: []colDef{{"email", kKey, ""}, {"grps", kText, "''"}}},
	{name: "revocations", pk: "entry", cols: []colDef{{"entry", kKey, ""}, {"created", kInt, ""}}},
	{name: "enroll_items", pk: "id", indexes: [][]string{{"state_key"}, {"ticket_key"}, {"expires"}}, cols: []colDef{
		{"id", kKey, ""}, {"email", kKey, ""}, {"state_key", kKey, "''"}, {"ticket_key", kKey, "''"}, {"expires", kInt, ""}, {"data", kText, ""},
	}},
	{name: "revoke_tokens", pk: "hash", cols: []colDef{{"hash", kKey, ""}, {"email", kKey, ""}, {"expires", kInt, ""}}},
	{name: "admin_sessions", pk: "hash", cols: []colDef{
		{"hash", kKey, ""}, {"email", kKey, ""}, {"method", kKey, ""}, {"csrf", kKey, ""}, {"created", kInt, ""}, {"last", kInt, ""},
	}},
	{name: "state_version", pk: "id", cols: []colDef{{"id", kInt, ""}, {"v", kInt, "0"}}},
	{name: "replicas", pk: "id", cols: []colDef{{"id", kKey, ""}, {"addr", kKey, "''"}, {"beat", kInt, ""}}},
	{name: "presence", pkCols: []string{"email", "device"}, indexes: [][]string{{"replica"}}, cols: []colDef{
		{"email", kKey, ""}, {"device", kKey, ""}, {"replica", kKey, ""}, {"addr", kKey, "''"}, {"serial", kKey, "''"},
		{"since", kInt, ""}, {"ctx", kText, "''"}, {"beat", kInt, ""},
	}},
	{name: "kicks", pk: "id", cols: []colDef{
		{"id", kSerial, ""}, {"email", kKey, ""}, {"device", kKey, "''"}, {"serial", kKey, "''"}, {"before_ts", kInt, "0"}, {"ts", kInt, ""},
	}},
	{name: "gw_presence", pk: "id", indexes: [][]string{{"replica"}}, cols: []colDef{
		{"id", kKey, ""}, {"replica", kKey, ""}, {"addr", kKey, "''"}, {"serial", kKey, "''"}, {"since", kInt, ""}, {"beat", kInt, ""},
	}},
}

// OpenShared opens (and prepares) the database named by addr. replicaID names
// this relay; empty means a random one.
func OpenShared(addr, replicaID string) (*Shared, error) {
	db, err := openDB(addr)
	if err != nil {
		return nil, err
	}
	if err := db.migrate(adminTables); err != nil {
		db.Close()
		return nil, fmt.Errorf("database: %w", err)
	}
	if err := db.migrate(sharedTables); err != nil {
		db.Close()
		return nil, fmt.Errorf("database: %w", err)
	}
	// columns the certificate ledger added to a table older releases made
	for _, c := range []struct{ col, def string }{{"ip", "VARCHAR(255) NOT NULL DEFAULT ''"}, {"origin", "BIGINT NOT NULL DEFAULT 0"}} {
		typ := c.def
		if db.dia == dialSQLite {
			typ = strings.Replace(typ, "VARCHAR(255)", "TEXT", 1)
		}
		if err := db.addColumn("certs", c.col, typ); err != nil {
			db.Close()
			return nil, err
		}
	}
	if replicaID == "" {
		b := make([]byte, 5)
		rand.Read(b)
		replicaID = "r-" + hex.EncodeToString(b)
	}
	if !authIDRe.MatchString(replicaID) {
		db.Close()
		return nil, errors.New("the replica id must be lowercase letters, digits, - and _")
	}
	// the single row of the change counter
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM state_version`).Scan(&n); err != nil {
		db.Close()
		return nil, err
	}
	if n == 0 {
		if _, err := db.Exec(`INSERT INTO state_version(id, v) VALUES(1, 0)`); err != nil && !isDuplicate(err) {
			db.Close()
			return nil, err
		}
	}
	sh := &Shared{db: db, ReplicaID: replicaID}
	sh.admin = &adminDB{db: db, changed: sh.bump}
	return sh, nil
}

// Close closes the database.
func (sh *Shared) Close() error { return sh.db.Close() }

// Ping checks that the database answers.
func (sh *Shared) Ping() error { return sh.db.Ping() }

// addColumn adds a column to a table unless it is there.
func (c *dbConn) addColumn(table, col, typ string) error {
	_, err := c.DB.Exec("ALTER TABLE " + table + " ADD COLUMN " + c.q(col) + " " + typ)
	if err != nil {
		s := strings.ToLower(err.Error())
		if strings.Contains(s, "duplicate column") || strings.Contains(s, "already exists") {
			return nil
		}
		return fmt.Errorf("adding %s.%s: %w", table, col, err)
	}
	return nil
}

// bump says that something users can see changed (a contact, who is online,
// the catalog...): the other relays push fresh states to their users.
func (sh *Shared) bump() {
	sh.db.Exec(`UPDATE state_version SET v = v + 1 WHERE id = 1`)
}

// version is the change counter.
func (sh *Shared) version() int64 {
	var v int64
	if err := sh.db.QueryRow(`SELECT v FROM state_version WHERE id = 1`).Scan(&v); err != nil {
		return -1
	}
	return v
}

func nowUnix() int64 { return time.Now().Unix() }

// tx runs fn in a transaction.
func (c *dbConn) tx(fn func(tx *dbTx) error) error {
	t, err := c.DB.Begin()
	if err != nil {
		return err
	}
	if err := fn(&dbTx{Tx: t, c: c}); err != nil {
		t.Rollback()
		return err
	}
	return t.Commit()
}

type dbTx struct {
	*sql.Tx
	c *dbConn
}

func (t *dbTx) Exec(q string, args ...any) (sql.Result, error) { return t.Tx.Exec(t.c.rb(q), args...) }
func (t *dbTx) Query(q string, args ...any) (*sql.Rows, error) { return t.Tx.Query(t.c.rb(q), args...) }
func (t *dbTx) QueryRow(q string, args ...any) *sql.Row        { return t.Tx.QueryRow(t.c.rb(q), args...) }

// insertIgnore inserts a row unless its key exists, and says whether it did.
func (t *dbTx) insertIgnore(table string, cols []string, args ...any) (bool, error) {
	ph := strings.TrimSuffix(strings.Repeat("?,", len(cols)), ",")
	qc := make([]string, len(cols))
	for i, x := range cols {
		qc[i] = t.c.q(x)
	}
	var stmt string
	switch t.c.dia {
	case dialMySQL:
		stmt = fmt.Sprintf("INSERT IGNORE INTO %s(%s) VALUES(%s)", table, strings.Join(qc, ","), ph)
	default:
		stmt = fmt.Sprintf("INSERT INTO %s(%s) VALUES(%s) ON CONFLICT DO NOTHING", table, strings.Join(qc, ","), ph)
	}
	res, err := t.Exec(stmt, args...)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (t *dbTx) deleted(q string, args ...any) (bool, error) {
	res, err := t.Exec(q, args...)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
