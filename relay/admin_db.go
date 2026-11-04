package relay

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure Go SQLite driver
)

// adminDB is the database of the management interface: the local password
// users, the certificates that were issued, the audit log and the enrollment
// rules edited from the interface.
type adminDB struct {
	db *sql.DB
}

const adminSchema = `
CREATE TABLE IF NOT EXISTS users (
	username TEXT PRIMARY KEY,
	hash     TEXT NOT NULL,
	email    TEXT NOT NULL,
	groups   TEXT NOT NULL DEFAULT '',
	created  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS certs (
	serial     TEXT PRIMARY KEY,
	email      TEXT NOT NULL,
	device     TEXT NOT NULL DEFAULT '',
	method     TEXT NOT NULL DEFAULT '',
	issued     INTEGER NOT NULL,
	expires    INTEGER NOT NULL,
	revoked    INTEGER NOT NULL DEFAULT 0,
	revoked_by TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS certs_email ON certs(email);
CREATE TABLE IF NOT EXISTS gateways (
	serial     TEXT PRIMARY KEY,
	id         TEXT NOT NULL,
	issued     INTEGER NOT NULL,
	expires    INTEGER NOT NULL,
	revoked    INTEGER NOT NULL DEFAULT 0,
	revoked_by TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS gateways_id ON gateways(id);
CREATE TABLE IF NOT EXISTS events (
	id      INTEGER PRIMARY KEY AUTOINCREMENT,
	ts      INTEGER NOT NULL,
	kind    TEXT NOT NULL,
	actor   TEXT NOT NULL DEFAULT '',
	subject TEXT NOT NULL DEFAULT '',
	detail  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);`

const maxEvents = 100000

func openAdminDB(path string) (*adminDB, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("the database path is required")
	}
	// Create the file private before the driver does: it holds password hashes
	// and the SMTP password.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	f.Close()
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(adminSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("database %s: %w", path, err)
	}
	return &adminDB{db: db}, nil
}

func (d *adminDB) Close() error { return d.db.Close() }

// ---- users ------------------------------------------------------------

// LocalUser is a user of a password method kept in the database.
type LocalUser struct {
	Username string    `json:"username"`
	Email    string    `json:"email"`
	Groups   []string  `json:"groups"`
	Created  time.Time `json:"created"`
}

func splitGroups(s string) []string {
	out := []string{}
	for _, g := range strings.Split(s, ",") {
		if g = strings.TrimSpace(g); g != "" {
			out = append(out, g)
		}
	}
	return out
}

func joinGroups(g []string) string {
	clean := []string{}
	for _, x := range g {
		x = strings.TrimSpace(strings.ReplaceAll(x, ",", " "))
		if x != "" {
			clean = append(clean, x)
		}
	}
	return strings.Join(clean, ",")
}

func (d *adminDB) lookupUser(name string) (passwordUser, bool, error) {
	var hash, email, groups string
	err := d.db.QueryRow(`SELECT hash, email, groups FROM users WHERE username = ?`, name).Scan(&hash, &email, &groups)
	if errors.Is(err, sql.ErrNoRows) {
		return passwordUser{}, false, nil
	}
	if err != nil {
		return passwordUser{}, false, err
	}
	return passwordUser{hash: []byte(hash), email: email, groups: splitGroups(groups)}, true, nil
}

func (d *adminDB) listUsers() ([]LocalUser, error) {
	rows, err := d.db.Query(`SELECT username, email, groups, created FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LocalUser{}
	for rows.Next() {
		var u LocalUser
		var groups string
		var created int64
		if err := rows.Scan(&u.Username, &u.Email, &groups, &created); err != nil {
			return nil, err
		}
		u.Groups, u.Created = splitGroups(groups), time.Unix(created, 0)
		out = append(out, u)
	}
	return out, rows.Err()
}

var errUserExists = errors.New("this user name is already in use")

func validUsername(name string) bool {
	return name != "" && len(name) <= 64 && !strings.ContainsAny(name, ":,\n\r\t ")
}

func (d *adminDB) addUser(name, password, email string, groups []string) error {
	name = strings.ToLower(strings.TrimSpace(name))
	if !validUsername(name) {
		return errors.New("invalid user name")
	}
	if strings.TrimSpace(email) == "" {
		email = name
	}
	email, ok := NormalizeEmail(email)
	if !ok {
		return errors.New("invalid e-mail address")
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	_, err = d.db.Exec(`INSERT INTO users(username, hash, email, groups, created) VALUES(?,?,?,?,?)`,
		name, hash, email, joinGroups(groups), time.Now().Unix())
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return errUserExists
	}
	return err
}

// updateUser changes the e-mail address and groups of a user and, when
// password is not empty, the password.
func (d *adminDB) updateUser(name, password, email string, groups []string) error {
	name = strings.ToLower(strings.TrimSpace(name))
	email, ok := NormalizeEmail(email)
	if !ok {
		return errors.New("invalid e-mail address")
	}
	var res sql.Result
	var err error
	if password != "" {
		hash, herr := HashPassword(password)
		if herr != nil {
			return herr
		}
		res, err = d.db.Exec(`UPDATE users SET hash = ?, email = ?, groups = ? WHERE username = ?`, hash, email, joinGroups(groups), name)
	} else {
		res, err = d.db.Exec(`UPDATE users SET email = ?, groups = ? WHERE username = ?`, email, joinGroups(groups), name)
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (d *adminDB) deleteUser(name string) error {
	res, err := d.db.Exec(`DELETE FROM users WHERE username = ?`, strings.ToLower(strings.TrimSpace(name)))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ---- certificates -----------------------------------------------------

// CertRecord is a certificate the relay issued.
type CertRecord struct {
	Serial    string    `json:"serial"`
	Email     string    `json:"email"`
	Device    string    `json:"device,omitempty"`
	Method    string    `json:"method,omitempty"`
	Issued    time.Time `json:"issued"`
	Expires   time.Time `json:"expires"`
	Revoked   bool      `json:"revoked"`
	RevokedBy string    `json:"revokedBy,omitempty"`
}

func (d *adminDB) recordCert(c CertRecord) error {
	_, err := d.db.Exec(`INSERT OR REPLACE INTO certs(serial, email, device, method, issued, expires) VALUES(?,?,?,?,?,?)`,
		c.Serial, c.Email, c.Device, c.Method, c.Issued.Unix(), c.Expires.Unix())
	return err
}

func scanCerts(rows *sql.Rows) ([]CertRecord, error) {
	defer rows.Close()
	out := []CertRecord{}
	for rows.Next() {
		var c CertRecord
		var issued, expires, revoked int64
		if err := rows.Scan(&c.Serial, &c.Email, &c.Device, &c.Method, &issued, &expires, &revoked, &c.RevokedBy); err != nil {
			return nil, err
		}
		c.Issued, c.Expires, c.Revoked = time.Unix(issued, 0), time.Unix(expires, 0), revoked != 0
		out = append(out, c)
	}
	return out, rows.Err()
}

const certCols = `serial, email, device, method, issued, expires, revoked, revoked_by`

func (d *adminDB) certs(email string) ([]CertRecord, error) {
	rows, err := d.db.Query(`SELECT `+certCols+` FROM certs WHERE email = ? ORDER BY issued DESC`, email)
	if err != nil {
		return nil, err
	}
	return scanCerts(rows)
}

func (d *adminDB) allCerts() ([]CertRecord, error) {
	rows, err := d.db.Query(`SELECT ` + certCols + ` FROM certs ORDER BY issued DESC`)
	if err != nil {
		return nil, err
	}
	return scanCerts(rows)
}

func (d *adminDB) cert(serial string) (CertRecord, bool, error) {
	rows, err := d.db.Query(`SELECT `+certCols+` FROM certs WHERE serial = ?`, serial)
	if err != nil {
		return CertRecord{}, false, err
	}
	cs, err := scanCerts(rows)
	if err != nil || len(cs) == 0 {
		return CertRecord{}, false, err
	}
	return cs[0], true, nil
}

func (d *adminDB) markCert(serial string, revoked bool, by string) error {
	v := 0
	if !revoked {
		by = ""
	} else {
		v = 1
	}
	_, err := d.db.Exec(`UPDATE certs SET revoked = ?, revoked_by = ? WHERE serial = ?`, v, by, serial)
	return err
}

// ---- events -----------------------------------------------------------

// Event is an entry of the audit log.
type Event struct {
	ID      int64     `json:"id"`
	Time    time.Time `json:"time"`
	Kind    string    `json:"kind"`
	Actor   string    `json:"actor,omitempty"`
	Subject string    `json:"subject,omitempty"`
	Detail  string    `json:"detail,omitempty"`
}

func (d *adminDB) addEvent(kind, actor, subject, detail string) error {
	clip := func(s string, n int) string {
		if len(s) > n {
			return s[:n]
		}
		return s
	}
	_, err := d.db.Exec(`INSERT INTO events(ts, kind, actor, subject, detail) VALUES(?,?,?,?,?)`,
		time.Now().UnixMilli(), clip(kind, 64), clip(actor, 256), clip(subject, 256), clip(detail, 1024))
	return err
}

// pruneEvents keeps the newest maxEvents entries.
func (d *adminDB) pruneEvents() {
	d.db.Exec(`DELETE FROM events WHERE id <= (SELECT MAX(id) FROM events) - ?`, maxEvents)
}

// EventFilter selects events. Before is a cursor: only events with a smaller
// id are returned.
type EventFilter struct {
	Kind   string // exact kind or a prefix ending in "."
	Search string // substring of actor, subject or detail
	Before int64
	Limit  int
}

func (d *adminDB) events(f EventFilter) ([]Event, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	q := `SELECT id, ts, kind, actor, subject, detail FROM events WHERE 1=1`
	var args []any
	if f.Kind != "" {
		if strings.HasSuffix(f.Kind, ".") {
			q += ` AND kind LIKE ? ESCAPE '\'`
			args = append(args, escapeLike(f.Kind)+"%")
		} else {
			q += ` AND kind = ?`
			args = append(args, f.Kind)
		}
	}
	if f.Search != "" {
		q += ` AND (actor LIKE ? ESCAPE '\' OR subject LIKE ? ESCAPE '\' OR detail LIKE ? ESCAPE '\')`
		like := "%" + escapeLike(f.Search) + "%"
		args = append(args, like, like, like)
	}
	if f.Before > 0 {
		q += ` AND id < ?`
		args = append(args, f.Before)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, f.Limit)
	rows, err := d.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		var ts int64
		if err := rows.Scan(&e.ID, &ts, &e.Kind, &e.Actor, &e.Subject, &e.Detail); err != nil {
			return nil, err
		}
		e.Time = time.UnixMilli(ts)
		out = append(out, e)
	}
	return out, rows.Err()
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// ---- settings ---------------------------------------------------------

func (d *adminDB) getSetting(key string, v any) (bool, error) {
	var raw string
	err := d.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal([]byte(raw), v)
}

func (d *adminDB) setSetting(key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = d.db.Exec(`INSERT INTO settings(key, value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, string(b))
	return err
}

// ---- gateways ---------------------------------------------------------

// GatewayCert is a certificate issued to an application gateway.
type GatewayCert struct {
	Serial    string    `json:"serial"`
	ID        string    `json:"id"`
	Issued    time.Time `json:"issued"`
	Expires   time.Time `json:"expires"`
	Revoked   bool      `json:"revoked"`
	RevokedBy string    `json:"revokedBy,omitempty"`
}

func (d *adminDB) recordGateway(g GatewayCert) error {
	_, err := d.db.Exec(`INSERT OR REPLACE INTO gateways(serial, id, issued, expires) VALUES(?,?,?,?)`,
		g.Serial, g.ID, g.Issued.Unix(), g.Expires.Unix())
	return err
}

func (d *adminDB) gatewayCerts() ([]GatewayCert, error) {
	rows, err := d.db.Query(`SELECT serial, id, issued, expires, revoked, revoked_by FROM gateways ORDER BY id, issued DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []GatewayCert{}
	for rows.Next() {
		var g GatewayCert
		var issued, expires, revoked int64
		if err := rows.Scan(&g.Serial, &g.ID, &issued, &expires, &revoked, &g.RevokedBy); err != nil {
			return nil, err
		}
		g.Issued, g.Expires, g.Revoked = time.Unix(issued, 0), time.Unix(expires, 0), revoked != 0
		out = append(out, g)
	}
	return out, rows.Err()
}

func (d *adminDB) markGateway(serial string, by string) error {
	_, err := d.db.Exec(`UPDATE gateways SET revoked = 1, revoked_by = ? WHERE serial = ?`, by, serial)
	return err
}
