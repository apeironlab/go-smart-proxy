package relay

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"time"
)

// With a shared database the enrollments in progress live in it, so that the
// steps of one enrollment (the request, the browser coming back from the
// identity provider, the proxy polling) may reach different relays. The maps in
// EnrollServer are then a cache of the copies read from the database: every
// lookup reads the row again, and saveLocked writes back what changed.

// itemRecord is an Enrollment with the fields that are kept in memory only,
// which a database row must carry too.
type itemRecord struct {
	Enrollment
	XState         string `json:"xState,omitempty"`
	XNonce         string `json:"xNonce,omitempty"`
	XVerifier      string `json:"xVerifier,omitempty"`
	XSAMLRequestID string `json:"xSamlId,omitempty"`
	XTicket        string `json:"xTicket,omitempty"`
	XClientAddr    string `json:"xClientAddr,omitempty"`
	XAdmin         bool   `json:"xAdmin,omitempty"`
	XLoginHash     string `json:"xLoginHash,omitempty"`
}

func encodeItem(it *Enrollment) (data, stateKey, ticketKey string) {
	rec := itemRecord{Enrollment: *it, XState: it.State, XNonce: it.Nonce, XVerifier: it.Verifier, XSAMLRequestID: it.SAMLRequestID,
		XTicket: it.Ticket, XClientAddr: it.ClientAddr, XAdmin: it.Admin, XLoginHash: it.LoginHash}
	b, _ := json.Marshal(rec)
	stateKey = it.State
	if it.stateUsed {
		stateKey = ""
	}
	return string(b), stateKey, it.Ticket
}

func decodeItem(data string, stateKey string) (*Enrollment, error) {
	var rec itemRecord
	if err := json.Unmarshal([]byte(data), &rec); err != nil {
		return nil, err
	}
	it := rec.Enrollment
	it.State, it.Nonce, it.Verifier, it.SAMLRequestID = rec.XState, rec.XNonce, rec.XVerifier, rec.XSAMLRequestID
	it.Ticket, it.ClientAddr, it.Admin, it.LoginHash = rec.XTicket, rec.XClientAddr, rec.XAdmin, rec.XLoginHash
	it.stateUsed = stateKey == "" && it.State != ""
	it.saved = data
	return &it, nil
}

func (s *EnrollServer) shared() bool { return s.cfg.Shared != nil }

func (s *EnrollServer) sdb() *dbConn { return s.cfg.Shared.db }

// itemAddLocked registers a new enrollment.
func (s *EnrollServer) itemAddLocked(it *Enrollment) {
	s.items[it.ID] = it
	if !s.shared() {
		if it.State != "" {
			s.byState[it.State] = it.ID
		}
		s.saveLocked()
		return
	}
	data, sk, tk := encodeItem(it)
	_, err := s.sdb().Exec(`INSERT INTO enroll_items(id, email, state_key, ticket_key, expires, data) VALUES(?,?,?,?,?,?)`,
		it.ID, it.Email, sk, tk, it.Expires.Unix(), data)
	if err != nil {
		log.Printf("enrollment: cannot store the request: %v", err)
	}
	it.saved = data
}

// itemLoadLocked returns an enrollment by id: in shared mode a fresh copy.
func (s *EnrollServer) itemLoadLocked(id string) *Enrollment {
	if !s.shared() {
		return s.items[id]
	}
	return s.loadWhere(`id = ?`, id)
}

func (s *EnrollServer) loadWhere(where string, arg any) *Enrollment {
	var data, sk string
	err := s.sdb().QueryRow(`SELECT data, state_key FROM enroll_items WHERE `+where, arg).Scan(&data, &sk)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			log.Printf("enrollment: %v", err)
		}
		return nil
	}
	it, err := decodeItem(data, sk)
	if err != nil {
		return nil
	}
	s.items[it.ID] = it
	return it
}

// itemByStateLocked finds the enrollment waiting for a return from the identity
// provider and uses the state up: it is good for one return only.
func (s *EnrollServer) itemByStateLocked(state string) *Enrollment {
	if state == "" {
		return nil
	}
	if !s.shared() {
		id, ok := s.byState[state]
		delete(s.byState, state)
		if !ok {
			return nil
		}
		return s.items[id]
	}
	var id string
	if err := s.sdb().QueryRow(`SELECT id FROM enroll_items WHERE state_key = ?`, state).Scan(&id); err != nil {
		return nil
	}
	// whoever clears the key first wins
	res, err := s.sdb().Exec(`UPDATE enroll_items SET state_key = '' WHERE id = ? AND state_key = ?`, id, state)
	if err != nil {
		return nil
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return nil
	}
	it := s.loadWhere(`id = ?`, id)
	if it != nil {
		it.stateUsed = true
	}
	return it
}

// setTicketLocked gives the enrollment a ticket for the confirmation page.
func (s *EnrollServer) setTicketLocked(it *Enrollment, ticket string) {
	it.Ticket = ticket
	if !s.shared() {
		s.byTicket[ticket] = it.ID
		return
	}
	s.saveLocked()
}

// itemByTicketLocked finds the enrollment a confirmation ticket belongs to.
func (s *EnrollServer) itemByTicketLocked(ticket string) *Enrollment {
	if ticket == "" {
		return nil
	}
	if !s.shared() {
		id, ok := s.byTicket[ticket]
		if !ok {
			return nil
		}
		return s.items[id]
	}
	return s.loadWhere(`ticket_key = ?`, ticket)
}

// clearTicketLocked uses a ticket up.
func (s *EnrollServer) clearTicketLocked(it *Enrollment, ticket string) {
	delete(s.byTicket, ticket)
	it.Ticket = ""
}

// itemDropLocked forgets an enrollment.
func (s *EnrollServer) itemDropLocked(id string) {
	delete(s.items, id)
	if !s.shared() {
		s.saveLocked()
		return
	}
	s.sdb().Exec(`DELETE FROM enroll_items WHERE id = ?`, id)
}

// userKnownLocked says whether the address has been issued a certificate
// before (the e-mail says so: "a new configuration was asked").
func (s *EnrollServer) userKnownLocked(email string) bool {
	if !s.shared() {
		return s.users[email]
	}
	var n int
	s.sdb().QueryRow(`SELECT COUNT(*) FROM certs WHERE email = ?`, email).Scan(&n)
	return n > 0
}

func (s *EnrollServer) noteUserLocked(email string) {
	if !s.shared() {
		s.users[email] = true
	}
}

// flushLocked writes back the enrollments that changed since they were read.
// A row somebody else changed meanwhile is left alone and forgotten.
func (s *EnrollServer) flushLocked() {
	for id, it := range s.items {
		data, sk, tk := encodeItem(it)
		if data == it.saved {
			continue
		}
		res, err := s.sdb().Exec(`UPDATE enroll_items SET email = ?, state_key = ?, ticket_key = ?, expires = ?, data = ? WHERE id = ? AND data = ?`,
			it.Email, sk, tk, it.Expires.Unix(), data, id, it.saved)
		if err != nil {
			log.Printf("enrollment: cannot save the request: %v", err)
			continue
		}
		if n, _ := res.RowsAffected(); n == 0 {
			delete(s.items, id) // changed elsewhere: read it again next time
			continue
		}
		it.saved = data
	}
}

// pruneSharedLocked drops what has expired from the database.
func (s *EnrollServer) pruneSharedLocked(now time.Time) {
	db := s.sdb()
	db.Exec(`DELETE FROM enroll_items WHERE expires < ?`, now.Add(-time.Hour).Unix())
	db.Exec(`DELETE FROM revoke_tokens WHERE expires < ?`, now.Unix())
	db.Exec(`DELETE FROM certs WHERE expires < ?`, now.Add(-ledgerKeep).Unix())
	for id, it := range s.items { // the cache forgets them too
		if now.After(it.Expires.Add(time.Hour)) {
			delete(s.items, id)
		}
	}
}

// ---- the ledger of certificates, in the shared database ---------------

func (s *EnrollServer) sqlRecordIssued(c *IssuedCert) {
	err := s.sdb().upsert("certs", "serial",
		[]string{"serial", "email", "device", "method", "issued", "expires", "ip", "origin"},
		[]string{"email", "device", "method", "issued", "expires", "ip", "origin"},
		c.Serial, c.Email, c.Device, c.Method, c.Issued.Unix(), c.Expires.Unix(), c.IP, c.Origin.Unix())
	if err != nil {
		log.Printf("recording the certificate of %s: %v", c.Email, err)
	}
}

func (s *EnrollServer) sqlActiveCerts(email string) []IssuedCert {
	rows, err := s.sdb().Query(`SELECT serial, email, device, method, ip, issued, expires, origin FROM certs WHERE email = ? AND revoked = 0 AND expires > ? ORDER BY issued DESC`,
		email, nowUnix())
	if err != nil {
		return nil
	}
	var all []IssuedCert
	for rows.Next() {
		var c IssuedCert
		var issued, expires, origin int64
		if rows.Scan(&c.Serial, &c.Email, &c.Device, &c.Method, &c.IP, &issued, &expires, &origin) != nil {
			continue
		}
		c.Issued, c.Expires = time.Unix(issued, 0), time.Unix(expires, 0)
		if origin > 0 {
			c.Origin = time.Unix(origin, 0)
		}
		all = append(all, c)
	}
	rows.Close() // before asking for anything else: SQLite has one connection
	var out []IssuedCert
	for _, c := range all {
		if !s.cfg.Revoked.IsRevoked(c.Email, c.Serial) {
			out = append(out, c)
		}
	}
	return out
}

func (s *EnrollServer) sqlActiveCertCount() int {
	var n int
	s.sdb().QueryRow(`SELECT COUNT(*) FROM certs WHERE revoked = 0 AND expires > ?`, nowUnix()).Scan(&n)
	return n
}

func (s *EnrollServer) sqlOriginOf(serial string, fallback time.Time) time.Time {
	var issued, origin int64
	if err := s.sdb().QueryRow(`SELECT issued, origin FROM certs WHERE serial = ?`, serial).Scan(&issued, &origin); err != nil {
		return fallback
	}
	if origin > 0 {
		return time.Unix(origin, 0)
	}
	return time.Unix(issued, 0)
}

// ---- tokens of the revocation e-mails ---------------------------------

func (s *EnrollServer) putRevokeTokenLocked(hash, email string, expires time.Time) {
	if !s.shared() {
		s.revoke[hash] = &revokeToken{email: email, expires: expires}
		return
	}
	s.sdb().Exec(`INSERT INTO revoke_tokens(hash, email, expires) VALUES(?,?,?)`, hash, email, expires.Unix())
}

func (s *EnrollServer) getRevokeTokenLocked(hash string) (string, bool) {
	if !s.shared() {
		t := s.revoke[hash]
		if t == nil || time.Now().After(t.expires) {
			return "", false
		}
		return t.email, true
	}
	var email string
	var expires int64
	if err := s.sdb().QueryRow(`SELECT email, expires FROM revoke_tokens WHERE hash = ?`, hash).Scan(&email, &expires); err != nil || nowUnix() > expires {
		return "", false
	}
	return email, true
}

func (s *EnrollServer) delRevokeTokenLocked(hash string) {
	if !s.shared() {
		delete(s.revoke, hash)
		return
	}
	s.sdb().Exec(`DELETE FROM revoke_tokens WHERE hash = ?`, hash)
}

// ---- administrator sessions, in the shared database -------------------

func (a *Admin) startSharedSession(key, email, method string, now time.Time) {
	db := a.sh.db
	db.Exec(`DELETE FROM admin_sessions WHERE created < ? OR last < ?`, now.Add(-a.cfg.SessionTTL).Unix(), now.Add(-adminIdleTTL).Unix())
	_, err := db.Exec(`INSERT INTO admin_sessions(hash, email, method, csrf, created, last) VALUES(?,?,?,?,?,?)`,
		key, email, method, randomToken(24), now.Unix(), now.Unix())
	if err != nil {
		a.log.Printf("admin: cannot store the session: %v", err)
	}
}

func (a *Admin) sharedSession(key string, now time.Time) *adminSession {
	var email, method, csrf string
	var created, last int64
	err := a.sh.db.QueryRow(`SELECT email, method, csrf, created, last FROM admin_sessions WHERE hash = ?`, key).Scan(&email, &method, &csrf, &created, &last)
	if err != nil {
		return nil
	}
	s := &adminSession{email: email, method: method, csrf: csrf, created: time.Unix(created, 0), last: time.Unix(last, 0)}
	if now.Sub(s.created) > a.cfg.SessionTTL || now.Sub(s.last) > adminIdleTTL {
		a.sh.db.Exec(`DELETE FROM admin_sessions WHERE hash = ?`, key)
		return nil
	}
	if now.Sub(s.last) > 30*time.Second { // not on every request
		a.sh.db.Exec(`UPDATE admin_sessions SET last = ? WHERE hash = ?`, now.Unix(), key)
	}
	s.last = now
	return s
}
