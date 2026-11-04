package relay

import (
	"database/sql"
	"errors"
	"log"
	"sort"
	"strings"
	"time"
)

// The Store in the shared database. Same rules as the file version; every
// change that users can see also bumps the change counter, so that the other
// relays push the new state to their own users.

func (s *Store) sqlErr(what string, err error) {
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		log.Printf("store: %s: %v", what, err)
	}
}

func (s *Store) strings(q string, args ...any) []string {
	rows, err := s.sh.db.Query(q, args...)
	if err != nil {
		s.sqlErr(q, err)
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if rows.Scan(&v) == nil {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func (s *Store) sqlIsContact(a, b string) bool {
	var n int
	s.sqlErr("is contact", s.sh.db.QueryRow(`SELECT COUNT(*) FROM contacts WHERE a = ? AND b = ?`, a, b).Scan(&n))
	return n > 0
}

func (s *Store) sqlRememberDevice(email, device string) bool {
	var added bool
	err := s.sh.db.tx(func(tx *dbTx) error {
		var err error
		added, err = tx.insertIgnore("devices", []string{"email", "device"}, email, device)
		return err
	})
	s.sqlErr("remember device", err)
	if added {
		s.sh.bump()
	}
	return added
}

func (s *Store) sqlSeen(email string, t time.Time) {
	s.sqlErr("seen", s.sh.db.upsert("last_seen", "email", []string{"email", "ts"}, []string{"ts"}, email, t.Unix()))
}

func (s *Store) sqlLastSeen(email string) int64 {
	var ts int64
	if err := s.sh.db.QueryRow(`SELECT ts FROM last_seen WHERE email = ?`, email).Scan(&ts); err != nil {
		return 0
	}
	return ts
}

func (s *Store) sqlDevices(email string) []string {
	return s.strings(`SELECT device FROM devices WHERE email = ?`, email)
}

func (s *Store) sqlForgetDevice(email, device string) {
	_, err := s.sh.db.Exec(`DELETE FROM devices WHERE email = ? AND device = ?`, email, device)
	s.sqlErr("forget device", err)
}

func (s *Store) sqlSnapshot(email string) (contacts, incoming, outgoing []string) {
	contacts = s.strings(`SELECT b FROM contacts WHERE a = ?`, email)
	incoming = s.strings(`SELECT from_email FROM pending WHERE to_email = ?`, email)
	outgoing = s.strings(`SELECT to_email FROM pending WHERE from_email = ?`, email)
	return
}

func (s *Store) sqlRequest(from, to string) (changed []string, notice string) {
	err := s.sh.db.tx(func(tx *dbTx) error {
		count := func(q string, a ...any) (int, error) {
			var n int
			err := tx.QueryRow(q, a...).Scan(&n)
			return n, err
		}
		switch {
		case from == to:
			notice = "cannot add yourself"
			return nil
		}
		if n, err := count(`SELECT COUNT(*) FROM contacts WHERE a = ? AND b = ?`, from, to); err != nil {
			return err
		} else if n > 0 {
			notice = to + " is already a contact"
			return nil
		}
		if n, err := count(`SELECT COUNT(*) FROM pending WHERE to_email = ? AND from_email = ?`, to, from); err != nil {
			return err
		} else if n > 0 {
			changed, notice = []string{from}, "request already sent"
			return nil
		}
		if n, err := count(`SELECT COUNT(*) FROM pending WHERE to_email = ? AND from_email = ?`, from, to); err != nil {
			return err
		} else if n > 0 { // they already asked us: mutual intent, accept
			if _, err := tx.Exec(`DELETE FROM pending WHERE to_email = ? AND from_email = ?`, from, to); err != nil {
				return err
			}
			if _, err := tx.insertIgnore("contacts", []string{"a", "b"}, from, to); err != nil {
				return err
			}
			if _, err := tx.insertIgnore("contacts", []string{"a", "b"}, to, from); err != nil {
				return err
			}
			changed = []string{from, to}
			return nil
		}
		if _, err := tx.insertIgnore("pending", []string{"to_email", "from_email"}, to, from); err != nil {
			return err
		}
		changed = []string{from, to}
		return nil
	})
	s.sqlErr("request", err)
	if len(changed) > 0 {
		s.sh.bump()
	}
	return
}

func (s *Store) sqlRespond(self, from string, accept bool) (changed []string) {
	err := s.sh.db.tx(func(tx *dbTx) error {
		ok, err := tx.deleted(`DELETE FROM pending WHERE to_email = ? AND from_email = ?`, self, from)
		if err != nil || !ok {
			return err
		}
		if accept {
			if _, err := tx.insertIgnore("contacts", []string{"a", "b"}, self, from); err != nil {
				return err
			}
			if _, err := tx.insertIgnore("contacts", []string{"a", "b"}, from, self); err != nil {
				return err
			}
		}
		changed = []string{self, from}
		return nil
	})
	s.sqlErr("respond", err)
	if len(changed) > 0 {
		s.sh.bump()
	}
	return
}

func (s *Store) sqlRemove(self, other string) (changed []string) {
	err := s.sh.db.tx(func(tx *dbTx) error {
		any := false
		for _, q := range []struct {
			sql  string
			a, b string
		}{
			{`DELETE FROM contacts WHERE a = ? AND b = ?`, self, other},
			{`DELETE FROM contacts WHERE a = ? AND b = ?`, other, self},
			{`DELETE FROM pending WHERE to_email = ? AND from_email = ?`, other, self},
			{`DELETE FROM pending WHERE to_email = ? AND from_email = ?`, self, other},
		} {
			ok, err := tx.deleted(q.sql, q.a, q.b)
			if err != nil {
				return err
			}
			any = any || ok
		}
		if any {
			changed = []string{self, other}
		}
		return nil
	})
	s.sqlErr("remove", err)
	if len(changed) > 0 {
		s.sh.bump()
	}
	return
}

func (s *Store) sqlSetGroups(email string, groups []string) {
	g := append([]string{}, groups...)
	sort.Strings(g)
	joined := strings.Join(g, "\n") // not a comma: distinguished names have them
	var old string
	err := s.sh.db.QueryRow(`SELECT grps FROM groups_of WHERE email = ?`, email).Scan(&old)
	if err == nil && old == joined {
		return
	}
	s.sqlErr("set groups", s.sh.db.upsert("groups_of", "email", []string{"email", "grps"}, []string{"grps"}, email, joined))
	s.sh.bump() // the applications a user may open can change
}

func (s *Store) sqlGroups(email string) []string {
	var g string
	if err := s.sh.db.QueryRow(`SELECT grps FROM groups_of WHERE email = ?`, email).Scan(&g); err != nil || g == "" {
		return []string{}
	}
	return strings.Split(g, "\n")
}
