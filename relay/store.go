package relay

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Store keeps contacts and pending contact requests, persisted as JSON.
type Store struct {
	mu       sync.Mutex
	path     string
	contacts map[string]map[string]bool // email -> set of contact emails (symmetric)
	pending  map[string]map[string]bool // to -> set of requesters
	devices  map[string]map[string]bool // email -> set of known device codes
	lastSeen map[string]int64           // email -> Unix time of the last disconnection
	groups   map[string][]string        // email -> groups reported when the user last signed in
	sh       *Shared                    // when set, everything is in the shared database
}

type storeFile struct {
	Contacts map[string][]string `json:"contacts"`
	Pending  map[string][]string `json:"pending"`
	Devices  map[string][]string `json:"devices"`
	LastSeen map[string]int64    `json:"lastSeen,omitempty"`
	Groups   map[string][]string `json:"groups,omitempty"`
}

func NewStore(path string) (*Store, error) {
	s := &Store{
		path: path, contacts: map[string]map[string]bool{}, pending: map[string]map[string]bool{},
		devices: map[string]map[string]bool{}, lastSeen: map[string]int64{},
		groups: map[string][]string{},
	}
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var f storeFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	for k, v := range f.Contacts {
		for _, c := range v {
			addTo(s.contacts, k, c)
		}
	}
	for k, v := range f.Pending {
		for _, c := range v {
			addTo(s.pending, k, c)
		}
	}
	for k, v := range f.Devices {
		for _, d := range v {
			addTo(s.devices, k, d)
		}
	}
	for k, v := range f.LastSeen {
		s.lastSeen[k] = v
	}
	for k, v := range f.Groups {
		s.groups[k] = v
	}
	return s, nil
}

func addTo(m map[string]map[string]bool, k, v string) {
	if m[k] == nil {
		m[k] = map[string]bool{}
	}
	m[k][v] = true
}

func delFrom(m map[string]map[string]bool, k, v string) bool {
	if !m[k][v] {
		return false
	}
	delete(m[k], v)
	if len(m[k]) == 0 {
		delete(m, k)
	}
	return true
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (s *Store) saveLocked() {
	if s.path == "" {
		return
	}
	f := storeFile{Contacts: map[string][]string{}, Pending: map[string][]string{}, Devices: map[string][]string{}, LastSeen: map[string]int64{}, Groups: map[string][]string{}}
	for k, v := range s.groups {
		f.Groups[k] = v
	}
	for k, v := range s.contacts {
		f.Contacts[k] = keys(v)
	}
	for k, v := range s.pending {
		f.Pending[k] = keys(v)
	}
	for k, v := range s.devices {
		f.Devices[k] = keys(v)
	}
	for k, v := range s.lastSeen {
		f.LastSeen[k] = v
	}
	b, _ := json.MarshalIndent(f, "", "  ")
	WriteFileAtomic(s.path, b, 0o600)
}

func (s *Store) IsContact(a, b string) bool {
	if s.sh != nil {
		return s.sqlIsContact(a, b)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.contacts[a][b]
}

// RememberDevice records a device that connected at least once for an email.
func (s *Store) RememberDevice(email, device string) bool {
	if s.sh != nil {
		return s.sqlRememberDevice(email, device)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.devices[email][device] {
		return false
	}
	addTo(s.devices, email, device)
	s.saveLocked()
	return true
}

// Seen records that email was online until now.
func (s *Store) Seen(email string, t time.Time) {
	if s.sh != nil {
		s.sqlSeen(email, t)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastSeen[email] = t.Unix()
	s.saveLocked()
}

// LastSeen returns when email was last online (Unix seconds), or 0.
func (s *Store) LastSeen(email string) int64 {
	if s.sh != nil {
		return s.sqlLastSeen(email)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastSeen[email]
}

// Devices returns all known devices of an email, sorted.
func (s *Store) Devices(email string) []string {
	if s.sh != nil {
		return s.sqlDevices(email)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return keys(s.devices[email])
}

// ForgetDevice removes a device code from the list of an address (the device
// shows again if it connects).
func (s *Store) ForgetDevice(email, device string) {
	if s.sh != nil {
		s.sqlForgetDevice(email, device)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if delFrom(s.devices, email, device) {
		s.saveLocked()
	}
}

// Snapshot returns the contacts, incoming and outgoing requests of email.
func (s *Store) Snapshot(email string) (contacts, incoming, outgoing []string) {
	if s.sh != nil {
		return s.sqlSnapshot(email)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	contacts = keys(s.contacts[email])
	incoming = keys(s.pending[email])
	for to, from := range s.pending {
		if from[email] {
			outgoing = append(outgoing, to)
		}
	}
	sort.Strings(outgoing)
	return
}

// Request registers a contact request from -> to. Returns the emails whose
// state changed and a notice for the requester.
func (s *Store) Request(from, to string) (changed []string, notice string) {
	if s.sh != nil {
		return s.sqlRequest(from, to)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case from == to:
		return nil, "cannot add yourself"
	case s.contacts[from][to]:
		return nil, to + " is already a contact"
	case s.pending[to][from]:
		return []string{from}, "request already sent"
	case s.pending[from][to]: // they already asked us: mutual intent, accept
		delFrom(s.pending, from, to)
		addTo(s.contacts, from, to)
		addTo(s.contacts, to, from)
		s.saveLocked()
		return []string{from, to}, ""
	}
	addTo(s.pending, to, from)
	s.saveLocked()
	return []string{from, to}, ""
}

// Respond answers the request of from, addressed to self.
func (s *Store) Respond(self, from string, accept bool) (changed []string) {
	if s.sh != nil {
		return s.sqlRespond(self, from, accept)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !delFrom(s.pending, self, from) {
		return nil
	}
	if accept {
		addTo(s.contacts, self, from)
		addTo(s.contacts, from, self)
	}
	s.saveLocked()
	return []string{self, from}
}

// Remove deletes the contact (both sides) and any pending request between the two.
func (s *Store) Remove(self, other string) (changed []string) {
	if s.sh != nil {
		return s.sqlRemove(self, other)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a := delFrom(s.contacts, self, other)
	b := delFrom(s.contacts, other, self)
	c := delFrom(s.pending, other, self)
	d := delFrom(s.pending, self, other)
	if !(a || b || c || d) {
		return nil
	}
	s.saveLocked()
	return []string{self, other}
}

// SetGroups records the groups an identity provider reported for email at
// sign-in. Applications whose access is by group use them.
func (s *Store) SetGroups(email string, groups []string) {
	if s.sh != nil {
		s.sqlSetGroups(email, groups)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	g := append([]string{}, groups...)
	sort.Strings(g)
	if strings.Join(s.groups[email], "\x00") == strings.Join(g, "\x00") {
		return
	}
	s.groups[email] = g
	s.saveLocked()
}

// Groups returns the groups last recorded for email.
func (s *Store) Groups(email string) []string {
	if s.sh != nil {
		return s.sqlGroups(email)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.groups[email]...)
}

// NewSharedStore returns a store kept in the shared database.
func NewSharedStore(sh *Shared) *Store {
	return &Store{sh: sh}
}
