package relay

import (
	"encoding/json"
	"os"
	"sort"
	"sync"
)

// Store keeps contacts and pending contact requests, persisted as JSON.
type Store struct {
	mu       sync.Mutex
	path     string
	contacts map[string]map[string]bool // email -> set of contact emails (symmetric)
	pending  map[string]map[string]bool // to -> set of requesters
	devices  map[string]map[string]bool // email -> set of known device codes
}

type storeFile struct {
	Contacts map[string][]string `json:"contacts"`
	Pending  map[string][]string `json:"pending"`
	Devices  map[string][]string `json:"devices"`
}

func NewStore(path string) (*Store, error) {
	s := &Store{
		path: path, contacts: map[string]map[string]bool{}, pending: map[string]map[string]bool{},
		devices: map[string]map[string]bool{},
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
	f := storeFile{Contacts: map[string][]string{}, Pending: map[string][]string{}, Devices: map[string][]string{}}
	for k, v := range s.contacts {
		f.Contacts[k] = keys(v)
	}
	for k, v := range s.pending {
		f.Pending[k] = keys(v)
	}
	for k, v := range s.devices {
		f.Devices[k] = keys(v)
	}
	b, _ := json.MarshalIndent(f, "", "  ")
	tmp := s.path + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		os.Rename(tmp, s.path)
	}
}

func (s *Store) IsContact(a, b string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.contacts[a][b]
}

// RememberDevice records a device that connected at least once for an email.
func (s *Store) RememberDevice(email, device string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.devices[email][device] {
		return false
	}
	addTo(s.devices, email, device)
	s.saveLocked()
	return true
}

// Devices returns all known devices of an email, sorted.
func (s *Store) Devices(email string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return keys(s.devices[email])
}

// Snapshot returns the contacts, incoming and outgoing requests of email.
func (s *Store) Snapshot(email string) (contacts, incoming, outgoing []string) {
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
