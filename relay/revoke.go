package relay

import (
	"bufio"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Revocations is a file-backed deny list of client certificates. Each line is
// either an e-mail address (every certificate of that identity is refused) or
// a certificate serial number in hexadecimal prefixed by "serial:". Blank lines
// and lines starting with '#' are ignored. The file is re-read when it changes,
// so a revocation takes effect for new connections without restarting.
type Revocations struct {
	path string

	mu      sync.Mutex
	mtime   time.Time
	size    int64
	emails  map[string]bool
	serials map[string]bool
}

// NewRevocations returns a deny list backed by path. A missing file means that
// nothing is revoked. An empty path disables revocation checks.
func NewRevocations(path string) *Revocations {
	return &Revocations{path: path, emails: map[string]bool{}, serials: map[string]bool{}}
}

func (r *Revocations) reload() {
	if r.path == "" {
		return
	}
	info, err := os.Stat(r.path)
	if err != nil {
		r.mtime, r.size = time.Time{}, 0
		r.emails, r.serials = map[string]bool{}, map[string]bool{}
		return
	}
	if info.ModTime().Equal(r.mtime) && info.Size() == r.size {
		return
	}
	f, err := os.Open(r.path)
	if err != nil {
		return
	}
	defer f.Close()
	emails, serials := map[string]bool{}, map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if s, ok := strings.CutPrefix(line, "serial:"); ok {
			serials[strings.ToLower(strings.TrimSpace(s))] = true
			continue
		}
		if e, ok := NormalizeEmail(line); ok {
			emails[e] = true
		}
	}
	r.emails, r.serials = emails, serials
	r.mtime, r.size = info.ModTime(), info.Size()
}

// IsRevoked reports whether a certificate serial (lowercase hex) or the e-mail
// identity is revoked, for a certificate that is not at hand.
func (r *Revocations) IsRevoked(email, serial string) bool {
	if r == nil || r.path == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reload()
	return r.serials[strings.ToLower(serial)] || r.emails[email]
}

// Revoked reports whether the certificate (or the e-mail identity it carries)
// has been revoked.
func (r *Revocations) Revoked(cert *x509.Certificate) bool {
	if r == nil || r.path == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reload()
	if cert.SerialNumber != nil && r.serials[strings.ToLower(cert.SerialNumber.Text(16))] {
		return true
	}
	if email, ok := EmailFromCert(cert); ok && r.emails[email] {
		return true
	}
	return false
}

// Revoke appends an e-mail address or a serial number ("serial:<hex>") to the
// deny list file.
func Revoke(path, entry string) error {
	entry = strings.TrimSpace(entry)
	if !strings.HasPrefix(entry, "serial:") {
		e, ok := NormalizeEmail(entry)
		if !ok {
			return fmt.Errorf("invalid e-mail address or serial %q", entry)
		}
		entry = e
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, entry)
	return err
}

// normalizeRevocation turns an e-mail address or "serial:<hex>" into the line
// stored in the file.
func normalizeRevocation(entry string) (string, error) {
	entry = strings.TrimSpace(entry)
	if rest, ok := strings.CutPrefix(entry, "serial:"); ok {
		rest = strings.ToLower(strings.TrimSpace(rest))
		if rest == "" || strings.Trim(rest, "0123456789abcdef") != "" {
			return "", fmt.Errorf("invalid serial %q", entry)
		}
		return "serial:" + rest, nil
	}
	e, ok := NormalizeEmail(entry)
	if !ok {
		return "", fmt.Errorf("invalid e-mail address or serial %q", entry)
	}
	return e, nil
}

// Add revokes an e-mail address or a serial ("serial:<hex>"). Revoking what is
// already revoked is not an error.
func (r *Revocations) Add(entry string) error {
	return r.edit(entry, true)
}

// Remove lifts a revocation.
func (r *Revocations) Remove(entry string) error {
	return r.edit(entry, false)
}

func (r *Revocations) edit(entry string, add bool) error {
	if r == nil || r.path == "" {
		return errors.New("revocation is not enabled")
	}
	entry, err := normalizeRevocation(entry)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	b, err := os.ReadFile(r.path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	var out []string
	found := false
	for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if strings.TrimSpace(line) == "" && len(b) == 0 {
			continue
		}
		if n, err := normalizeRevocation(line); err == nil && n == entry {
			found = true
			if !add {
				continue
			}
		}
		out = append(out, line)
	}
	if add && !found {
		out = append(out, entry)
	}
	if !add && !found {
		return nil
	}
	data := strings.Join(out, "\n")
	if data != "" {
		data += "\n"
	}
	if err := WriteFileAtomic(r.path, []byte(data), 0o600); err != nil {
		return err
	}
	r.mtime, r.size = time.Time{}, 0 // read it again
	return nil
}

// List returns what is revoked, sorted.
func (r *Revocations) List() (emails, serials []string) {
	if r == nil || r.path == "" {
		return nil, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reload()
	for e := range r.emails {
		emails = append(emails, e)
	}
	for s := range r.serials {
		serials = append(serials, s)
	}
	sort.Strings(emails)
	sort.Strings(serials)
	return emails, serials
}

// Enabled reports whether the list is backed by a file.
func (r *Revocations) Enabled() bool { return r != nil && r.path != "" }
