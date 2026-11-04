package relay

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// AdminDevice is one device of a user, as the interface shows it.
type AdminDevice struct {
	Device  string       `json:"device"`
	Online  bool         `json:"online"`
	Addr    string       `json:"addr,omitempty"`
	Since   *time.Time   `json:"since,omitempty"`
	Network *NetContext  `json:"context,omitempty"`
	Certs   []CertRecord `json:"certs"`
}

func (a *Admin) handleDevices(w http.ResponseWriter, r *http.Request, _ *adminSession) {
	email, ok := NormalizeEmail(r.URL.Query().Get("email"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid e-mail address")
		return
	}
	certs, err := a.db.certs(email)
	if err != nil {
		a.fail(w, err)
		return
	}
	_, serials := a.cfg.Revoked.List()
	revoked := map[string]bool{}
	for _, s := range serials {
		revoked[s] = true
	}
	byDev := map[string]*AdminDevice{}
	get := func(d string) *AdminDevice {
		if d == "" {
			d = "-"
		}
		x := byDev[d]
		if x == nil {
			x = &AdminDevice{Device: d, Certs: []CertRecord{}}
			byDev[d] = x
		}
		return x
	}
	for _, c := range certs {
		if revoked[c.Serial] {
			c.Revoked = true
		}
		d := get(c.Device)
		d.Certs = append(d.Certs, c)
	}
	if srv := a.srv(); srv != nil {
		for _, d := range srv.Online() {
			if d.Email != email {
				continue
			}
			x := get(d.Device)
			since := d.Since
			x.Online, x.Addr, x.Since, x.Network = true, d.Addr, &since, d.Context
		}
		// devices that connected before the ledger existed
		for _, d := range srv.Store.Devices(email) {
			get(d)
		}
	}
	out := make([]*AdminDevice, 0, len(byDev))
	for _, d := range byDev {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Online != out[j].Online {
			return out[i].Online
		}
		return out[i].Device < out[j].Device
	})
	writeJSON(w, http.StatusOK, out)
}

type revokeDeviceReq struct {
	Email  string `json:"email"`
	Device string `json:"device"`
	// Forget also removes the device from the user's list of devices.
	Forget bool `json:"forget"`
}

// handleRevokeDevice revokes every certificate issued for one device of a
// user and disconnects it; the user's other devices are not touched.
func (a *Admin) handleRevokeDevice(w http.ResponseWriter, r *http.Request, sess *adminSession) {
	var req revokeDeviceReq
	if !readJSON(w, r, &req) {
		return
	}
	email, ok := NormalizeEmail(req.Email)
	device, dok := NormalizeDevice(req.Device)
	if !ok || !dok || device == "" {
		writeError(w, http.StatusBadRequest, "give an e-mail address and a device")
		return
	}
	certs, err := a.db.certs(email)
	if err != nil {
		a.fail(w, err)
		return
	}
	n, kicked := 0, 0
	for _, c := range certs {
		if c.Device != device || c.Revoked {
			continue
		}
		if err := a.cfg.Revoked.Add("serial:" + c.Serial); err != nil {
			a.fail(w, err)
			return
		}
		a.db.markCert(c.Serial, true, sess.email)
		if srv := a.srv(); srv != nil {
			kicked += srv.Kick(email, c.Serial)
		}
		n++
	}
	if n == 0 {
		writeError(w, http.StatusNotFound, "no active certificate for that device")
		return
	}
	// A device with an old, unbound certificate (no device in it) connects under
	// whatever name it claims: cut that session too.
	if srv := a.srv(); srv != nil {
		for _, d := range srv.Online() {
			if d.Email == email && d.Device == device {
				kicked += srv.Kick(email, d.Serial)
			}
		}
		if req.Forget {
			srv.Store.ForgetDevice(email, device)
		}
	}
	a.Record("admin.revoke.device", sess.email, email+"/"+device, "certificates: "+strconv.Itoa(n)+", disconnected: "+strconv.Itoa(kicked))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "revoked": n, "disconnected": kicked})
}

const maxInvites = 50

// handleInvite e-mails an invitation to each address: how to get the proxy and
// where to enroll. Nothing is created: the person enrolls as anybody else
// would, with the methods the relay offers.
func (a *Admin) handleInvite(w http.ResponseWriter, r *http.Request, sess *adminSession) {
	var req struct {
		Emails []string `json:"emails"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if len(req.Emails) == 0 || len(req.Emails) > maxInvites {
		writeError(w, http.StatusBadRequest, "give between 1 and "+strconv.Itoa(maxInvites)+" addresses")
		return
	}
	if !a.enroll.canMail() {
		writeError(w, http.StatusConflict, "the relay has no SMTP server configured (see Access and enrollment)")
		return
	}
	if a.enroll.cfg.PublicURL == "" {
		writeError(w, http.StatusConflict, "the relay does not know its public enrollment address (-public-url)")
		return
	}
	type result struct {
		Email string `json:"email"`
		OK    bool   `json:"ok"`
		Error string `json:"error,omitempty"`
	}
	allowed := a.enroll.Rules().AllowedDomains
	seen := map[string]bool{}
	var out []result
	sent := 0
	for _, raw := range req.Emails {
		email, ok := NormalizeEmail(raw)
		switch {
		case !ok:
			out = append(out, result{Email: strings.TrimSpace(raw), Error: "not a valid address"})
			continue
		case seen[email]:
			continue
		case !allowedDomain(email, allowed):
			out = append(out, result{Email: email, Error: "its domain is not allowed to enroll"})
			continue
		}
		seen[email] = true
		if !a.enroll.allow("invite:"+email, 3) {
			out = append(out, result{Email: email, Error: "invited too often, try later"})
			continue
		}
		if err := SendInvite(a.enroll.mailConfig(), email); err != nil {
			a.log.Printf("admin: invitation to %s: %v", email, err)
			out = append(out, result{Email: email, Error: "the e-mail could not be sent"})
			continue
		}
		out = append(out, result{Email: email, OK: true})
		sent++
	}
	a.Record("admin.invite", sess.email, "", strconv.Itoa(sent)+" sent")
	writeJSON(w, http.StatusOK, map[string]any{"results": out, "sent": sent})
}
