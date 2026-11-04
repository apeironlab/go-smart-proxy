package relay

import (
	"crypto/subtle"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Observability: every event the relay audits is also counted
// (gsp_relay_events_total{kind=...}) and offered to an event logger, a few
// counters are kept for what is not an event, and a handler serves
// /healthz, /readyz and /metrics (Prometheus text format, no dependency).

// ---- events -----------------------------------------------------------

var eventLogger atomic.Pointer[func(kind, actor, subject, detail string)]

// SetEventLogger registers a function that receives every audited event, for
// structured logging. nil removes it.
func SetEventLogger(fn func(kind, actor, subject, detail string)) {
	if fn == nil {
		eventLogger.Store(nil)
		return
	}
	eventLogger.Store(&fn)
}

// emitEvent counts an event and passes it to the event logger.
func emitEvent(kind, actor, subject, detail string) {
	CounterInc("gsp_relay_events_total", "kind", kind)
	if fn := eventLogger.Load(); fn != nil {
		(*fn)(kind, actor, subject, detail)
	}
}

// ---- counters ---------------------------------------------------------

type counter struct {
	help   string
	labels []string // label names, from the first use
	mu     sync.Mutex
	vals   map[string]*atomic.Uint64
}

var (
	countersMu sync.Mutex
	counters   = map[string]*counter{}
)

var counterHelp = map[string]string{
	"gsp_relay_events_total":       "Audited events, by kind.",
	"gsp_relay_connections_total":  "Connections to the relay, by outcome.",
	"gsp_relay_dials_total":        "Streams opened through the relay, by kind and outcome.",
	"gsp_relay_mail_total":         "E-mails sent by the relay, by outcome.",
	"gsp_relay_enrollments_total":  "Certificates issued, by method.",
	"gsp_relay_policy_fetch_total": "Block list downloads, by outcome.",
}

// CounterInc adds one to a counter with labels given as name, value pairs.
func CounterInc(name string, labelPairs ...string) {
	countersMu.Lock()
	c := counters[name]
	if c == nil {
		c = &counter{help: counterHelp[name], vals: map[string]*atomic.Uint64{}}
		for i := 0; i+1 < len(labelPairs); i += 2 {
			c.labels = append(c.labels, labelPairs[i])
		}
		counters[name] = c
	}
	countersMu.Unlock()
	var vals []string
	for i := 1; i < len(labelPairs); i += 2 {
		vals = append(vals, labelPairs[i])
	}
	key := strings.Join(vals, "\x00")
	c.mu.Lock()
	v := c.vals[key]
	if v == nil {
		v = &atomic.Uint64{}
		c.vals[key] = v
	}
	c.mu.Unlock()
	v.Add(1)
}

// Sample is one value of a gauge.
type Sample struct {
	Labels [][2]string
	Value  float64
}

type gauge struct {
	name, help string
	fn         func() []Sample
}

func escapeLabel(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`).Replace(s)
}

func writeSample(w io.Writer, name string, labels [][2]string, v float64) {
	if len(labels) == 0 {
		fmt.Fprintf(w, "%s %v\n", name, v)
		return
	}
	var parts []string
	for _, l := range labels {
		parts = append(parts, fmt.Sprintf(`%s="%s"`, l[0], escapeLabel(l[1])))
	}
	fmt.Fprintf(w, "%s{%s} %v\n", name, strings.Join(parts, ","), v)
}

// writeCounters writes every counter in the Prometheus text format.
func writeCounters(w io.Writer) {
	countersMu.Lock()
	names := make([]string, 0, len(counters))
	for n := range counters {
		names = append(names, n)
	}
	countersMu.Unlock()
	sort.Strings(names)
	for _, n := range names {
		countersMu.Lock()
		c := counters[n]
		countersMu.Unlock()
		if c.help != "" {
			fmt.Fprintf(w, "# HELP %s %s\n", n, c.help)
		}
		fmt.Fprintf(w, "# TYPE %s counter\n", n)
		c.mu.Lock()
		keys := make([]string, 0, len(c.vals))
		for k := range c.vals {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			var labels [][2]string
			if len(c.labels) > 0 {
				vals := strings.Split(k, "\x00")
				for i, ln := range c.labels {
					if i < len(vals) {
						labels = append(labels, [2]string{ln, vals[i]})
					}
				}
			}
			writeSample(w, n, labels, float64(c.vals[k].Load()))
		}
		c.mu.Unlock()
	}
}

// ---- the handler ------------------------------------------------------

// Observer says what to report and watch.
type Observer struct {
	Server *Server
	Enroll *EnrollServer
	Admin  *Admin
	Policy *Policy
	// Shared, when the relay uses a shared database, is checked for readiness.
	Shared *Shared
	// Token, when set, is required (as a bearer token) to read /metrics. The
	// health endpoints never need it and say nothing about users.
	Token   string
	Started time.Time
	// Version is shown in gsp_relay_build_info.
	Version string
}

// Ready reports why the relay is not ready to serve, or nil.
func (o *Observer) Ready() error {
	if o.Server != nil && !o.Server.Serving() {
		return fmt.Errorf("the mTLS listener is not running")
	}
	if o.Shared != nil {
		if err := o.Shared.Ping(); err != nil {
			return fmt.Errorf("the shared database does not answer: %w", err)
		}
	}
	if o.Admin != nil {
		if err := o.Admin.Ping(); err != nil {
			return fmt.Errorf("the management database does not answer: %w", err)
		}
	}
	return nil
}

func (o *Observer) gauges() []gauge {
	var gs []gauge
	one := func(v float64) []Sample { return []Sample{{Value: v}} }
	started := o.Started
	if started.IsZero() {
		started = time.Now()
	}
	gs = append(gs,
		gauge{"gsp_relay_build_info", "Version of the relay.", func() []Sample {
			return []Sample{{Labels: [][2]string{{"version", orDash(o.Version)}, {"go", runtime.Version()}}, Value: 1}}
		}},
		gauge{"gsp_relay_uptime_seconds", "Seconds since the relay started.", func() []Sample { return one(time.Since(started).Seconds()) }},
		gauge{"go_goroutines", "Number of goroutines.", func() []Sample { return one(float64(runtime.NumGoroutine())) }},
		gauge{"go_memstats_alloc_bytes", "Bytes of allocated heap objects.", func() []Sample {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			return one(float64(m.Alloc))
		}},
	)
	if o.Server != nil {
		srv := o.Server
		gs = append(gs,
			gauge{"gsp_relay_devices_online", "Devices connected now.", func() []Sample { return one(float64(len(srv.Online()))) }},
			gauge{"gsp_relay_users_online", "People with at least one device connected.", func() []Sample {
				seen := map[string]bool{}
				for _, d := range srv.Online() {
					seen[d.Email] = true
				}
				return one(float64(len(seen)))
			}},
			gauge{"gsp_relay_gateways_online", "Application gateways connected now.", func() []Sample { return one(float64(len(srv.OnlineGateways()))) }},
			gauge{"gsp_relay_ready", "1 when the relay is ready to serve.", func() []Sample {
				if o.Ready() == nil {
					return one(1)
				}
				return one(0)
			}},
		)
		if srv.Catalog != nil {
			gs = append(gs, gauge{"gsp_relay_applications", "Applications in the catalog.", func() []Sample { return one(float64(len(srv.Catalog.Apps()))) }})
		}
	}
	if o.Enroll != nil {
		es := o.Enroll
		gs = append(gs,
			gauge{"gsp_relay_enrollments_pending", "Certificate requests waiting for the user.", func() []Sample { return one(float64(es.pendingCount())) }},
			gauge{"gsp_relay_certificates_active", "Certificates issued, not revoked and not expired.", func() []Sample { return one(float64(es.activeCertCount())) }},
		)
	}
	if o.Policy != nil {
		p := o.Policy
		gs = append(gs, gauge{"gsp_relay_policy_list_entries", "Entries of each downloaded block list.", func() []Sample {
			lists, _, _ := p.Status()
			var out []Sample
			for _, l := range lists {
				out = append(out, Sample{Labels: [][2]string{{"list", l.ID}}, Value: float64(l.Entries)})
			}
			return out
		}})
	}
	return gs
}

// Handler serves /healthz, /readyz and /metrics.
func (o *Observer) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "ok\n")
	})
	m.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if err := o.Ready(); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			io.WriteString(w, "not ready: "+err.Error()+"\n")
			return
		}
		io.WriteString(w, "ok\n")
	})
	m.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		if o.Token != "" {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(got), []byte(o.Token)) != 1 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		for _, g := range o.gauges() {
			fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n", g.name, g.help, g.name)
			for _, s := range g.fn() {
				writeSample(w, g.name, s.Labels, s.Value)
			}
		}
		writeCounters(w)
	})
	return m
}
