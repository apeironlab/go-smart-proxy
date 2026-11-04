package main

import (
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"runtime/debug"
	"strings"

	"github.com/apeironlab/go-smart-proxy/relay"
)

// jsonLog turns the lines the relay writes with the standard logger into JSON
// records, with a level guessed from the text, and the audited events into
// records with their own fields.
type jsonLog struct{ l *slog.Logger }

func (j jsonLog) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\r\n")
	lower := strings.ToLower(msg)
	switch {
	case strings.HasPrefix(msg, "WARNING"):
		j.l.Warn(strings.TrimSpace(strings.TrimPrefix(msg, "WARNING:")))
	case strings.Contains(lower, "failed") || strings.Contains(lower, "error") || strings.Contains(lower, "refused"):
		j.l.Warn(msg)
	default:
		j.l.Info(msg)
	}
	return len(p), nil
}

func setupLogging(format string) error {
	switch format {
	case "", "text":
		return nil
	case "json":
		l := slog.New(slog.NewJSONHandler(os.Stderr, nil))
		log.SetFlags(0)
		log.SetOutput(jsonLog{l})
		relay.SetEventLogger(func(kind, actor, subject, detail string) {
			l.Info("event", slog.String("kind", kind), slog.String("actor", actor), slog.String("subject", subject), slog.String("detail", detail))
		})
		return nil
	}
	return fmt.Errorf("-log-format: text or json, not %q", format)
}

func buildVersion() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	rev, dirty := "", ""
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "+dirty"
			}
		}
	}
	if rev == "" {
		return "dev"
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	return rev + dirty
}

func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
