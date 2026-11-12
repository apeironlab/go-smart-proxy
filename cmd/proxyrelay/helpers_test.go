package main

import (
	"flag"
	"io"
	"log/slog"

	"github.com/apeironlab/go-smart-proxy/relay"
)

func newTestLogger(w io.Writer) jsonLog {
	return jsonLog{slog.New(slog.NewJSONHandler(w, nil))}
}

func flagSetForTest() *flag.FlagSet { return flag.NewFlagSet("test", flag.ContinueOnError) }

func configForTest() *relay.EnrollConfig { return &relay.EnrollConfig{} }
