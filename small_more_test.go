package main

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEscapeAppleScript(t *testing.T) {
	if got := escapeAppleScript("a \"b\" \\c\r\nd"); got != `a \"b\" \\c  d` {
		t.Fatalf("got %q", got)
	}
}

func TestConnectionRecordAccessors(t *testing.T) {
	rec := connReg.newConn("tunnel", "1.2.3.4:5", "example.org", "example.org:443", "", "", "", "CONNECT", "")
	rec.setRouting("office", "proxy:8080", "corp")
	if rec.Route != "office" || rec.Proxy != "proxy:8080" || rec.Cred != "corp" {
		t.Fatalf("routing not set: %+v", rec)
	}
	if connReg.get(rec.ID) != rec {
		t.Fatal("the registry does not return the record")
	}
	if connReg.get(1<<60) != nil {
		t.Fatal("unknown id")
	}
}

type hijackRecorder struct {
	*httptest.ResponseRecorder
	hijacked bool
}

func (h *hijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked = true
	return nil, nil, nil
}

func TestCountingResponseWriterHijacks(t *testing.T) {
	h := &hijackRecorder{ResponseRecorder: httptest.NewRecorder()}
	w := &countingResponseWriter{ResponseWriter: h}
	if _, _, err := w.Hijack(); err != nil || !h.hijacked {
		t.Fatal("Hijack must reach the underlying writer")
	}
	var _ http.Flusher = w
}

func TestSingleConnListener(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	l := &singleConnListener{conn: a}
	if l.Addr() == nil {
		t.Fatal("no address")
	}
	if c, err := l.Accept(); err != nil || c != a {
		t.Fatalf("first accept: %v %v", c, err)
	}
	if _, err := l.Accept(); err == nil {
		t.Fatal("a second accept must fail")
	}
	if l.Close() != nil {
		t.Fatal("close")
	}
}

func TestPublishContextWithoutConnections(t *testing.T) {
	// no relay is connected: nothing is sent and nothing breaks
	(&relayClient{}).PublishContext()
	relayHub.PublishContext()
}
