package main

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestSpoolRequestBody(t *testing.T) {
	mk := func(body string, length int64) *http.Request {
		r, _ := http.NewRequest("POST", "http://example.org/", strings.NewReader(body))
		r.ContentLength = length
		return r
	}
	if spoolRequestBody(mk("x", 1), false) != nil {
		t.Error("spooled although not needed")
	}
	if spoolRequestBody(mk("", 0), true) != nil {
		t.Error("spooled an empty body")
	}
	if spoolRequestBody(mk("small", 5), true) != nil {
		t.Error("spooled a small body")
	}
	r := mk(strings.Repeat("a", int(bodySpoolThreshold)+10), bodySpoolThreshold+10)
	f := spoolRequestBody(r, true)
	if f == nil {
		t.Fatal("a large body was not spooled")
	}
	defer f.Close()
	got, _ := io.ReadAll(r.Body)
	if int64(len(got)) != bodySpoolThreshold+10 || r.ContentLength != bodySpoolThreshold+10 {
		t.Errorf("body = %d bytes, length %d", len(got), r.ContentLength)
	}
	// unknown size is spooled too, and the length becomes known
	r = mk(strings.Repeat("b", 100), -1)
	if f2 := spoolRequestBody(r, true); f2 == nil || r.ContentLength != 100 {
		t.Errorf("unknown length: %v %d", f2, r.ContentLength)
	} else {
		f2.Close()
	}
}
