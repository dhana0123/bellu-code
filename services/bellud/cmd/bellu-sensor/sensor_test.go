//go:build linux

package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestCheckKernel(t *testing.T) {
	cases := []struct {
		rel    string
		btf    bool
		status string
		reason string
	}{
		{"5.4.0-91-generic", true, StatusUnsupported, ReasonKernelTooOld},
		{"4.19.0", true, StatusUnsupported, ReasonKernelTooOld},
		{"garbage", true, StatusUnsupported, ReasonKernelTooOld},
		{"5.8.0", false, StatusUnsupported, ReasonBTFMissing},
		{"5.8.0", true, StatusOK, ""},
		{"5.15.0-91-generic", true, StatusOK, ""},
		{"6.1.0", true, StatusOK, ""},
		{"5.10-rc1", true, StatusOK, ""},
	}
	for _, c := range cases {
		got := CheckKernel(c.rel, c.btf)
		if got.Status != c.status || got.Reason != c.reason {
			t.Errorf("%s btf=%v: got %+v", c.rel, c.btf, got)
		}
	}
}

func TestNormalizeRedactsAndTruncates(t *testing.T) {
	e := Normalize(Event{Type: TypeProcessExec, ProcessPath: "/bin/curl", Args: "curl password=hunter2hunter2 " + strings.Repeat("a", 5000)})
	if strings.Contains(e.Args, "hunter2") {
		t.Fatalf("secret not redacted: %q", e.Args[:80])
	}
	if len([]rune(e.Args)) > maxArgsLen {
		t.Fatalf("args too long: %d", len(e.Args))
	}
}

func TestNormalizeUnavailable(t *testing.T) {
	e := Normalize(Event{Type: TypeNetConnect, ProcessPath: "/bin/x", User: "root"})
	want := map[string]bool{"container_id": true, "pod": true, "namespace": true, "node": true, "args": true}
	if len(e.Unavailable) != len(want) {
		t.Fatalf("unavailable = %v", e.Unavailable)
	}
	for _, f := range e.Unavailable {
		if !want[f] {
			t.Fatalf("unexpected %s", f)
		}
	}
}

func TestBPFSourceMissingObject(t *testing.T) {
	if err := (&BPFSource{}).Start(context.Background(), func(Event) {}); !errors.Is(err, ErrObjectMissing) {
		t.Fatalf("got %v, want ErrObjectMissing", err)
	}
}

func TestToEventConnect(t *testing.T) {
	var r rawEvent
	r.Kind = kindConnect
	r.Addr4 = [4]byte{10, 0, 0, 1}
	r.Port = 443
	copy(r.Comm[:], "curl")
	e, ok := (&BPFSource{Node: "n1"}).toEvent(r)
	if !ok || e.Type != TypeNetConnect || e.Args != "10.0.0.1:443" || e.ProcessPath != "curl" || e.Node != "n1" {
		t.Fatalf("unexpected event %+v", e)
	}
	if _, ok := (&BPFSource{}).toEvent(rawEvent{Kind: 99}); ok {
		t.Fatal("unknown kind accepted")
	}
}
