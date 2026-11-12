package logx

import (
	"bytes"
	"strings"
	"testing"
)

func TestLoggerPrefix(t *testing.T) {
	var b bytes.Buffer
	New(&b).Printf("hello")
	if !strings.HasPrefix(b.String(), "[bellud] ") || !strings.HasSuffix(b.String(), "hello\n") {
		t.Fatalf("got %q", b.String())
	}
}

func TestRelayPrefixesEachLine(t *testing.T) {
	var b bytes.Buffer
	r := NewRelay(&b)
	r.Write([]byte("a\nb"))
	r.Write([]byte("c\n"))
	if got, want := b.String(), "[ts-child] a\n[ts-child] bc\n"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestRelayFlushPartialLine(t *testing.T) {
	var b bytes.Buffer
	r := NewRelay(&b)
	r.Write([]byte("tail"))
	if b.Len() != 0 {
		t.Fatalf("premature output %q", b.String())
	}
	if err := r.Flush(); err != nil {
		t.Fatal(err)
	}
	if b.String() != "[ts-child] tail\n" {
		t.Fatalf("got %q", b.String())
	}
	if err := r.Flush(); err != nil || b.String() != "[ts-child] tail\n" {
		t.Fatalf("second flush wrote: %q", b.String())
	}
}
