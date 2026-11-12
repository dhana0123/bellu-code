package tschild

import (
	"bytes"
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestParseReady(t *testing.T) {
	cases := map[string]string{
		`{"url":"http://127.0.0.1:5555"}`:           "http://127.0.0.1:5555",
		"server listening on http://127.0.0.1:1234": "http://127.0.0.1:1234",
	}
	for in, want := range cases {
		if got, ok := ParseReady(in); !ok || got != want {
			t.Fatalf("ParseReady(%q) = %q,%v", in, got, ok)
		}
	}
	for _, in := range []string{"", "hello", `{"x":1}`, "server listening on "} {
		if _, ok := ParseReady(in); ok {
			t.Fatalf("ParseReady(%q) should fail", in)
		}
	}
}

func TestBuildEnvStripsExternalPassword(t *testing.T) {
	s := New(Config{
		BaseEnv: []string{"PATH=/bin", "BELLUCODE_PASSWORD=external", "OPENCODE_PASSWORD=external", "BELLUCODE_SERVER_PASSWORD=x"},
		Env:     map[string]string{"BELLUCODE_CONFIG_CONTENT": "{}", "BELLUCODE_PASSWORD": "evil"},
	})
	env := strings.Join(s.buildEnv("internal"), "\n")
	if strings.Contains(env, "external") || strings.Contains(env, "evil") || strings.Contains(env, "OPENCODE_PASSWORD") {
		t.Fatalf("external password leaked: %s", env)
	}
	if !strings.Contains(env, "BELLUCODE_PASSWORD=internal") || !strings.Contains(env, "BELLUCODE_CONFIG_CONTENT={}") {
		t.Fatalf("missing entries: %s", env)
	}
}

func TestDegradedAfterRepeatedFailures(t *testing.T) {
	out := &syncBuf{}
	s := New(Config{
		Command:       []string{"sh", "-c", "echo boom-line >&2; exit 1"},
		BaseEnv:       os.Environ(),
		Out:           out,
		DegradedAfter: 2,
		StartTimeout:  2 * time.Second,
	})
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for s.State() != StateDegraded && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if s.State() != StateDegraded {
		t.Fatalf("state = %s", s.State())
	}
	if s.Current() != nil {
		t.Fatal("Current must be nil when not ready")
	}
	if got := s.LastStderr(); len(got) == 0 || got[len(got)-1] != "boom-line" {
		t.Fatalf("stderr = %v", got)
	}
	if !strings.Contains(out.String(), "[ts-child] boom-line") {
		t.Fatalf("relay = %q", out.String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if s.State() != StateStopped {
		t.Fatalf("state = %s", s.State())
	}
}
