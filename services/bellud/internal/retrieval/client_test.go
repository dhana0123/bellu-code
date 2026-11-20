package retrieval

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestDownServiceIsUnavailableAndExactLookupStillWorks(t *testing.T) {
	c := NewUnix(filepath.Join(t.TempDir(), "none.sock"), "tok")
	g := &Gateway{Client: c, Exact: func(_ context.Context, id string) (any, error) { return "found:" + id, nil }}
	err := g.Stage(context.Background(), StagePlan, map[string]any{}, nil)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
	rec := httptest.NewRecorder()
	if !HandleError(rec, err) || rec.Code != 503 || rec.Body.String() != "{\"error\":\"retrieval_unavailable\"}\n" {
		t.Fatalf("bad 503: %d %q", rec.Code, rec.Body.String())
	}
	if v, err := g.Lookup(context.Background(), "CVE-2024-1"); err != nil || v != "found:CVE-2024-1" {
		t.Fatalf("lookup: %v %v", v, err)
	}
	if err := (&Gateway{}).Stage(context.Background(), StagePlan, nil, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil client: %v", err)
	}
}

func TestLoopbackOnlyAndTokenSent(t *testing.T) {
	if _, err := NewLoopback("10.0.0.5:80", "t"); err == nil {
		t.Fatal("non-loopback accepted")
	}
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get(TokenHeader)
		if r.URL.Path != "/v1/rank" {
			t.Errorf("path %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	c, err := NewLoopback(srv.Listener.Addr().String(), "secret")
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]bool
	if err := c.Rank(context.Background(), map[string]any{}, &out); err != nil || !out["ok"] || got != "secret" {
		t.Fatalf("err=%v out=%v token=%q", err, out, got)
	}
}

func TestStatusMapping(t *testing.T) {
	for code, want := range map[int]error{401: ErrAuth, 503: ErrUnavailable, 500: ErrUnavailable} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) }))
		c, _ := NewLoopback(srv.Listener.Addr().String(), "t")
		if err := c.Plan(context.Background(), nil, nil); !errors.Is(err, want) {
			t.Errorf("%d: got %v", code, err)
		}
		srv.Close()
	}
}

// Runs the real Python service over a Unix socket.
func TestPythonServiceEndToEnd(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not found")
	}
	dir, _ := filepath.Abs("../../../retrieval")
	if _, err := os.Stat(filepath.Join(dir, "retrieval_service")); err != nil {
		t.Skip("retrieval service not present")
	}
	sock := filepath.Join(t.TempDir(), "r.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p, err := Start(ctx, ProcessConfig{ServiceDir: dir, SocketPath: sock})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	// Stage logic is not registered yet: authenticated calls reach the service (501, not unavailable).
	if err := p.Client.Plan(ctx, map[string]any{}, nil); err == nil || errors.Is(err, ErrUnavailable) || errors.Is(err, ErrAuth) {
		t.Fatalf("authenticated call: %v", err)
	}
	bad := NewUnix(sock, "wrong")
	if err := bad.Plan(ctx, map[string]any{}, nil); !errors.Is(err, ErrAuth) {
		t.Fatalf("wrong token: %v", err)
	}
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}
