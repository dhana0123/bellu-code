package collectors

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
	"github.com/bellu/bellucode/services/bellud/internal/redact"
)

type fake struct {
	name string
	fn   func(ctx context.Context) (graph.Batch, error)
}

func (f fake) Name() string            { return f.name }
func (f fake) Interval() time.Duration { return 10 * time.Millisecond }
func (f fake) Collect(ctx context.Context) (graph.Batch, error) {
	return f.fn(ctx)
}

type buf struct {
	mu sync.Mutex
	b  []string
}

func (l *buf) Println(v ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.b = append(l.b, strings.TrimSpace(strings.Join(strSlice(v), " ")))
}
func (l *buf) lines() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.b...)
}
func strSlice(v []any) []string {
	out := make([]string, len(v))
	for i, x := range v {
		out[i], _ = x.(string)
	}
	return out
}

func openEngine(t *testing.T) graph.Engine {
	t.Helper()
	e, err := graph.Open(context.Background(), graph.Config{
		Enabled: true, Dir: filepath.Join(t.TempDir(), "g"),
		Logger: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close(context.Background()) })
	return e
}

func hostBatch(name string) graph.Batch {
	return graph.Batch{Entities: []batch.Entity{{
		Type: "host", Identity: map[string]string{"hostname": name}, Attributes: map[string]any{"os": "linux"},
	}}}
}

func status(t *testing.T, e graph.Engine, name string) map[string]any {
	t.Helper()
	id, err := identity.Hash("collector_status", map[string]string{"collector": name})
	if err != nil {
		t.Fatal(err)
	}
	en, err := e.Query().Entity(context.Background(), graph.EntityID(id), nil)
	if err != nil {
		t.Fatalf("status %s: %v", name, err)
	}
	return en.Attributes
}

func hostFound(e graph.Engine, name string) bool {
	id, _ := identity.Hash("host", map[string]string{"hostname": name})
	_, err := e.Query().Entity(context.Background(), graph.EntityID(id), nil)
	return err == nil
}

func TestOKErrorTimeoutLeakAndIsolation(t *testing.T) {
	e := openEngine(t)
	lg := &buf{}
	leak := hostBatch("leaky")
	leak.Entities[0].Attributes["note"] = "AKIAABCDEFGHIJKLMNOP" // scrubbed to a marker, not a leak
	cols := []Collector{
		fake{"good", func(context.Context) (graph.Batch, error) { return hostBatch("good"), nil }},
		fake{"bad", func(context.Context) (graph.Batch, error) {
			return hostBatch("partial"), errors.New("docker socket missing")
		}},
		fake{"slow", func(ctx context.Context) (graph.Batch, error) { <-ctx.Done(); return graph.Batch{}, ctx.Err() }},
	}
	r := New(e, cols, WithLogger(lg), WithTickTimeout(50*time.Millisecond))
	ctx := context.Background()
	if err := r.RunOnce(ctx, cols[0]); err != nil {
		t.Fatal(err)
	}
	if err := r.RunOnce(ctx, cols[1]); err == nil {
		t.Fatal("want error")
	}
	r.RunOnce(ctx, cols[2])
	if !hostFound(e, "good") || hostFound(e, "partial") {
		t.Fatal("good must apply; failing collector's partial batch must be discarded")
	}
	if a := status(t, e, "good"); a["status"] != StatusOK {
		t.Fatalf("%v", a)
	}
	if a := status(t, e, "bad"); a["status"] != StatusError || !strings.Contains(a["last_error"].(string), "docker") {
		t.Fatalf("%v", a)
	}
	if a := status(t, e, "slow"); a["status"] != StatusTimeout {
		t.Fatalf("%v", a)
	}
}

type leakyGuard struct{ redact.Guard }

func (leakyGuard) Leaks(b batch.Batch) bool { return b.Collector != StatusCollector }
func (g leakyGuard) FirstLeak(b batch.Batch) (string, bool) {
	return "rule-x", g.Leaks(b)
}

func TestLeakDiscardsAndAudits(t *testing.T) {
	e := openEngine(t)
	lg := &buf{}
	c := fake{"leaky", func(context.Context) (graph.Batch, error) { return hostBatch("leaky"), nil }}
	r := New(e, []Collector{c}, WithLogger(lg), WithGuard(leakyGuard{redact.New()}))
	if err := r.RunOnce(context.Background(), c); !errors.Is(err, redact.ErrSecretLeak) {
		t.Fatalf("got %v", err)
	}
	if hostFound(e, "leaky") {
		t.Fatal("leaking batch must not be applied")
	}
	if a := status(t, e, "leaky"); a["status"] != StatusLeak {
		t.Fatalf("%v", a)
	}
	var audit bool
	for _, l := range lg.lines() {
		audit = audit || (strings.Contains(l, "collector=leaky") && strings.Contains(l, "rule=rule-x"))
	}
	if !audit {
		t.Fatalf("no audit line: %v", lg.lines())
	}
}

func TestLogBackoff(t *testing.T) {
	e := openEngine(t)
	lg := &buf{}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := fake{"bad", func(context.Context) (graph.Batch, error) { return graph.Batch{}, errors.New("boom") }}
	r := New(e, []Collector{c}, WithLogger(lg), WithClock(func() time.Time { return now }))
	for i := 0; i < 5; i++ {
		r.RunOnce(context.Background(), c)
	}
	if n := len(lg.lines()); n != 1 {
		t.Fatalf("want 1 log in window, got %d", n)
	}
	now = now.Add(2 * time.Minute)
	r.RunOnce(context.Background(), c)
	if n := len(lg.lines()); n != 2 {
		t.Fatalf("want log after window, got %d", n)
	}
}

func TestStartStop(t *testing.T) {
	e := openEngine(t)
	c := fake{"good", func(context.Context) (graph.Batch, error) { return hostBatch("loop"), nil }}
	r := New(e, []Collector{c})
	r.Start(context.Background())
	deadline := time.Now().Add(3 * time.Second)
	for !hostFound(e, "loop") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	r.Stop()
	if !hostFound(e, "loop") {
		t.Fatal("loop never ingested")
	}
	New(e, nil).Start(context.Background()) // no collectors is a no-op
}
