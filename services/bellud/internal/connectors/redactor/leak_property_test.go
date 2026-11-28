package redactor

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
	"github.com/bellu/bellucode/services/bellud/internal/redact"
)

type leakCollector struct {
	name string
	b    graph.Batch
}

func (c leakCollector) Name() string            { return c.name }
func (c leakCollector) Interval() time.Duration { return time.Minute }
func (c leakCollector) Collect(context.Context) (graph.Batch, error) {
	return c.b, nil
}

type lineLog struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lineLog) Println(v ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.b.WriteString(fmt.Sprintln(v...))
}

func (l *lineLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func entityOf(t interface{ Fatal(...any) }, e graph.Engine, kind string, id map[string]string) (graph.Entity, error) {
	h, err := identity.Hash(kind, id)
	if err != nil {
		t.Fatal(err)
	}
	return e.Query().Entity(context.Background(), graph.EntityID(h), nil)
}

// Feature: cloud-connectors, Property 6: Leaking batches are discarded
//
// Validates: Requirements 7.6, 7.7
func TestPropertyLeakingBatchesDiscarded(t *testing.T) {
	ctx := context.Background()
	e, err := graph.Open(ctx, graph.Config{
		Enabled: true, Dir: filepath.Join(t.TempDir(), "g"),
		Logger: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close(ctx) })

	// Prior state ingested by a healthy collector.
	priorID := map[string]string{"hostname": "prior-host"}
	prior := graph.Batch{Collector: "prior", Entities: []batch.Entity{{
		Type: "host", Identity: priorID, Attributes: map[string]any{"os": "linux"},
	}}}
	if _, err := e.Ingest().Apply(ctx, prior); err != nil {
		t.Fatal(err)
	}
	before, err := entityOf(t, e, "host", priorID)
	if err != nil {
		t.Fatal(err)
	}

	n := 0
	rapid.Check(t, func(rt *rapid.T) {
		n++
		// Uppercase+digits only so it cannot collide with lowercase runner text.
		secret := rapid.StringMatching(`[A-Z0-9]{12,40}`).Draw(rt, "secret")
		pos := rapid.IntRange(0, 6).Draw(rt, "position")

		red := New()
		release := red.Register([]byte(secret))
		defer release()

		host := fmt.Sprintf("leak-host-%d", n)
		id := map[string]string{"hostname": host}
		attrs := map[string]any{"os": "linux"}
		switch pos {
		case 0:
			attrs["k"+secret] = "v"
		case 1:
			attrs["note"] = "pre " + secret + " post"
		case 2:
			attrs["nested"] = map[string]any{"a": map[string]any{"b": secret}}
		case 3:
			attrs["list"] = []any{"x", map[string]any{"deep": []string{"y", secret}}}
		case 4:
			attrs["nested"] = map[string]any{secret: 1}
		case 5:
			id = map[string]string{"hostname": host + secret}
		case 6:
			attrs["list"] = []string{secret}
		}
		cname := fmt.Sprintf("conn-%d", n)
		col := leakCollector{cname, graph.Batch{Entities: []batch.Entity{{
			Type: "host", Identity: id, Attributes: attrs,
		}}}}
		lg := &lineLog{}
		r := collectors.New(e, []collectors.Collector{col},
			collectors.WithGuard(red.Guard(redact.New())), collectors.WithLogger(lg))

		if err := r.RunOnce(ctx, col); err == nil {
			rt.Fatal("expected leak error")
		}

		// Nothing applied.
		if _, err := entityOf(rt, e, "host", id); err == nil {
			rt.Fatal("leaking batch entity was applied")
		}
		// Prior entities unchanged.
		after, err := entityOf(rt, e, "host", priorID)
		if err != nil || fmt.Sprint(after) != fmt.Sprint(before) {
			rt.Fatalf("prior entity changed: %v %v", after, err)
		}
		// Status is leak and contains no secret.
		st, err := entityOf(rt, e, "collector_status", map[string]string{"collector": cname})
		if err != nil {
			rt.Fatal(err)
		}
		if st.Attributes["status"] != collectors.StatusLeak {
			rt.Fatalf("status = %v", st.Attributes["status"])
		}
		if s := fmt.Sprint(st.Attributes); strings.Contains(s, secret) {
			rt.Fatal("status leaks secret")
		}
		if strings.Contains(lg.String(), secret) {
			rt.Fatal("log leaks secret")
		}
	})
}
