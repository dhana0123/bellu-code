package engine

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/internal/gen"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

// lockedBuf is a goroutine-safe log sink (background loops also log).
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// Feature: bellu-graph-native, Property 22: No attribute values in logs or metrics
// Validates: Requirements 20.5
func TestPropNoAttributeValuesInLogsOrMetrics(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		dir, err := os.MkdirTemp("", "bge-prop-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(dir) })

		logs := &lockedBuf{}
		opts := Options{
			Clock:  func() time.Time { return gen.Epoch },
			Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		}
		open := func() *Core {
			c, err := Open(dir, opts)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			return c
		}
		c := open()
		closed := false
		t.Cleanup(func() {
			if !closed {
				_ = c.Close(context.Background())
			}
		})

		var sentinels []string
		n := 0
		fresh := func() string {
			n++
			s := fmt.Sprintf("ZQ%dx%dQZ", rapid.IntRange(0, 1<<30).Draw(t, "salt"), n)
			sentinels = append(sentinels, s)
			return s
		}
		ctx := context.Background()
		var ids []string

		for i, steps := 0, rapid.IntRange(1, 5).Draw(t, "steps"); i < steps; i++ {
			// Valid batch: sentinels in identity values and attribute values.
			var b batch.Batch
			ids = ids[:0] // only this batch's entities are certainly live
			b.Collector = rapid.SampledFrom([]string{"c1", "c2"}).Draw(t, "collector")
			b.ObservedAt = gen.Epoch
			for j, ents := 0, rapid.IntRange(1, 3).Draw(t, "ents"); j < ents; j++ {
				host := map[string]string{"hostname": fresh()}
				b.Entities = append(b.Entities, batch.Entity{
					Type: "host", Identity: host,
					Attributes: map[string]any{"os": fresh(), "addresses": []string{fresh(), fresh()}},
				})
				id, _ := ident.Hash("host", host)
				ids = append(ids, id)
			}
			mode := ModePartial
			if rapid.Bool().Draw(t, "full") {
				mode = ModeFull
			}
			if _, err := c.Apply(ctx, b, mode); err != nil {
				t.Fatalf("valid batch: %v", err)
			}

			// Rejected batch: one defect, sentinels in values.
			bad := batch.Batch{Collector: "c1", ObservedAt: gen.Epoch}
			host := batch.Entity{Type: "host", Identity: map[string]string{"hostname": fresh()}, Attributes: map[string]any{"os": fresh()}}
			hid, _ := ident.Hash("host", host.Identity)
			switch rapid.IntRange(0, 5).Draw(t, "defect") {
			case 0:
				bad.Entities = []batch.Entity{{Type: "no_such_kind", Identity: map[string]string{"name": fresh()}, Attributes: map[string]any{"a": fresh()}}}
			case 1:
				bad.Entities = []batch.Entity{{Type: "host", Identity: map[string]string{"other": fresh()}, Attributes: map[string]any{"a": fresh()}}}
			case 2:
				bad.Entities = []batch.Entity{host, host}
			case 3:
				bad.Entities = []batch.Entity{host}
				bad.Relations = []batch.Relation{{Type: "talks_to", From: hid, To: hid, Attributes: map[string]any{"w": fresh()}}}
			case 4:
				ghost, _ := ident.Hash("host", map[string]string{"hostname": fresh()})
				bad.Entities = []batch.Entity{host}
				bad.Relations = []batch.Relation{{Type: "talks_to", From: hid, To: ghost}}
			case 5:
				bad.Collector = ""
				bad.Entities = []batch.Entity{host}
			}
			if _, err := c.Apply(ctx, bad, ModePartial); err == nil {
				t.Fatalf("defective batch accepted")
			}

			// Annotations, valid and failing.
			target := ids[rapid.IntRange(0, len(ids)-1).Draw(t, "target")]
			if _, err := c.Annotate(ctx, target, map[string]string{"note": fresh()}, nil, "tester"); err != nil {
				t.Fatalf("annotate: %v", err)
			}
			_, _ = c.Annotate(ctx, "no-such-entity", map[string]string{"note": fresh()}, nil, "tester")

			// Queries, including ones whose filter values are sentinels.
			_, _ = c.Entity(ctx, target, nil)
			_, _ = c.Find(ctx, FindQuery{Kind: "host", Attributes: map[string]string{"os": fresh()}}, nil)
			_, _ = c.Find(ctx, FindQuery{Attributes: map[string]string{"hostname": fresh()}}, nil)
			_, _ = c.Neighbors(ctx, target, NeighborOpts{Depth: 2}, nil)

			if rapid.Bool().Draw(t, "snapshot") {
				if err := c.writeSnapshot(); err != nil {
					t.Fatal(err)
				}
			}
			if rapid.Bool().Draw(t, "reopen") {
				if err := c.Close(ctx); err != nil {
					t.Fatal(err)
				}
				c = open()
			}
		}

		rec := httptest.NewRecorder()
		c.Metrics().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
		metrics := rec.Body.String()
		if err := c.Close(ctx); err != nil {
			t.Fatal(err)
		}
		closed = true
		out := logs.String()
		for _, s := range sentinels {
			if strings.Contains(out, s) {
				t.Fatalf("sentinel %s leaked into logs:\n%s", s, out)
			}
			if strings.Contains(metrics, s) {
				t.Fatalf("sentinel %s leaked into metrics", s)
			}
		}
	})
}
