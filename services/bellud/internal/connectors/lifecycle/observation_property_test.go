package lifecycle

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

// obsCollector is a scripted connector collector: each run either returns an
// observation, fails, or blocks until its context is cancelled.
type obsCollector struct {
	name string
	mode string // "ok" | "fail" | "hang"
	ents []batch.Entity
}

func (c *obsCollector) Name() string            { return c.name }
func (c *obsCollector) Interval() time.Duration { return time.Minute }
func (c *obsCollector) Collect(ctx context.Context) (graph.Batch, error) {
	switch c.mode {
	case "fail":
		return graph.Batch{}, errors.New("upstream failure")
	case "hang":
		<-ctx.Done()
		return graph.Batch{}, ctx.Err()
	}
	return graph.Batch{Collector: c.name, Entities: c.ents}, nil
}

// liveFor returns the live entity values (id -> "v" attribute) for a connection.
func liveFor(t interface{ Fatal(...any) }, e graph.Engine, conn string) map[string]string {
	got := map[string]string{}
	cursor := ""
	for {
		pg, err := e.Query().Find(context.Background(), graph.FindQuery{
			Type:       "host",
			Attributes: map[string]string{"conn": conn},
			Paging:     graph.Paging{PageSize: graph.MaxPageSize, Cursor: cursor},
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range pg.Items {
			got[fmt.Sprint(it.Attributes["rid"])] = fmt.Sprint(it.Attributes["v"])
		}
		if pg.NextCursor == "" {
			return got
		}
		cursor = pg.NextCursor
	}
}

func obsEntities(conn string, m map[string]string) []batch.Entity {
	out := make([]batch.Entity, 0, len(m))
	for id, v := range m {
		out = append(out, batch.Entity{
			Type:       "host",
			Identity:   map[string]string{"hostname": conn + "/" + id},
			Attributes: map[string]any{"conn": conn, "rid": id, "v": v},
		})
	}
	return out
}

// Feature: cloud-connectors, Property 29: Full-observation semantics
//
// Validates: Requirements 2.7, 7.3, 7.5
func TestPropertyFullObservationSemantics(t *testing.T) {
	ctx := context.Background()
	e, err := graph.Open(ctx, graph.Config{
		Enabled: true, Dir: filepath.Join(t.TempDir(), "g"),
		Logger: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close(ctx) })

	n := 0
	rapid.Check(t, func(rt *rapid.T) {
		n++
		conn := fmt.Sprintf("c%d", n)
		other := fmt.Sprintf("o%d", n)
		col := &obsCollector{name: "connector:test:" + conn}
		oth := &obsCollector{name: "connector:test:" + other}
		r := collectors.New(e, []collectors.Collector{col, oth},
			collectors.WithTickTimeout(15*time.Millisecond))

		// A sibling connection with a fixed observation must never be affected.
		oth.mode, oth.ents = "ok", obsEntities(other, map[string]string{"x": "1", "y": "2"})
		if err := r.RunOnce(ctx, oth); err != nil {
			rt.Fatal(err)
		}
		otherWant := map[string]string{"x": "1", "y": "2"}

		want := map[string]string{}
		steps := rapid.IntRange(2, 8).Draw(rt, "steps")
		for i := 0; i < steps; i++ {
			kind := rapid.SampledFrom([]string{"obs", "obs", "fail", "timeout", "empty"}).Draw(rt, "kind")
			switch kind {
			case "obs":
				ids := rapid.SliceOfNDistinct(rapid.SampledFrom([]string{"a", "b", "c", "d", "e", "f"}),
					0, 6, func(s string) string { return s }).Draw(rt, "ids")
				obs := map[string]string{}
				for _, id := range ids {
					obs[id] = rapid.StringMatching(`[a-z]{1,6}`).Draw(rt, "val")
				}
				col.mode, col.ents = "ok", obsEntities(conn, obs)
				if err := r.RunOnce(ctx, col); err != nil {
					rt.Fatalf("run: %v", err)
				}
				want = obs
			case "empty":
				col.mode, col.ents = "ok", nil
				if err := r.RunOnce(ctx, col); err != nil {
					rt.Fatalf("empty run: %v", err)
				}
				want = map[string]string{}
			case "fail":
				col.mode = "fail"
				if err := r.RunOnce(ctx, col); err == nil {
					rt.Fatal("expected failure")
				}
			case "timeout":
				col.mode = "hang"
				if err := r.RunOnce(ctx, col); err == nil {
					rt.Fatal("expected timeout")
				}
			}
			if got := liveFor(rt, e, conn); !mapsEqual(got, want) {
				rt.Fatalf("after %s: live=%v want=%v", kind, got, want)
			}
			if got := liveFor(rt, e, other); !mapsEqual(got, otherWant) {
				rt.Fatalf("sibling connection changed after %s: %v", kind, got)
			}
		}
	})
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}
