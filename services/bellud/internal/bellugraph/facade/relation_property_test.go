package facade

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"pgregory.net/rapid"
)

// Feature: go-server-bellu-graph, Property 14: Relation constraint
// **Validates: Requirements 11.14, 14.7**

// rcOpen opens an engine in a per-iteration temp dir (rapid.T has no TempDir).
func rcOpen(t *rapid.T) Engine {
	dir, err := os.MkdirTemp("", "rc-")
	if err != nil {
		t.Fatal(err)
	}
	e, err := Open(context.Background(), testCfg(filepath.Join(dir, "g"), &bytes.Buffer{}))
	if err != nil {
		os.RemoveAll(dir)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		e.Close(context.Background())
		os.RemoveAll(dir)
	})
	return e
}

func rcID(t *rapid.T, kind string, attrs map[string]string) string {
	id, err := Hash(kind, attrs)
	if err != nil {
		t.Fatal(err)
	}
	return string(id)
}

type rcTotals struct{ finds, changes int }

func rcSnapshot(t *rapid.T, e Engine) rcTotals {
	ctx := context.Background()
	var s rcTotals
	for _, kind := range []string{"host", "process"} {
		p, err := e.Query().Find(ctx, FindQuery{Type: kind, Paging: Paging{PageSize: 1}})
		if err != nil {
			t.Fatal(err)
		}
		s.finds += p.Total
	}
	c, err := e.Query().Changes(ctx, TimeRange{}, ChangeFilter{Paging: Paging{PageSize: 1}})
	if err != nil {
		t.Fatal(err)
	}
	s.changes = c.Total
	return s
}

func TestRelationConstraintProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		ctx := context.Background()
		e := rcOpen(t)

		// Baseline so "unchanged" is non-trivial.
		if _, err := e.Ingest().Apply(ctx, batch.Batch{
			Collector: "host", ObservedAt: t0,
			Entities: []batch.Entity{hostEnt("base", nil)},
		}); err != nil {
			t.Fatal(err)
		}
		before := rcSnapshot(t, e)

		n := rapid.IntRange(1, 5).Draw(t, "n")
		var b batch.Batch
		b.Collector, b.ObservedAt = "host", t0.Add(1)
		var hostIDs, procIDs []string
		for i := 0; i < n; i++ {
			h, p := fmt.Sprintf("h%d", i), fmt.Sprintf("%d", i+1)
			b.Entities = append(b.Entities, hostEnt(h, nil), procEnt(h, p, nil))
			hostIDs = append(hostIDs, rcID(t, "host", map[string]string{"hostname": h}))
			procIDs = append(procIDs, rcID(t, "process", map[string]string{"host": h, "pid": p, "start_time": "1"}))
		}
		bad := -1
		for i := 0; i < n; i++ {
			r := batch.Relation{Type: "runs_on", From: procIDs[i], To: hostIDs[i]}
			if rapid.Bool().Draw(t, fmt.Sprintf("attributed_%d", i)) {
				// Names outside the fixed set are rejected.
				r.Attributes = map[string]any{rapid.StringMatching(`[a-z]{1,6}`).Draw(t, "key"): rapid.Int().Draw(t, "val")}
				if bad < 0 {
					bad = i
				}
			} else if rapid.Bool().Draw(t, fmt.Sprintf("fixed_%d", i)) {
				// Fixed names with valid values are accepted.
				r.Attributes = map[string]any{"confidence": rapid.SampledFrom([]string{"extracted", "inferred"}).Draw(t, "conf"), "evidence": "e"}
			}
			b.Relations = append(b.Relations, r)
		}

		rec, err := e.Ingest().Apply(ctx, b)
		if bad >= 0 {
			if !errors.Is(err, ErrValidation) {
				t.Fatalf("relation with attribute outside the fixed set accepted or wrong error: %v", err)
			}
			if !strings.Contains(err.Error(), fmt.Sprintf("relation %d", bad)) {
				t.Fatalf("error does not name relation %d: %v", bad, err)
			}
			if after := rcSnapshot(t, e); after != before {
				t.Fatalf("graph changed by rejected batch: %+v -> %+v", before, after)
			}
			return
		}

		if err != nil {
			t.Fatalf("valid batch rejected: %v", err)
		}
		if rec.Relations != n {
			t.Fatalf("receipt relations = %d, want %d", rec.Relations, n)
		}
		// Every stored relation is reachable and carries only structure
		// (Edge has no attribute payload), and the log records exactly n.
		for i := 0; i < n; i++ {
			nb, err := e.Query().Neighbors(ctx, EntityID(hostIDs[i]), NeighborOpts{Direction: DirIn, RelationType: "runs_on"})
			if err != nil {
				t.Fatal(err)
			}
			if len(nb.Items) != 1 || nb.Items[0].From != EntityID(procIDs[i]) {
				t.Fatalf("host %d neighbors: %+v", i, nb.Items)
			}
		}
		ch, err := e.Query().Changes(ctx, TimeRange{}, ChangeFilter{Subject: SubjectRelation, Paging: Paging{PageSize: MaxPageSize}})
		if err != nil {
			t.Fatal(err)
		}
		if ch.Total != n {
			t.Fatalf("relation changes = %d, want %d", ch.Total, n)
		}
	})
}
