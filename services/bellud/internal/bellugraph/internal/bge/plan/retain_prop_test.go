package plan_test

import (
	"fmt"
	"testing"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/graph"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/plan"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

// Feature: aws-relationship-registry, Property 19: A failed type keeps its entities and a succeeded type retires
//
// Validates: Requirements 11.8, 11.9, 11.12, 11.13
func TestPropertyRetainFailedTypeKeepsEntities(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(2, 8).Draw(t, "hosts")
		tier := make([]string, n)
		var seed batch.Batch
		seed.Collector = "c"
		for i := range n {
			tier[i] = rapid.SampledFrom([]string{"x", "y"}).Draw(t, "tier")
			seed.Entities = append(seed.Entities, host(fmt.Sprintf("h%d", i), map[string]any{"tier": tier[i]}))
		}
		for i := 1; i < n; i++ {
			seed.Relations = append(seed.Relations, batch.Relation{Type: "depends_on", From: hid(fmt.Sprintf("h%d", i)), To: hid("h0")})
		}
		g := graph.New()
		applyR(t, g, seed, plan.ModeFull)

		// The next run observes a random subset and fails type "x".
		keep := make([]bool, n)
		next := batch.Batch{Collector: "c", Retain: []batch.Retain{{Kind: "host", Attrs: map[string]string{"tier": "x"}}}}
		for i := range n {
			keep[i] = rapid.Bool().Draw(t, "keep")
			if keep[i] {
				next.Entities = append(next.Entities, host(fmt.Sprintf("h%d", i), map[string]any{"tier": tier[i]}))
			}
		}
		applyR(t, g, next, plan.ModeFull)

		for i := range n {
			es, ok := g.Entity(hid(fmt.Sprintf("h%d", i)))
			live := ok && es.Live
			want := keep[i] || tier[i] == "x"
			if live != want {
				t.Fatalf("h%d tier %s observed=%v: live=%v, want %v", i, tier[i], keep[i], live, want)
			}
		}
		// A relation survives when both endpoints are live and at least one
		// endpoint belongs to the failed type.
		for i := 1; i < n; i++ {
			k := graph.RelKey{Type: "depends_on", From: hid(fmt.Sprintf("h%d", i)), To: hid("h0")}
			_, ok := g.Relation(k)
			bothLive := (keep[i] || tier[i] == "x") && (keep[0] || tier[0] == "x")
			if (tier[i] == "x" || tier[0] == "x") && bothLive && !ok {
				t.Fatalf("relation h%d->h0 was removed although an endpoint type failed", i)
			}
			if !bothLive && ok {
				if es, _ := g.Entity(k.From); es != nil && es.Live {
					if et, _ := g.Entity(k.To); et != nil && et.Live {
						continue
					}
					t.Fatalf("relation h%d->h0 kept with a retired endpoint", i)
				}
			}
		}
	})
}

// applyR plans and folds like apply, for a rapid.T.
func applyR(t *rapid.T, g *graph.Graph, b batch.Batch, mode plan.Mode) {
	r, err := plan.Plan(g, b, mode, t0)
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range r.Events {
		ev.Seq = g.LastSeq + 1
		ev.RecordedNS = t0.UnixNano()
		g.Fold(ev)
	}
}
