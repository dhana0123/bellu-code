package engine

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"testing"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/internal/gen"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/internal/gen/model"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

// Feature: bellu-graph-native, Property 5: Rejected batches change nothing
// Validates: Requirements 3.4, 3.5, 3.6
func TestPropRejectedBatchesChangeNothing(t *testing.T) {
	ghost := func() string {
		id, _ := ident.Hash("host", map[string]string{"hostname": "ghost"})
		return id
	}()
	rapid.Check(t, func(t *rapid.T) {
		steps := gen.Options{}.Schedule(0, 8).Draw(t, "schedule")
		clk := &stepClock{t: gen.Epoch}
		c := propEngine(t, clk.now)
		ctx := context.Background()
		for _, s := range steps {
			clk.t = s.Now
			if _, err := c.Apply(ctx, s.Batch, engineMode(s.Mode)); err != nil {
				t.Fatal(err)
			}
		}

		base := gen.Options{}.Batch(rapid.SampledFrom([]string{"c1", "c2", "c3"}).Draw(t, "collector"), gen.ValidTime().Draw(t, "obs")).Draw(t, "base")
		mode := engineMode(rapid.SampledFrom([]model.Mode{model.Full, model.Partial}).Draw(t, "mode"))
		keeper := batch.Entity{Type: "host", Identity: map[string]string{"hostname": "keeper"}}

		defects := []string{"empty-collector", "unknown-kind", "missing-identity", "empty-identity", "duplicate", "no-rel-type", "rel-attrs", "foreign-endpoint"}
		// An entity solely asserted by the collector can be retired by a Full batch.
		var sole string
		for _, col := range c.g.Collectors() {
			if col != base.Collector {
				continue
			}
			var ids []string
			for id := range c.g.Scope(col).Ents {
				if es, ok := c.g.Entity(id); ok && es.Live && len(es.Asserted) == 1 {
					ids = append(ids, id)
				}
			}
			sort.Strings(ids)
			if len(ids) > 0 {
				sole = ids[0]
				defects = append(defects, "retired-endpoint")
			}
		}
		defect := rapid.SampledFrom(defects).Draw(t, "defect")
		b := base
		b.Entities = append([]batch.Entity(nil), base.Entities...)
		b.Relations = append([]batch.Relation(nil), base.Relations...)
		cloneIdent := func(m map[string]string) map[string]string {
			o := map[string]string{}
			for k, v := range m {
				o[k] = v
			}
			return o
		}
		switch defect {
		case "empty-collector":
			b.Collector = ""
		case "unknown-kind":
			b.Entities = append(b.Entities, batch.Entity{Type: "no_such_kind", Identity: map[string]string{"name": "x"}})
		case "missing-identity":
			b.Entities = append(b.Entities, batch.Entity{Type: "host", Identity: map[string]string{"other": "x"}})
		case "empty-identity":
			b.Entities = append(b.Entities, batch.Entity{Type: "host", Identity: map[string]string{"hostname": ""}})
		case "duplicate":
			e := batch.Entity{Type: "host", Identity: map[string]string{"hostname": "dup"}}
			if len(b.Entities) > 0 {
				e = b.Entities[rapid.IntRange(0, len(b.Entities)-1).Draw(t, "dupidx")]
				e.Identity = cloneIdent(e.Identity)
				b.Entities = append(b.Entities, e)
			} else {
				b.Entities = append(b.Entities, e, e)
			}
		case "no-rel-type":
			b.Entities = append(b.Entities, keeper)
			id, _ := ident.Hash("host", keeper.Identity)
			b.Relations = append(b.Relations, batch.Relation{From: id, To: id})
		case "rel-attrs":
			b.Entities = append(b.Entities, keeper)
			id, _ := ident.Hash("host", keeper.Identity)
			b.Relations = append(b.Relations, batch.Relation{Type: "talks_to", From: id, To: id, Attributes: map[string]any{"w": 1}})
		case "foreign-endpoint":
			b.Entities = append(b.Entities, keeper)
			id, _ := ident.Hash("host", keeper.Identity)
			b.Relations = append(b.Relations, batch.Relation{Type: "talks_to", From: id, To: ghost})
		case "retired-endpoint":
			// Full mode with the sole-asserted entity omitted from the batch.
			mode = ModeFull
			b = batch.Batch{Collector: base.Collector, ObservedAt: base.ObservedAt, Entities: []batch.Entity{keeper}}
			id, _ := ident.Hash("host", keeper.Identity)
			b.Relations = []batch.Relation{{Type: "talks_to", From: id, To: sole}}
		}

		before := c.g.Clone()
		_, rawsBefore := logEvents(t, c, 1, 0)
		clk.t = clk.t.Add(1)
		_, err := c.Apply(ctx, b, mode)
		if err == nil || !errors.Is(err, errs.Validation) {
			t.Fatalf("defect %s: err = %v, want ErrValidation", defect, err)
		}
		_, rawsAfter := logEvents(t, c, 1, 0)
		if len(rawsBefore) != len(rawsAfter) {
			t.Fatalf("defect %s: log grew from %d to %d", defect, len(rawsBefore), len(rawsAfter))
		}
		for i := range rawsBefore {
			if !bytes.Equal(rawsBefore[i], rawsAfter[i]) {
				t.Fatalf("defect %s: event %d changed", defect, i+1)
			}
		}
		if !c.g.Equal(before) || c.g.LastSeq != before.LastSeq {
			t.Fatalf("defect %s: projection or scopes changed", defect)
		}
	})
}
