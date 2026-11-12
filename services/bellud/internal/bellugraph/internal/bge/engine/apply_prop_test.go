package engine

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/internal/gen"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/internal/gen/model"
)

// Feature: bellu-graph-native, Property 6: Apply matches the reference model
// Validates: Requirements 4.1, 5.7, 5.8, 5.9, 5.10, 5.11, 5.12, 19.3
func TestPropApplyMatchesModel(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		steps := gen.Options{ForeignEndpoints: true}.Schedule(1, 14).Draw(t, "schedule")
		clk := &stepClock{t: gen.Epoch}
		c := propEngine(t, clk.now)
		m := model.New()
		ctx := context.Background()
		removed := map[string]bool{}
		for i, s := range steps {
			clk.t = s.Now
			mevs, merr := m.Fold(s.Batch, s.Mode, s.Now)
			before := c.g.LastSeq
			_, err := c.Apply(ctx, s.Batch, engineMode(s.Mode))
			if (err != nil) != (merr != nil) {
				t.Fatalf("step %d: engine err %v, model err %v", i, err, merr)
			}
			if err != nil {
				if !errors.Is(err, errs.Validation) {
					t.Fatalf("step %d: err %v does not wrap ErrValidation", i, err)
				}
				compareToModel(t, c.g, m.Current())
				continue
			}
			evs, _ := logEvents(t, c, before+1, 0)
			if !reflect.DeepEqual(typesOf(evs), modelTypesOf(mevs)) {
				t.Fatalf("step %d: event types %v, model %v", i, typesOf(evs), modelTypesOf(mevs))
			}
			// Revived entities come back under the same ID with an added change.
			for _, me := range mevs {
				switch me.Type {
				case model.EntityRemoved:
					removed[me.ID] = true
				case model.EntityCreated:
					if removed[me.ID] {
						if es, ok := c.g.Entity(me.ID); !ok || !es.Live {
							t.Fatalf("step %d: revived entity %s not live", i, me.ID)
						}
						delete(removed, me.ID)
					}
				}
			}
			compareToModel(t, c.g, m.Current())
			// Each touched entity's ObservedAt is the Batch's.
			for _, ev := range evs {
				if s.Batch.ObservedAt.IsZero() {
					continue
				}
				if ev.ValidNS != s.Batch.ObservedAt.UnixNano() {
					t.Fatalf("step %d: event valid %d, batch observed %d", i, ev.ValidNS, s.Batch.ObservedAt.UnixNano())
				}
			}
		}
	})
}

// Feature: bellu-graph-native, Property 7: Re-applying a batch is a no-op
// Validates: Requirements 3.10
func TestPropReapplyIsNoop(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		steps := gen.Options{}.Schedule(1, 8).Draw(t, "schedule")
		clk := &stepClock{t: gen.Epoch}
		c := propEngine(t, clk.now)
		ctx := context.Background()
		for _, s := range steps {
			clk.t = s.Now
			if _, err := c.Apply(ctx, s.Batch, engineMode(s.Mode)); err != nil {
				t.Fatal(err)
			}
		}
		last := steps[len(steps)-1]
		// Apply the last batch once more, then a second time: the second must be a no-op.
		clk.t = clk.t.Add(1e9)
		r1, err := c.Apply(ctx, last.Batch, engineMode(last.Mode))
		if err != nil {
			t.Fatal(err)
		}
		before := c.g.Clone()
		seq := c.g.LastSeq
		clk.t = clk.t.Add(1e9)
		r2, err := c.Apply(ctx, last.Batch, engineMode(last.Mode))
		if err != nil {
			t.Fatal(err)
		}
		if c.g.LastSeq != seq {
			t.Fatalf("re-apply appended %d events", c.g.LastSeq-seq)
		}
		if !c.g.Equal(before) {
			t.Fatal("re-apply changed the projection")
		}
		if r2.ID == "" || r2.ID == r1.ID {
			t.Fatalf("no-op receipt ID %q (previous %q) is not fresh", r2.ID, r1.ID)
		}
	})
}

// Feature: bellu-graph-native, Property 12: Annotations are operator-owned
// Validates: Requirements 5.13
func TestPropAnnotationsOperatorOwned(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		pre := gen.Options{}.Schedule(1, 5).Draw(t, "pre")
		post := gen.Options{ForeignEndpoints: true}.Schedule(1, 10).Draw(t, "post")
		clk := &stepClock{t: gen.Epoch}
		c := propEngine(t, clk.now)
		ctx := context.Background()
		for _, s := range pre {
			clk.t = s.Now
			if _, err := c.Apply(ctx, s.Batch, engineMode(s.Mode)); err != nil {
				t.Fatal(err)
			}
		}
		live := append([]string(nil), c.g.LiveIDs()...)
		want := map[string]map[string]string{}
		if len(live) > 0 {
			n := rapid.IntRange(1, len(live)).Draw(t, "n")
			for i := 0; i < n; i++ {
				id := rapid.SampledFrom(live).Draw(t, "id")
				set := rapid.MapOfN(rapid.SampledFrom([]string{"owner", "team", "note", "env"}), rapid.StringN(0, 8, -1), 1, 3).Draw(t, "set")
				an, err := c.Annotate(ctx, id, set, nil, "op")
				if err != nil {
					t.Fatal(err)
				}
				want[id] = an.Values
			}
		}
		for i, s := range post {
			clk.t = s.Now
			_, _ = c.Apply(ctx, s.Batch, engineMode(s.Mode)) // foreign endpoints may be rejected
			for id, w := range want {
				es, _ := c.g.Entity(id)
				if es == nil || !es.Live {
					continue
				}
				got, ok, err := c.Annotations.Get(id)
				if err != nil || !ok || !reflect.DeepEqual(got.Values, w) {
					t.Fatalf("step %d: annotations of %s = %v (ok=%v err=%v), want %v", i, id, got.Values, ok, err, w)
				}
			}
		}
	})
}
