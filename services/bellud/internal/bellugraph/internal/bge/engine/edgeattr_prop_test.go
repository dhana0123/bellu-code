package engine

import (
	"context"
	"reflect"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/codec"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/graph"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/internal/gen"
)

// raBatch observes the two endpoint hosts and one relation carrying attrs.
func raBatch(rel string, from, to gen.Ref, attrs map[string]any, at time.Time) batch.Batch {
	b := batch.Batch{
		Collector:  "c1",
		ObservedAt: at,
		Entities: []batch.Entity{
			{Type: from.Kind, Identity: from.Identity()},
			{Type: to.Kind, Identity: to.Identity()},
		},
		Relations: []batch.Relation{{Type: rel, From: from.ID(), To: to.ID()}},
	}
	if len(attrs) > 0 {
		b.Relations[0].Attributes = attrs
	}
	return b
}

// raWant is the stored form of an attribute map.
func raWant(attrs map[string]any) codec.EdgeAttrs {
	var a codec.EdgeAttrs
	if v, ok := attrs["evidence"].(string); ok {
		a.Evidence, a.Has = v, a.Has|1
	}
	if v, ok := attrs["confidence"].(string); ok {
		a.Confidence, a.Has = v, a.Has|2
	}
	if v, ok := attrs["observed_at"].(string); ok {
		a.ObservedAt, a.Has = v, a.Has|4
	}
	return a
}

func raCount(evs []codec.Event, typ codec.EventType) int {
	n := 0
	for _, e := range evs {
		if e.Type == typ {
			n++
		}
	}
	return n
}

// Feature: aws-relationship-registry, Property 7: Re-asserting relations replaces attributes and is idempotent
// Validates: Requirements 6.6, 6.7, 6.10, 6.11
func TestPropReassertReplacesAttributes(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		from := gen.Ref{Kind: "host", Index: 0}
		to := gen.Ref{Kind: "host", Index: 1}
		rel := gen.RelType().Draw(t, "rel")
		a := gen.RelAttrs().Draw(t, "A")
		b := gen.RelAttrs().Draw(t, "B")
		// Half the time B repeats A, so the unchanged path is covered.
		if rapid.Bool().Draw(t, "same") {
			b = a
		}
		clk := &stepClock{t: gen.Epoch}
		c := propEngine(t, clk.now)
		ctx := context.Background()
		key := graph.RelKey{Type: rel, From: from.ID(), To: to.ID()}
		t1, t2, t3 := gen.Epoch.Add(time.Minute), gen.Epoch.Add(2*time.Minute), gen.Epoch.Add(3*time.Minute)

		apply := func(attrs map[string]any, at time.Time) []codec.Event {
			clk.t = at
			before := c.g.LastSeq
			if _, err := c.Apply(ctx, raBatch(rel, from, to, attrs, at), ModeFull); err != nil {
				t.Fatalf("apply %v: %v", attrs, err)
			}
			evs, _ := logEvents(t, c, before+1, 0)
			return evs
		}
		stored := func(want map[string]any) {
			t.Helper()
			if c.g.RelationCount() != 1 {
				t.Fatalf("relation count %d, want 1", c.g.RelationCount())
			}
			r, ok := c.g.Relation(key)
			if !ok {
				t.Fatalf("relation %v missing", key)
			}
			if w := raWant(want); !r.Attrs.Equal(w) {
				t.Fatalf("stored attrs %+v, want %+v", r.Attrs, w)
			}
		}
		entityDigest := func() Digest {
			d, err := c.Digest(ctx, TimeRange{}, ChangeFilter{Subject: SubjectEntity})
			if err != nil {
				t.Fatal(err)
			}
			return d
		}

		first := apply(a, t1)
		if raCount(first, codec.RelationAdded) != 1 {
			t.Fatalf("first apply events %v, want one RelationAdded", typesOf(first))
		}
		stored(a)
		digestBefore := entityDigest()

		// A then B: stored attributes equal B, and only attributes changed.
		second := apply(b, t2)
		stored(b)
		wantUpdates := 1
		if reflect.DeepEqual(raWant(a), raWant(b)) {
			wantUpdates = 0
		}
		if len(second) != wantUpdates || raCount(second, codec.RelationUpdated) != wantUpdates {
			t.Fatalf("A=%v B=%v: events %v, want %d RelationUpdated only", a, b, typesOf(second), wantUpdates)
		}

		// The relation update is a relation change and adds no entity change or flap.
		if wantUpdates == 1 {
			pg, err := c.Changes(ctx, TimeRange{}, ChangeFilter{Kind: ChangeChanged, Subject: SubjectRelation}, OrderAsc)
			if err != nil {
				t.Fatal(err)
			}
			if len(pg.Items) != 1 || pg.Items[0].RelationType != rel || pg.Items[0].From != from.ID() || pg.Items[0].To != to.ID() {
				t.Fatalf("relation changes %+v, want exactly the updated relation", pg.Items)
			}
		}
		if got := entityDigest(); !reflect.DeepEqual(got, digestBefore) {
			t.Fatalf("entity digest changed by an attribute-only update: %+v, was %+v", got, digestBefore)
		}
		for _, f := range digestBefore.Top {
			if f.Changes != 1 {
				t.Fatalf("entity %s has %d changes, want 1 (created only)", f.ID, f.Changes)
			}
		}
		diff, err := c.Diff(ctx, gen.Epoch, t3)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range diff.Flapping {
			if f.Changes > 1 {
				t.Fatalf("entity %s flapping with %d changes after an attribute-only update", f.ID, f.Changes)
			}
		}

		// Applying B again appends nothing and leaves the projection unchanged.
		snap := c.g.Clone()
		if again := apply(b, t3); len(again) != 0 {
			t.Fatalf("re-applying B appended %v", typesOf(again))
		}
		if !c.g.Equal(snap) {
			t.Fatal("re-applying B changed the projection")
		}
		stored(b)
	})
}
