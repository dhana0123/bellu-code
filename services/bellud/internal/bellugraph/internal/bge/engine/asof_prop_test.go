package engine

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/graph"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/internal/gen"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/internal/gen/model"
)

// buildSnapFixture is like buildPropFixture but also writes Snapshots at
// random points of the log, so as-of reads start from them.
func buildSnapFixture(t *rapid.T) *propFixture {
	steps := gen.Options{ForeignEndpoints: true}.Schedule(1, 14).Draw(t, "schedule")
	clk := &stepClock{t: gen.Epoch}
	f := &propFixture{c: propEngine(t, clk.now), m: model.New()}
	ctx := context.Background()
	n := 0
	for i, s := range steps {
		clk.t = s.Now
		mevs, merr := f.m.Fold(s.Batch, s.Mode, s.Now)
		_, err := f.c.Apply(ctx, s.Batch, engineMode(s.Mode))
		if (err != nil) != (merr != nil) {
			t.Fatalf("step %d: engine err %v, model err %v", i, err, merr)
		}
		f.events = append(f.events, mevs...)
		if rapid.IntRange(0, 3).Draw(t, "annotate") == 0 {
			if live := f.m.Current().LiveIDs(); len(live) > 0 {
				id := rapid.SampledFrom(live).Draw(t, "annotated")
				n++
				set := map[string]string{"note": fmt.Sprintf("v%d", n)}
				if _, err := f.c.Annotate(ctx, id, set, nil, "op"); err != nil {
					t.Fatal(err)
				}
				ev, err := f.m.Annotate(id, "op", set, nil, s.Now)
				if err != nil {
					t.Fatal(err)
				}
				f.events = append(f.events, ev)
			}
		}
		if rapid.IntRange(0, 3).Draw(t, "snapshot") == 0 {
			if err := f.c.writeSnapshot(); err != nil {
				t.Fatal(err)
			}
		}
	}
	return f
}

// drawInstant draws an instant near the event Valid_Times, on the grid, or
// outside the log's range.
func drawInstant(t *rapid.T, evs []model.Event, label string) time.Time {
	gens := []*rapid.Generator[time.Time]{
		gen.ValidTime(),
		rapid.Map(rapid.IntRange(-3, 3), func(s int) time.Time { return gen.Epoch.Add(time.Duration(s) * time.Second) }),
	}
	if len(evs) > 0 {
		gens = append(gens, rapid.Custom(func(t *rapid.T) time.Time {
			e := rapid.SampledFrom(evs).Draw(t, "event")
			return e.Valid.Add(time.Duration(rapid.IntRange(-1, 1).Draw(t, "off")) * time.Second)
		}))
	}
	return rapid.OneOf(gens...).Draw(t, label)
}

// Feature: bellu-graph-native, Property 9: As-of equals the naive fold
// Validates: Requirements 4.4, 4.7
func TestPropAsOfEqualsNaiveFold(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		f := buildSnapFixture(t)
		ctx := context.Background()
		ids := map[string]bool{"missing-entity": true}
		for _, e := range f.events {
			if e.ID != "" {
				ids[e.ID] = true
			}
		}
		idList := make([]string, 0, len(ids))
		for id := range ids {
			idList = append(idList, id)
		}
		sort.Strings(idList)
		for i := 0; i < 3; i++ {
			at := drawInstant(t, f.events, "at")
			want := f.m.AsOf(at)
			g, err := f.c.StateAt(ctx, at)
			if err != nil {
				t.Fatalf("StateAt(%v): %v", at, err)
			}
			compareAsOf(t, g, want)
			for _, id := range idList {
				v, err := f.c.Entity(ctx, id, &at)
				if !want.IsLive(id) {
					if !errors.Is(err, errs.NotFound) {
						t.Fatalf("Entity(%s, %v) = %+v, %v; want NotFound", id, at, v, err)
					}
					continue
				}
				if err != nil {
					t.Fatalf("Entity(%s, %v): %v", id, at, err)
				}
				me := want.Entities[id]
				if v.Kind != me.Kind || !v.ObservedAt.Equal(me.Valid) || !v.RecordedAt.Equal(me.Recorded) {
					t.Fatalf("Entity(%s, %v) kind/times %s %v %v, model %s %v %v", id, at, v.Kind, v.ObservedAt, v.RecordedAt, me.Kind, me.Valid, me.Recorded)
				}
				if len(v.Attributes) != len(me.Attrs)+len(me.Identity) {
					t.Fatalf("Entity(%s, %v) attributes %v, model %v %v", id, at, v.Attributes, me.Identity, me.Attrs)
				}
				for k, a := range me.Attrs {
					if !reflect.DeepEqual(v.Attributes[k], a.ToAny()) {
						t.Fatalf("Entity(%s, %v) attr %q = %v, model %v", id, at, k, v.Attributes[k], a.ToAny())
					}
				}
				for k, s := range me.Identity {
					if v.Attributes[k] != s {
						t.Fatalf("Entity(%s, %v) identity %q = %v, model %v", id, at, k, v.Attributes[k], s)
					}
				}
				if !sameMap(v.Annotations, want.Ann[id].Values) {
					t.Fatalf("Entity(%s, %v) annotations %v, model %v", id, at, v.Annotations, want.Ann[id].Values)
				}
			}
		}
	})
}

// compareAsOf is compareToModel for as-of states. With out-of-order
// Valid_Times a relation may be folded before its endpoint exists, so the
// live-endpoint invariant of the current Projection does not apply.
func compareAsOf(t *rapid.T, g *graph.Graph, ms *model.State) {
	t.Helper()
	if g.EntityCount() != len(ms.Entities) || g.LastSeq != ms.LastSeq {
		t.Fatalf("entities %d lastSeq %d, model %d %d", g.EntityCount(), g.LastSeq, len(ms.Entities), ms.LastSeq)
	}
	for id, me := range ms.Entities {
		ee, ok := g.Entity(id)
		if !ok || ee.Live != me.Live || !ee.VT.Equal(me.Valid) || !ee.RT.Equal(me.Recorded) || ee.Seq != me.Seq {
			t.Fatalf("entity %s = %+v (found %v), model %+v", id, ee, ok, me)
		}
		if !me.Live {
			continue
		}
		if ee.Kind != me.Kind || !sameMap(ee.Identity, me.Identity) || len(ee.Attrs) != len(me.Attrs) || !sameMap(ee.Owner, me.Owner) {
			t.Fatalf("entity %s = %+v, model %+v", id, ee, me)
		}
		for k, v := range me.Attrs {
			if w, ok := ee.Attrs[k]; !ok || !w.Equal(v) {
				t.Fatalf("entity %s attr %q = %v, model %v", id, k, w, v)
			}
		}
	}
	rs := func(k graph.RelKey) string { return k.Type + "|" + k.From + "|" + k.To }
	got := relStrings(g.AllRelations(), rs)
	want := relStrings(ms.LiveRels(), func(k model.RelKey) string { return k.Type + "|" + k.From + "|" + k.To })
	if !reflect.DeepEqual(got, want) && len(got)+len(want) > 0 {
		t.Fatalf("relations %v, model %v", got, want)
	}
}

// Feature: aws-relationship-registry, Property 11: Replay, snapshot restore, and as-of reads preserve attributes
// Validates: Requirements 7.6, 7.7, 7.8
func TestPropAsOfRelationAttrs(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		f := buildSnapFixture(t)
		ctx := context.Background()
		for i := 0; i < 3; i++ {
			at := drawInstant(t, f.events, "at")
			want := f.m.AsOf(at)
			g, err := f.c.StateAt(ctx, at)
			if err != nil {
				t.Fatalf("StateAt(%v): %v", at, err)
			}
			rpCheckAsOfRelAttrs(t, g, want)

			// A relation whose events all lie after the instant is absent.
			first := map[model.RelKey]time.Time{}
			for _, e := range f.events {
				if e.Type != model.RelationAdded && e.Type != model.RelationUpdated {
					continue
				}
				if p, ok := first[e.Rel]; !ok || e.Valid.Before(p) {
					first[e.Rel] = e.Valid
				}
			}
			for k, v := range first {
				if !v.After(at) {
					continue
				}
				if _, ok := g.Relation(graph.RelKey{Type: k.Type, From: k.From, To: k.To}); ok {
					t.Fatalf("relation %v first seen at %v is present as of %v", k, v, at)
				}
			}
		}
	})
}

// rpCheckAsOfRelAttrs compares the relations of an as-of state, keys and edge
// attributes, with the model's.
func rpCheckAsOfRelAttrs(t *rapid.T, g *graph.Graph, ms *model.State) {
	t.Helper()
	keys := g.AllRelations()
	if len(keys) != len(ms.Rels) {
		t.Fatalf("as-of relations %d, model %d", len(keys), len(ms.Rels))
	}
	for _, k := range keys {
		r, _ := g.Relation(k)
		mr := ms.Rels[model.RelKey{Type: k.Type, From: k.From, To: k.To}]
		if r == nil || mr == nil || !r.Attrs.Equal(mr.Attrs) {
			t.Fatalf("as-of relation %v = %+v, model %+v", k, r, mr)
		}
	}
}
