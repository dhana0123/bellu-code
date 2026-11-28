package plan_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/codec"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/graph"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/plan"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

var t0 = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

func host(name string, attrs map[string]any) batch.Entity {
	return batch.Entity{Type: "host", Identity: map[string]string{"hostname": name}, Attributes: attrs}
}

func hid(name string) string {
	id, _ := ident.Hash("host", map[string]string{"hostname": name})
	return id
}

// apply plans and folds, as the engine does.
func apply(t *testing.T, g *graph.Graph, b batch.Batch, mode plan.Mode) plan.Result {
	t.Helper()
	r, err := plan.Plan(g, b, mode, t0)
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range r.Events {
		ev.Seq = g.LastSeq + 1
		ev.RecordedNS = t0.UnixNano()
		g.Fold(ev)
	}
	return r
}

func types(r plan.Result) []codec.EventType {
	var out []codec.EventType
	for _, e := range r.Events {
		out = append(out, e.Type)
	}
	return out
}

func TestValidationErrors(t *testing.T) {
	g := graph.New()
	cases := []struct {
		name string
		b    batch.Batch
		want string
	}{
		{"empty collector", batch.Batch{}, "collector"},
		{"unknown kind", batch.Batch{Collector: "c", Entities: []batch.Entity{{Type: "bogus", Identity: map[string]string{"a": "b"}}}}, `"bogus"`},
		{"missing identity", batch.Batch{Collector: "c", Entities: []batch.Entity{{Type: "host"}}}, `"hostname"`},
		{"duplicate", batch.Batch{Collector: "c", Entities: []batch.Entity{host("a", nil), host("a", nil)}}, "duplicate"},
		{"bad attr type", batch.Batch{Collector: "c", Entities: []batch.Entity{host("a", map[string]any{"weird": struct{}{}})}}, `"weird"`},
		{"no rel type", batch.Batch{Collector: "c", Entities: []batch.Entity{host("a", nil)}, Relations: []batch.Relation{{From: hid("a"), To: hid("a")}}}, "no type"},
		{"rel attrs", batch.Batch{Collector: "c", Entities: []batch.Entity{host("a", nil)}, Relations: []batch.Relation{{Type: "runs_on", From: hid("a"), To: hid("a"), Attributes: map[string]any{"x": 1}}}}, `"runs_on"`},
		{"dangling endpoint", batch.Batch{Collector: "c", Entities: []batch.Entity{host("a", nil)}, Relations: []batch.Relation{{Type: "runs_on", From: hid("a"), To: "host:nope"}}}, `"host:nope"`},
	}
	for _, tc := range cases {
		_, err := plan.Plan(g, tc.b, plan.ModeFull, t0)
		if !errors.Is(err, errs.Validation) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want validation naming %s", tc.name, err, tc.want)
		}
	}
}

func TestClassificationAndOwnership(t *testing.T) {
	g := graph.New()
	r := apply(t, g, batch.Batch{Collector: "a", Entities: []batch.Entity{host("h", map[string]any{"os": "linux", "status": "up"})}}, plan.ModeFull)
	if got := types(r); len(got) != 1 || got[0] != codec.EntityCreated {
		t.Fatalf("created: %v", got)
	}
	// Unchanged: no events.
	if r = apply(t, g, batch.Batch{Collector: "a", Entities: []batch.Entity{host("h", map[string]any{"os": "linux", "status": "up"})}}, plan.ModeFull); len(r.Events) != 0 {
		t.Fatalf("unchanged produced %v", types(r))
	}
	// Attribute update.
	r = apply(t, g, batch.Batch{Collector: "a", Entities: []batch.Entity{host("h", map[string]any{"os": "bsd", "status": "up"})}}, plan.ModeFull)
	if len(r.Events) != 1 || r.Events[0].Class != codec.ClassAttr {
		t.Fatalf("attr update: %+v", r.Events)
	}
	// State change, and omitted owned attribute is unset.
	r = apply(t, g, batch.Batch{Collector: "a", Entities: []batch.Entity{host("h", map[string]any{"status": "down"})}}, plan.ModeFull)
	ev := r.Events[0]
	if ev.Class != codec.ClassState || len(ev.Unset) != 1 || ev.Unset[0] != "os" {
		t.Fatalf("state change: %+v", ev)
	}
	// Another collector omitting attributes it does not own unsets nothing.
	r = apply(t, g, batch.Batch{Collector: "b", Entities: []batch.Entity{host("h", nil)}}, plan.ModeFull)
	if got := types(r); len(got) != 1 || got[0] != codec.ScopeDelta || len(r.Events[0].AddEnts) != 1 {
		t.Fatalf("second collector: %v", got)
	}
}

func TestFullRemovalAndRelations(t *testing.T) {
	g := graph.New()
	rel := batch.Relation{Type: "runs_on", From: hid("a"), To: hid("b")}
	apply(t, g, batch.Batch{Collector: "c", Entities: []batch.Entity{host("a", nil), host("b", nil)}, Relations: []batch.Relation{rel}}, plan.ModeFull)
	if g.RelationCount() != 1 {
		t.Fatal("relation missing")
	}
	// Partial never removes.
	if r := apply(t, g, batch.Batch{Collector: "c", Entities: []batch.Entity{host("a", nil)}}, plan.ModePartial); len(r.Events) != 0 {
		t.Fatalf("partial: %v", types(r))
	}
	// Full drops b: relation first, then entity.
	r := apply(t, g, batch.Batch{Collector: "c", Entities: []batch.Entity{host("a", nil)}}, plan.ModeFull)
	got := types(r)
	if len(got) != 2 || got[0] != codec.RelationRemoved || got[1] != codec.EntityRemoved || r.Removed != 2 {
		t.Fatalf("removal: %v removed=%d", got, r.Removed)
	}
	if g.RelationCount() != 0 || g.LiveCount() != 1 {
		t.Fatal("projection wrong after removal")
	}
	// Revival is a Created event.
	r = apply(t, g, batch.Batch{Collector: "c", Entities: []batch.Entity{host("a", nil), host("b", nil)}}, plan.ModeFull)
	if got := types(r); len(got) != 1 || got[0] != codec.EntityCreated {
		t.Fatalf("revive: %v", got)
	}
}

func TestSharedAssertionAndRetireConflict(t *testing.T) {
	g := graph.New()
	apply(t, g, batch.Batch{Collector: "a", Entities: []batch.Entity{host("x", nil)}}, plan.ModeFull)
	apply(t, g, batch.Batch{Collector: "b", Entities: []batch.Entity{host("x", nil)}}, plan.ModeFull)
	// a drops x: b still asserts it, so only a ScopeDelta.
	r := apply(t, g, batch.Batch{Collector: "a", Entities: []batch.Entity{host("y", nil)}}, plan.ModeFull)
	var sd *codec.Event
	for i := range r.Events {
		if r.Events[i].Type == codec.EntityRemoved {
			t.Fatal("entity removed despite other asserter")
		}
		if r.Events[i].Type == codec.ScopeDelta {
			sd = &r.Events[i]
		}
	}
	if sd == nil || len(sd.DelEnts) != 1 {
		t.Fatalf("scope delta: %+v", sd)
	}
	if e, _ := g.Entity(hid("x")); !e.Live {
		t.Fatal("x should stay live")
	}
	// b drops x (sole asserter) while a relation names it: conflict.
	_, err := plan.Plan(g, batch.Batch{Collector: "b", Entities: []batch.Entity{host("z", nil)},
		Relations: []batch.Relation{{Type: "runs_on", From: hid("z"), To: hid("x")}}}, plan.ModeFull, t0)
	if !errors.Is(err, errs.Validation) || !strings.Contains(err.Error(), hid("x")) {
		t.Fatalf("retire conflict: %v", err)
	}
}

func TestObservedAtDefaultAndPreserved(t *testing.T) {
	g := graph.New()
	r, _ := plan.Plan(g, batch.Batch{Collector: "c"}, plan.ModeFull, t0)
	if !r.ObservedAt.Equal(t0) {
		t.Fatal("default now")
	}
	vt := t0.Add(-time.Hour)
	r, _ = plan.Plan(g, batch.Batch{Collector: "c", ObservedAt: vt, Entities: []batch.Entity{host("h", nil)}}, plan.ModeFull, t0)
	if !r.ObservedAt.Equal(vt) || r.Events[0].ValidNS != vt.UnixNano() {
		t.Fatal("supplied time not preserved")
	}
}

// Each validation failure must name the offending relation type, endpoint,
// kind or attribute so a collector author can find the problem (Req 3.5, 3.6).
func TestValidationErrorsNameTheOffender(t *testing.T) {
	a, b := hid("a"), hid("b")
	two := []batch.Entity{host("a", nil), host("b", nil)}
	cases := []struct {
		name string
		b    batch.Batch
		want []string
	}{
		{"unknown kind", batch.Batch{Collector: "c", Entities: []batch.Entity{{Type: "gizmo", Identity: map[string]string{"k": "v"}}}}, []string{`"gizmo"`}},
		{"missing identity attribute", batch.Batch{Collector: "c", Entities: []batch.Entity{{Type: "host", Identity: map[string]string{}}}}, []string{`"host"`, `"hostname"`}},
		{"empty identity attribute", batch.Batch{Collector: "c", Entities: []batch.Entity{{Type: "host", Identity: map[string]string{"hostname": ""}}}}, []string{`"hostname"`}},
		{"duplicate entity", batch.Batch{Collector: "c", Entities: []batch.Entity{host("a", nil), host("a", nil)}}, []string{"duplicate", `"host"`, a}},
		{"relation without type", batch.Batch{Collector: "c", Entities: two, Relations: []batch.Relation{{From: a, To: b}}}, []string{"no type", a, b}},
		{"relation attributes", batch.Batch{Collector: "c", Entities: two, Relations: []batch.Relation{{Type: "depends_on", From: a, To: b, Attributes: map[string]any{"w": 1}}}}, []string{`"depends_on"`, a, b, `attribute "w"`, "evidence, confidence and observed_at"}},
		{"unknown from endpoint", batch.Batch{Collector: "c", Entities: two, Relations: []batch.Relation{{Type: "runs_on", From: "host:ghost", To: b}}}, []string{`"runs_on"`, `"host:ghost"`, "from"}},
		{"unknown to endpoint", batch.Batch{Collector: "c", Entities: two, Relations: []batch.Relation{{Type: "runs_on", From: a, To: "host:ghost"}}}, []string{`"runs_on"`, `"host:ghost"`, "to"}},
	}
	for _, tc := range cases {
		_, err := plan.Plan(graph.New(), tc.b, plan.ModeFull, t0)
		if !errors.Is(err, errs.Validation) {
			t.Errorf("%s: got %v, want ErrValidation", tc.name, err)
			continue
		}
		for _, w := range tc.want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%s: error %q does not name %s", tc.name, err, w)
			}
		}
	}
}

// Relations accept exactly the fixed attribute names (Req 16.6).
func TestRelationAttributeNamesFixedSet(t *testing.T) {
	a, b := hid("a"), hid("b")
	two := []batch.Entity{host("a", nil), host("b", nil)}
	run := func(attrs map[string]any) error {
		_, err := plan.Plan(graph.New(), batch.Batch{Collector: "c", Entities: two,
			Relations: []batch.Relation{{Type: "depends_on", From: a, To: b, Attributes: attrs}}}, plan.ModeFull, t0)
		return err
	}
	ok := map[string]any{"evidence": "seen in config", "confidence": "inferred", "observed_at": "2024-01-02T03:04:05Z"}
	if err := run(ok); err != nil {
		t.Fatalf("fixed names rejected: %v", err)
	}
	for name := range ok {
		if err := run(map[string]any{name: ok[name]}); err != nil {
			t.Errorf("%s rejected: %v", name, err)
		}
	}
	for _, name := range []string{"w", "Evidence", "evidence ", "weight", ""} {
		err := run(map[string]any{name: "x"})
		if !errors.Is(err, errs.Validation) || !strings.Contains(err.Error(), "not allowed") {
			t.Errorf("name %q: got %v, want validation error", name, err)
		}
	}
}
func TestValidationRetiredEndpointNamed(t *testing.T) {
	g := graph.New()
	apply(t, g, batch.Batch{Collector: "c", Entities: []batch.Entity{host("a", nil), host("b", nil)}}, plan.ModeFull)
	// The full batch drops b yet relates to it.
	_, err := plan.Plan(g, batch.Batch{Collector: "c", Entities: []batch.Entity{host("a", nil)},
		Relations: []batch.Relation{{Type: "runs_on", From: hid("a"), To: hid("b")}}}, plan.ModeFull, t0)
	if !errors.Is(err, errs.Validation) {
		t.Fatalf("got %v, want ErrValidation", err)
	}
	for _, w := range []string{`"runs_on"`, hid("b"), "to", "retired"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("error %q does not name %s", err, w)
		}
	}
}

func TestValidationRejectsWholeBatch(t *testing.T) {
	g := graph.New()
	b := batch.Batch{Collector: "c", Entities: []batch.Entity{host("a", nil)},
		Relations: []batch.Relation{{Type: "runs_on", From: hid("a"), To: "host:ghost"}}}
	r, err := plan.Plan(g, b, plan.ModeFull, t0)
	if !errors.Is(err, errs.Validation) || g.LiveCount() != 0 {
		t.Fatalf("err=%v live=%d", err, g.LiveCount())
	}
	_ = r
}

func TestRetainKeepsEntitiesAndRelationsInFullMode(t *testing.T) {
	g := graph.New()
	apply(t, g, batch.Batch{Collector: "c", Entities: []batch.Entity{
		host("keep", map[string]any{"os": "linux"}), host("gone", map[string]any{"os": "bsd"}), host("other", map[string]any{"os": "linux"}),
	}, Relations: []batch.Relation{
		{Type: "runs_on", From: hid("other"), To: hid("keep")},
		{Type: "runs_on", From: hid("other"), To: hid("gone")},
	}}, plan.ModeFull)

	r := apply(t, g, batch.Batch{Collector: "c",
		Entities: []batch.Entity{host("other", map[string]any{"os": "linux"})},
		Retain:   []batch.Retain{{Kind: "host", Attrs: map[string]string{"os": "linux"}}},
	}, plan.ModeFull)

	if _, ok := g.Entity(hid("keep")); !ok || !mustEntity(g, hid("keep")).Live {
		t.Fatal("retained entity was retired")
	}
	if mustEntity(g, hid("gone")).Live {
		t.Fatal("unmatched entity should be retired")
	}
	if _, ok := g.Relation(graph.RelKey{Type: "runs_on", From: hid("other"), To: hid("keep")}); !ok {
		t.Fatal("relation to retained entity was removed")
	}
	if _, ok := g.Relation(graph.RelKey{Type: "runs_on", From: hid("other"), To: hid("gone")}); ok {
		t.Fatal("relation to retired entity should be removed")
	}
	for _, ev := range r.Events {
		if ev.Type == codec.EntityRemoved && ev.ID == hid("keep") {
			t.Fatal("EntityRemoved emitted for retained entity")
		}
	}
	if !mustEntityAsserted(g, hid("keep"), "c") {
		t.Fatal("retained entity lost its assertion")
	}
}

func TestRetainEmptyAttrsMatchesKindAndMismatchRetires(t *testing.T) {
	g := graph.New()
	apply(t, g, batch.Batch{Collector: "c", Entities: []batch.Entity{host("a", map[string]any{"os": "linux"})}}, plan.ModeFull)
	apply(t, g, batch.Batch{Collector: "c", Retain: []batch.Retain{{Kind: "host", Attrs: map[string]string{"os": "bsd"}}}}, plan.ModeFull)
	if mustEntity(g, hid("a")).Live {
		t.Fatal("non-matching rule must not retain")
	}
	g = graph.New()
	apply(t, g, batch.Batch{Collector: "c", Entities: []batch.Entity{host("a", nil)}}, plan.ModeFull)
	r := apply(t, g, batch.Batch{Collector: "c", Retain: []batch.Retain{{Kind: "host"}}}, plan.ModeFull)
	if !mustEntity(g, hid("a")).Live || len(r.Events) != 0 {
		t.Fatalf("empty Attrs rule should retain by kind with no events, got %v", types(r))
	}
}

func mustEntity(g *graph.Graph, id string) *graph.EntityState {
	es, _ := g.Entity(id)
	return es
}

func mustEntityAsserted(g *graph.Graph, id, c string) bool {
	_, ok := mustEntity(g, id).Asserted[c]
	return ok
}
