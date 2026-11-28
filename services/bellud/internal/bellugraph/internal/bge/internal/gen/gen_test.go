package gen_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/codec"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/internal/gen"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/internal/gen/model"
)

func TestValueGenerators(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		if _, err := codec.FromAny("v", gen.Value().Draw(t, "ok")); err != nil {
			t.Fatalf("supported value rejected: %v", err)
		}
		if _, err := codec.FromAny("v", gen.Unsupported().Draw(t, "bad")); err == nil {
			t.Fatal("unsupported value accepted")
		}
		if _, err := ident.Hash(gen.Kind().Draw(t, "kind"), nil); err == nil {
			t.Fatal("empty identity hashed")
		}
		if h := gen.HTML().Draw(t, "html"); h == "" {
			t.Fatal("empty html")
		}
	})
}

func TestClockRepeatsLast(t *testing.T) {
	a, b := gen.Epoch, gen.Epoch.Add(-time.Second)
	c := gen.NewClock(a, b)
	if c.Now() != a || c.Now() != b || c.Now() != b {
		t.Fatal("clock script not replayed")
	}
}

// Schedules fold through the model and keep its invariants.
func TestScheduleModelInvariants(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		steps := gen.Options{}.Schedule(1, 12).Draw(t, "schedule")
		m := model.New()
		var lastRT time.Time
		for _, s := range steps {
			evs, err := m.Fold(s.Batch, s.Mode, s.Now)
			if err != nil {
				t.Fatalf("batch without foreign endpoints rejected: %v", err)
			}
			for _, ev := range evs {
				if ev.Recorded.Before(lastRT) {
					t.Fatal("Recorded_Time decreased")
				}
				lastRT = ev.Recorded
			}
			cur := m.Current()
			for _, k := range cur.LiveRels() {
				if !cur.IsLive(k.From) || !cur.IsLive(k.To) {
					t.Fatalf("live relation %v has a dead endpoint", k)
				}
			}
			for c, sc := range cur.Scopes {
				for id := range sc.Ents {
					if !cur.IsLive(id) {
						t.Fatalf("%s asserts dead entity %s", c, id)
					}
				}
			}
			for id := range cur.Entities {
				if cur.IsLive(id) && len(cur.Asserted(id)) == 0 {
					t.Fatalf("live entity %s asserted by nobody", id)
				}
			}
			// Re-applying the same Batch is a no-op.
			again, err := m.Fold(s.Batch, s.Mode, s.Now)
			if err != nil || len(again) != 0 {
				t.Fatalf("re-apply: %d events, err %v", len(again), err)
			}
		}
		// Folding the whole log at the end of time equals the current state.
		all := m.AsOf(gen.Epoch.Add(1000 * time.Hour))
		if !reflect.DeepEqual(all.LiveIDs(), m.Current().LiveIDs()) || !reflect.DeepEqual(all.LiveRels(), m.Current().LiveRels()) {
			t.Fatal("AsOf(end) differs from current")
		}
	})
}

func TestModelSemantics(t *testing.T) {
	now := gen.Epoch
	h := gen.Ref{Kind: "host", Index: 1}
	p := gen.Ref{Kind: "process", Index: 1}
	ent := func(r gen.Ref, attrs map[string]any) batch.Entity {
		return batch.Entity{Type: r.Kind, Identity: r.Identity(), Attributes: attrs}
	}
	m := model.New()

	// c1 and c2 both assert the host; c1 alone asserts the process and relation.
	if _, err := m.Fold(batch.Batch{Collector: "c1", Entities: []batch.Entity{ent(h, map[string]any{"state": "up", "a": 1}), ent(p, nil)},
		Relations: []batch.Relation{{Type: "runs_on", From: p.ID(), To: h.ID()}}}, model.Full, now); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Fold(batch.Batch{Collector: "c2", Entities: []batch.Entity{ent(h, map[string]any{"state": "up", "a": 1})}}, model.Full, now); err != nil {
		t.Fatal(err)
	}
	// c1 stops reporting the host: still asserted by c2, so not removed; but
	// its relation endpoint is fine because the host stays live.
	evs, err := m.Fold(batch.Batch{Collector: "c1", Entities: []batch.Entity{ent(p, nil)},
		Relations: []batch.Relation{{Type: "runs_on", From: p.ID(), To: h.ID()}}}, model.Full, now)
	if err != nil || !m.Current().IsLive(h.ID()) {
		t.Fatalf("host retired while asserted by c2: %v", err)
	}
	for _, c := range model.Changes(evs) {
		if c.Kind == "removed" {
			t.Fatalf("unexpected removal %+v", c)
		}
	}
	// c2 stops too: the host and the relation touching it go.
	evs, err = m.Fold(batch.Batch{Collector: "c2"}, model.Full, now)
	if err != nil || m.Current().IsLive(h.ID()) || len(m.Current().LiveRels()) != 0 {
		t.Fatalf("host not retired: %v", err)
	}
	if got := model.Changes(evs); len(got) != 2 || got[0].Subject != "relation" || got[1].Subject != "entity" {
		t.Fatalf("removal events = %+v", got)
	}
	// A relation to a dead entity is rejected, changing nothing.
	n := len(m.Log)
	if _, err = m.Fold(batch.Batch{Collector: "c1", Relations: []batch.Relation{{Type: "runs_on", From: p.ID(), To: h.ID()}}}, model.Partial, now); err == nil || !strings.Contains(err.Error(), "neither in the batch nor live") || len(m.Log) != n {
		t.Fatalf("dead endpoint accepted: %v", err)
	}
	// Revival: same ID, created again; annotation survives and is operator-owned.
	if _, err := m.Annotate(p.ID(), "op", map[string]string{"note": "x"}, nil, now); err != nil {
		t.Fatal(err)
	}
	evs, err = m.Fold(batch.Batch{Collector: "c3", Entities: []batch.Entity{ent(h, map[string]any{"state": "down"})}}, model.Partial, now)
	if err != nil || model.Changes(evs)[0].Kind != "added" || !m.Current().IsLive(h.ID()) {
		t.Fatalf("revival: %v %+v", err, evs)
	}
	if a, ok := m.Current().Annotation(p.ID()); !ok || a.Values["note"] != "x" {
		t.Fatal("annotation lost")
	}
	if _, err := m.Annotate("host:dead", "op", nil, nil, now); !strings.Contains(err.Error(), errs.NotFound.Error()) {
		t.Fatalf("annotate unknown: %v", err)
	}
	// Attribute ownership: c3 owns "state"; c4 cannot unset it by omission.
	if _, err := m.Fold(batch.Batch{Collector: "c4", Entities: []batch.Entity{ent(h, map[string]any{"zone": "z"})}}, model.Partial, now); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Current().Entities[h.ID()].Attrs["state"]; !ok {
		t.Fatal("c4 unset an attribute owned by c3")
	}
}

// Valid attribute maps fold; maps with one injected defect are rejected whole.
func TestRelAttrsGenerators(t *testing.T) {
	h, p := gen.Ref{Kind: "host", Index: 0}, gen.Ref{Kind: "process", Index: 0}
	ents := []batch.Entity{
		{Type: h.Kind, Identity: h.Identity()},
		{Type: p.Kind, Identity: p.Identity()},
	}
	rel := func(attrs map[string]any) batch.Batch {
		return batch.Batch{Collector: "c1", Entities: ents, Relations: []batch.Relation{{Type: "runs_on", From: p.ID(), To: h.ID(), Attributes: attrs}}}
	}
	rapid.Check(t, func(t *rapid.T) {
		m := model.New()
		if _, err := m.Fold(rel(gen.RelAttrs().Draw(t, "ok")), model.Full, gen.Epoch); err != nil {
			t.Fatalf("valid attributes rejected: %v", err)
		}
		bad := gen.BadRelAttrs().Draw(t, "bad")
		n := len(m.Log)
		if _, err := m.Fold(rel(bad.Attributes), model.Full, gen.Epoch); !errors.Is(err, errs.Validation) || len(m.Log) != n {
			t.Fatalf("defect %s (%v): err %v, log %d -> %d", bad.Defect, bad.Attributes, err, n, len(m.Log))
		}
	})
}

func TestModelRelationAttributes(t *testing.T) {
	now := gen.Epoch
	h, p := gen.Ref{Kind: "host", Index: 0}, gen.Ref{Kind: "process", Index: 0}
	ents := []batch.Entity{{Type: h.Kind, Identity: h.Identity()}, {Type: p.Kind, Identity: p.Identity()}}
	key := model.RelKey{Type: "runs_on", From: p.ID(), To: h.ID()}
	apply := func(m *model.Model, collector string, attrs map[string]any) ([]model.Event, error) {
		return m.Fold(batch.Batch{Collector: collector, Entities: ents,
			Relations: []batch.Relation{{Type: key.Type, From: key.From, To: key.To, Attributes: attrs}}}, model.Partial, now)
	}
	types := func(evs []model.Event) []model.EventType {
		var out []model.EventType
		for _, ev := range evs {
			out = append(out, ev.Type)
		}
		return out
	}
	m := model.New()
	evs, err := apply(m, "c1", map[string]any{"evidence": "", "confidence": "inferred"})
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Current().Rels[key].Attrs; got.Has != 3 || got.Evidence != "" || got.Confidence != "inferred" {
		t.Fatalf("attrs after add = %+v", got)
	}
	// Same attributes: no event. Different: one RelationUpdated, reported as changed.
	if evs, _ = apply(m, "c1", map[string]any{"evidence": "", "confidence": "inferred"}); len(evs) != 0 {
		t.Fatalf("equal attributes produced %v", types(evs))
	}
	evs, _ = apply(m, "c1", map[string]any{"evidence": "x"})
	c := model.Changes(evs)
	if len(evs) != 1 || evs[0].Type != model.RelationUpdated || len(c) != 1 || c[0].Kind != "changed" || c[0].Subject != "relation" {
		t.Fatalf("update events = %v, changes = %+v", types(evs), c)
	}
	// An omitted evidence differs from an empty one.
	if evs, _ = apply(m, "c1", map[string]any{"evidence": ""}); len(evs) != 1 {
		t.Fatalf("empty vs omitted: %v", types(evs))
	}
	// Another collector with different attributes adds scope and replaces them.
	evs, _ = apply(m, "c2", nil)
	if got := types(evs); len(got) != 2 || got[0] != model.RelationUpdated || got[1] != model.ScopeDelta {
		t.Fatalf("c2 events = %v", got)
	}
	if !m.Current().Rels[key].Attrs.Zero() {
		t.Fatal("attributes not cleared")
	}
	// Rejections: conflicting duplicates, unknown name.
	n := len(m.Log)
	dup := batch.Batch{Collector: "c1", Entities: ents, Relations: []batch.Relation{
		{Type: key.Type, From: key.From, To: key.To, Attributes: map[string]any{"evidence": "a"}},
		{Type: key.Type, From: key.From, To: key.To, Attributes: map[string]any{"evidence": "b"}},
	}}
	if _, err := m.Fold(dup, model.Partial, now); !errors.Is(err, errs.Validation) || len(m.Log) != n {
		t.Fatalf("conflicting duplicates: %v", err)
	}
	// RelationUpdated for a relation that is not live changes nothing.
	s := model.NewState()
	s.Step(model.Event{Seq: 1, Type: model.RelationUpdated, Rel: key, Attrs: codec.EdgeAttrs{Evidence: "x", Has: 1}})
	if len(s.Rels) != 0 {
		t.Fatal("update created a relation")
	}
}
