package gen_test

import (
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
