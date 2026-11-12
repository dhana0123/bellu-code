package engine

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"reflect"
	"sort"
	"time"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/codec"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/graph"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/internal/gen/model"
)

// stepClock is a settable fake clock.
type stepClock struct{ t time.Time }

func (c *stepClock) now() time.Time { return c.t }

// propEngine opens an Engine in a fresh directory for one rapid iteration.
func propEngine(t *rapid.T, clock func() time.Time) *Core {
	dir, err := os.MkdirTemp("", "bge-prop-")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Open(dir, Options{Clock: clock, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		os.RemoveAll(dir)
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		_ = c.Close(context.Background())
		os.RemoveAll(dir)
	})
	return c
}

func engineMode(m model.Mode) Mode {
	if m == model.Partial {
		return ModePartial
	}
	return ModeFull
}

// logEvents returns the stored events with seq in [from, to] and their raw envelopes.
func logEvents(t *rapid.T, c *Core, from, to uint64) ([]codec.Event, [][]byte) {
	v := c.st.NewView()
	defer v.Close()
	it, err := v.Events(from, to)
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	var evs []codec.Event
	var raws [][]byte
	for it.Next() {
		ev, err := it.Event()
		if err != nil {
			t.Fatal(err)
		}
		evs = append(evs, ev)
		raws = append(raws, it.Raw())
	}
	return evs, raws
}

func relStrings[K any](ks []K, f func(K) string) []string {
	out := make([]string, len(ks))
	for i, k := range ks {
		out[i] = f(k)
	}
	sort.Strings(out)
	return out
}

func sameMap(a, b map[string]string) bool {
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

// compareToModel fails t when the Projection differs from the model state.
func compareToModel(t *rapid.T, g *graph.Graph, ms *model.State) {
	t.Helper()
	if g.EntityCount() != len(ms.Entities) {
		t.Fatalf("entity count %d, model %d", g.EntityCount(), len(ms.Entities))
	}
	if g.LastSeq != ms.LastSeq {
		t.Fatalf("LastSeq %d, model %d", g.LastSeq, ms.LastSeq)
	}
	for id, me := range ms.Entities {
		ee, ok := g.Entity(id)
		if !ok {
			t.Fatalf("entity %s missing", id)
		}
		if ee.Live != me.Live {
			t.Fatalf("entity %s live=%v, model %v", id, ee.Live, me.Live)
		}
		if !ee.VT.Equal(me.Valid) || !ee.RT.Equal(me.Recorded) || ee.Seq != me.Seq {
			t.Fatalf("entity %s stamps vt=%v rt=%v seq=%d, model vt=%v rt=%v seq=%d", id, ee.VT, ee.RT, ee.Seq, me.Valid, me.Recorded, me.Seq)
		}
		if !me.Live {
			continue
		}
		if ee.Kind != me.Kind || !sameMap(ee.Identity, me.Identity) {
			t.Fatalf("entity %s kind/identity %s %v, model %s %v", id, ee.Kind, ee.Identity, me.Kind, me.Identity)
		}
		if len(ee.Attrs) != len(me.Attrs) {
			t.Fatalf("entity %s attrs %v, model %v", id, ee.Attrs, me.Attrs)
		}
		for k, v := range me.Attrs {
			if w, ok := ee.Attrs[k]; !ok || !w.Equal(v) {
				t.Fatalf("entity %s attr %q = %v, model %v", id, k, w, v)
			}
		}
		if !sameMap(ee.Owner, me.Owner) {
			t.Fatalf("entity %s owners %v, model %v", id, ee.Owner, me.Owner)
		}
		got := make([]string, 0, len(ee.Asserted))
		for c := range ee.Asserted {
			got = append(got, c)
		}
		sort.Strings(got)
		if want := ms.Asserted(id); !reflect.DeepEqual(append([]string(nil), got...), append([]string(nil), want...)) && (len(got) != 0 || len(want) != 0) {
			t.Fatalf("entity %s asserted by %v, model %v", id, got, want)
		}
	}
	// Live relations.
	rs := func(k graph.RelKey) string { return k.Type + "|" + k.From + "|" + k.To }
	gotRels := g.AllRelations()
	for _, k := range gotRels {
		for _, end := range []string{k.From, k.To} {
			if e, ok := g.Entity(end); !ok || !e.Live {
				t.Fatalf("live relation %v has dead endpoint %s", k, end)
			}
		}
	}
	got := relStrings(gotRels, rs)
	want := relStrings(ms.LiveRels(), func(k model.RelKey) string { return k.Type + "|" + k.From + "|" + k.To })
	if !reflect.DeepEqual(got, want) && (len(got) != 0 || len(want) != 0) {
		t.Fatalf("live relations %v, model %v", got, want)
	}
	// Collector scopes (empty scopes do not exist in the Projection).
	cols := map[string]bool{}
	for c := range ms.Scopes {
		cols[c] = true
	}
	for _, c := range g.Collectors() {
		cols[c] = true
	}
	for c := range cols {
		var ge []string
		var gr []string
		if sc := g.Scope(c); sc != nil {
			for id := range sc.Ents {
				ge = append(ge, id)
			}
			for k := range sc.Rels {
				gr = append(gr, rs(k))
			}
		}
		var me, mr []string
		if sc := ms.Scopes[c]; sc != nil {
			for id := range sc.Ents {
				me = append(me, id)
			}
			for k := range sc.Rels {
				mr = append(mr, k.Type+"|"+k.From+"|"+k.To)
			}
		}
		sort.Strings(ge)
		sort.Strings(gr)
		sort.Strings(me)
		sort.Strings(mr)
		if len(ge)+len(me) > 0 && !reflect.DeepEqual(ge, me) {
			t.Fatalf("scope %s entities %v, model %v", c, ge, me)
		}
		if len(gr)+len(mr) > 0 && !reflect.DeepEqual(gr, mr) {
			t.Fatalf("scope %s relations %v, model %v", c, gr, mr)
		}
	}
}

func typesOf(evs []codec.Event) []int {
	out := make([]int, len(evs))
	for i, e := range evs {
		out[i] = int(e.Type)
	}
	return out
}

func modelTypesOf(evs []model.Event) []int {
	out := make([]int, len(evs))
	for i, e := range evs {
		out[i] = int(e.Type)
	}
	return out
}

var _ = fmt.Sprint
