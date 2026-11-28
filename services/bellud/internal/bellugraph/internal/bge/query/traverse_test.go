package query

import (
	"reflect"
	"sort"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/codec"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/graph"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
)

type fakeGraph struct {
	ents map[string]*graph.EntityState
	rels []graph.RelKey
}

func newFake(rels ...graph.RelKey) *fakeGraph {
	f := &fakeGraph{ents: map[string]*graph.EntityState{}, rels: rels}
	add := func(id string) {
		if _, ok := f.ents[id]; !ok {
			f.ents[id] = &graph.EntityState{ID: id, Kind: "host", Live: true,
				Identity: map[string]string{}, Attrs: map[string]codec.Value{}}
		}
	}
	for _, r := range rels {
		add(r.From)
		add(r.To)
	}
	return f
}

func (f *fakeGraph) Entity(id string) (*graph.EntityState, bool) { e, ok := f.ents[id]; return e, ok }
func (f *fakeGraph) LiveIDs() []string {
	var o []string
	for id := range f.ents {
		o = append(o, id)
	}
	sort.Strings(o)
	return o
}
func (f *fakeGraph) LiveIDsOfKind(string) []string { return f.LiveIDs() }
func (f *fakeGraph) Relation(k graph.RelKey) (*graph.RelState, bool) {
	for _, r := range f.rels {
		if r == k {
			return &graph.RelState{Key: k}, true
		}
	}
	return nil, false
}
func (f *fakeGraph) RelationsFrom(id string) []graph.RelKey {
	var o []graph.RelKey
	for _, r := range f.rels {
		if r.From == id {
			o = append(o, r)
		}
	}
	return o
}
func (f *fakeGraph) RelationsTo(id string) []graph.RelKey {
	var o []graph.RelKey
	for _, r := range f.rels {
		if r.To == id {
			o = append(o, r)
		}
	}
	return o
}

func rk(t, from, to string) graph.RelKey { return graph.RelKey{Type: t, From: from, To: to} }

func TestShortestPath(t *testing.T) {
	// a-b-c-d chain, a-x-d shortcut via two hops of x? a-x, x-d => a..d in 2 hops.
	g := newFake(rk("uses", "a", "b"), rk("uses", "b", "c"), rk("uses", "c", "d"),
		rk("uses", "a", "x"), rk("uses", "d", "x"), rk("uses", "p", "q"))
	r := ShortestPath(g, "a", "d", 6, nil)
	if !r.Found || len(r.Path) != 2 || r.Path[0].To != "x" || r.Path[1].Hops != 2 || r.Path[1].Direction != DirIn {
		t.Fatalf("path = %+v", r)
	}
	if r2 := ShortestPath(g, "a", "d", 6, nil); !reflect.DeepEqual(r, r2) {
		t.Fatal("not deterministic")
	}
	if r := ShortestPath(g, "a", "a", 3, nil); !r.Found || len(r.Path) != 0 {
		t.Fatalf("self = %+v", r)
	}
	// Disconnected: component exhausted.
	if r := ShortestPath(g, "a", "p", 6, nil); r.Found || !r.Exhausted {
		t.Fatalf("disconnected = %+v", r)
	}
	// Depth bound: chain of 4 with bound 2 is not exhausted.
	chain := newFake(rk("uses", "a", "b"), rk("uses", "b", "c"), rk("uses", "c", "d"), rk("uses", "d", "e"))
	if r := ShortestPath(chain, "a", "e", 2, nil); r.Found || r.Exhausted || r.DepthSearched != 2 {
		t.Fatalf("bounded = %+v", r)
	}
	if r := ShortestPath(chain, "a", "e", 4, nil); !r.Found || len(r.Path) != 4 {
		t.Fatalf("exact = %+v", r)
	}
}

func TestSharedNeighborsAndAttributes(t *testing.T) {
	g := newFake(rk("uses", "a", "n"), rk("uses", "b", "n"), rk("uses", "a", "m"))
	s := func(v string) codec.Value { return codec.Value{T: codec.TagString, S: v} }
	g.ents["a"].Attrs["os"] = s("linux")
	g.ents["b"].Attrs["os"] = s("linux")
	g.ents["a"].Attrs["api_token"] = s("SENTINEL")
	g.ents["b"].Attrs["api_token"] = s("SENTINEL")
	g.ents["a"].Attrs["arch"] = s("x")
	g.ents["b"].Attrs["arch"] = s("y")
	if got := SharedNeighbors(g, "a", "b", nil); !reflect.DeepEqual(got, []string{"n"}) {
		t.Fatalf("shared neighbors = %v", got)
	}
	if got := SharedAttributes(g, "a", "b"); !reflect.DeepEqual(got, map[string]string{"os": "linux"}) {
		t.Fatalf("shared attrs = %v", got)
	}
}

func dir(t string) ident.Direction { d, _ := ident.DirectionOf(t); return d }

func TestImpactFollowsDirections(t *testing.T) {
	// runs_on is reverse: failure of host h impacts process p (p -> h).
	// found_in is forward: failure of repo-side "from" f impacts "to" r.
	g := newFake(rk("runs_on", "p", "h"), rk("depends_on", "s", "p"), rk("found_in", "h", "r"), rk("runs_on", "h", "z"))
	got := Impact(g, "h", 5, dir, nil)
	ids := map[string]int{}
	for _, i := range got {
		ids[i.ID] = i.Hops
	}
	// p (hop1), s (hop2), r (forward from h, hop1); z is not impacted (h runs_on z, reverse flows z -> h).
	if !reflect.DeepEqual(ids, map[string]int{"p": 1, "r": 1, "s": 2}) {
		t.Fatalf("impact = %+v", got)
	}
	for _, i := range got {
		if i.ID == "s" && (len(i.Via) != 2 || i.Via[0].Type != "runs_on" || i.Via[1].Type != "depends_on") {
			t.Fatalf("via = %+v", i.Via)
		}
	}
	if got := Impact(g, "h", 1, dir, nil); len(got) != 2 {
		t.Fatalf("depth 1 = %+v", got)
	}
	// Undeclared type defaults to reverse.
	g2 := newFake(rk("custom", "a", "b"))
	if got := Impact(g2, "b", 1, dir, nil); len(got) != 1 || got[0].ID != "a" {
		t.Fatalf("default = %+v", got)
	}
	if got := Impact(g2, "a", 1, dir, nil); len(got) != 0 {
		t.Fatalf("default reverse blocked = %+v", got)
	}
}
