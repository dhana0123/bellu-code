package query

import (
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/codec"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/graph"
)

type attrGraph struct {
	*fakeGraph
	attrs codec.EdgeAttrs
}

func (g attrGraph) Relation(k graph.RelKey) (*graph.RelState, bool) {
	return &graph.RelState{Key: k, Attrs: g.attrs}, true
}

func TestNeighborsCarriesStoredEdgeAttrs(t *testing.T) {
	want := codec.EdgeAttrs{Evidence: "e", Confidence: "inferred", ObservedAt: "2025-01-01T00:00:00Z", Has: 7}
	g := attrGraph{newFake(graph.RelKey{Type: "t", From: "a", To: "b"}), want}
	derived := func(id string) []Edge {
		if id == "a" {
			return []Edge{{Type: "resolves_to", From: "a", To: "c"}}
		}
		return nil
	}
	got := Neighbors(g, "a", DirOut, "", 1, derived)
	if len(got) != 2 {
		t.Fatalf("edges = %+v", got)
	}
	for _, e := range got {
		if e.Derived {
			if e.Evidence != "" || e.Confidence != "" || e.ObservedAt != "" {
				t.Errorf("derived edge has attrs: %+v", e)
			}
			continue
		}
		if e.Evidence != "e" || e.Confidence != "inferred" || e.ObservedAt != want.ObservedAt {
			t.Errorf("stored edge attrs = %+v", e)
		}
	}
}
