package query

import (
	"sort"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/graph"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
)

// Impacted is an entity reached by Impact, at its fewest hops, with the edge
// path (Via) of that length from the start entity.
type Impacted struct {
	ID   graph.EntityID
	Hops int
	Via  []Edge
}

// Impact is a BFS from start that follows each relation only in its impact
// flow: for a forward type from x = From to To, for a reverse type from
// x = To to From. dirOf gives the direction per type (ident.DirectionOf
// semantics). The start entity is excluded; the result is ordered by
// (hops, ID). Via edges carry Hops 1..n and Direction "out" when the flow
// followed From to To.
func Impact(g Reader, start graph.EntityID, depth int, dirOf func(relType string) ident.Direction, derived DerivedFn) []Impacted {
	type node struct {
		prev graph.EntityID
		edge Edge
		hops int
	}
	reached := map[graph.EntityID]node{start: {}}
	frontier := []graph.EntityID{start}
	var order []graph.EntityID
	for hops := 1; hops <= depth && len(frontier) > 0; hops++ {
		var next []graph.EntityID
		for _, x := range frontier {
			for _, adj := range adjacents(g, x, derived) {
				e := adj.edge
				fwd := dirOf(e.Type) == ident.Forward
				// Forward: failure travels From -> To. Reverse: To -> From.
				if (fwd && e.From != x) || (!fwd && e.To != x) {
					continue
				}
				if _, ok := reached[adj.other]; ok {
					continue
				}
				if fwd {
					e.Direction = DirOut
				} else {
					e.Direction = DirIn
				}
				reached[adj.other] = node{x, e, hops}
				next = append(next, adj.other)
				order = append(order, adj.other)
			}
		}
		sort.Strings(next)
		frontier = next
	}
	out := make([]Impacted, 0, len(order))
	for _, id := range order {
		var via []Edge
		for cur := id; cur != start; cur = reached[cur].prev {
			via = append(via, reached[cur].edge)
		}
		for i, j := 0, len(via)-1; i < j; i, j = i+1, j-1 {
			via[i], via[j] = via[j], via[i]
		}
		for i := range via {
			via[i].Hops = i + 1
		}
		out = append(out, Impacted{ID: id, Hops: reached[id].hops, Via: via})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Hops != out[j].Hops {
			return out[i].Hops < out[j].Hops
		}
		return out[i].ID < out[j].ID
	})
	return out
}
