package query

import (
	"sort"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/graph"
)

// Traversal directions.
const (
	DirOut  = "out"
	DirIn   = "in"
	DirBoth = "both"
)

// MaxDepth bounds the Neighbors depth.
const MaxDepth = 10

// Edge is a relation reached by a traversal. Direction is relative to the
// step that first reached it ("out": followed From to To).
type Edge struct {
	Type      string
	From, To  graph.EntityID
	Direction string
	Hops      int
	Derived   bool
}

// DerivedFn returns the derived edges incident to id (from or to equal to
// id). A nil DerivedFn means stored relations only.
type DerivedFn func(id graph.EntityID) []Edge

// Neighbors is a level-order BFS from start limited to depth levels. Each
// reachable relation is returned once, at the fewest hops at which it is
// seen, ordered by (hops, type, from, to). Within a level the frontier is
// expanded in Entity_ID order, so the reported Direction is deterministic.
// dir is "out", "in" or "both"; relType, when set, keeps one relation type.
func Neighbors(g Reader, start graph.EntityID, dir, relType string, depth int, derived DerivedFn) []Edge {
	type key struct {
		t, f, to string
	}
	seen := map[key]struct{}{}
	visited := map[graph.EntityID]struct{}{start: {}}
	frontier := []graph.EntityID{start}
	var out []Edge
	wantOut, wantIn := dir != DirIn, dir != DirOut
	for hops := 1; hops <= depth && len(frontier) > 0; hops++ {
		sort.Strings(frontier)
		var next []graph.EntityID
		visit := func(x graph.EntityID, e Edge, direction string) {
			if relType != "" && e.Type != relType {
				return
			}
			k := key{e.Type, e.From, e.To}
			if _, ok := seen[k]; ok {
				return
			}
			seen[k] = struct{}{}
			e.Direction, e.Hops = direction, hops
			out = append(out, e)
			far := e.To
			if direction == DirIn {
				far = e.From
			}
			if _, ok := visited[far]; !ok {
				visited[far] = struct{}{}
				next = append(next, far)
			}
		}
		for _, x := range frontier {
			if wantOut {
				for _, r := range g.RelationsFrom(x) {
					visit(x, Edge{Type: r.Type, From: r.From, To: r.To}, DirOut)
				}
			}
			if wantIn {
				for _, r := range g.RelationsTo(x) {
					visit(x, Edge{Type: r.Type, From: r.From, To: r.To}, DirIn)
				}
			}
			if derived != nil {
				for _, d := range derived(x) {
					d.Derived = true
					switch {
					case d.From == x && wantOut:
						visit(x, d, DirOut)
					case d.To == x && wantIn:
						visit(x, d, DirIn)
					}
				}
			}
		}
		frontier = next
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Hops != b.Hops {
			return a.Hops < b.Hops
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.From != b.From {
			return a.From < b.From
		}
		return a.To < b.To
	})
	return out
}
