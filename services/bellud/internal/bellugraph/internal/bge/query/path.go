package query

import (
	"sort"
	"strconv"
	"strings"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/codec"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/graph"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
)

// PathResult is the outcome of ShortestPath. Found is true with an empty Path
// when the two ends are the same entity. When not Found, Exhausted tells
// whether the search covered the whole connected component (true) or stopped
// at the depth bound (false); DepthSearched is the number of levels expanded.
type PathResult struct {
	Found         bool
	Path          []Edge
	Exhausted     bool
	DepthSearched int
}

// adjacent is an edge seen from one of its ends.
type adjacent struct {
	other graph.EntityID
	edge  Edge
}

// adjacents returns every edge incident to x (stored and derived) with its
// far end, ordered by (type, other, from, to), without duplicates.
func adjacents(g Reader, x graph.EntityID, derived DerivedFn) []adjacent {
	var l []adjacent
	for _, r := range g.RelationsFrom(x) {
		l = append(l, adjacent{r.To, Edge{Type: r.Type, From: r.From, To: r.To, Direction: DirOut}})
	}
	for _, r := range g.RelationsTo(x) {
		l = append(l, adjacent{r.From, Edge{Type: r.Type, From: r.From, To: r.To, Direction: DirIn}})
	}
	if derived != nil {
		for _, d := range derived(x) {
			d.Derived = true
			switch {
			case d.From == x:
				d.Direction = DirOut
				l = append(l, adjacent{d.To, d})
			case d.To == x:
				d.Direction = DirIn
				l = append(l, adjacent{d.From, d})
			}
		}
	}
	sort.SliceStable(l, func(i, j int) bool {
		a, b := l[i], l[j]
		if a.edge.Type != b.edge.Type {
			return a.edge.Type < b.edge.Type
		}
		if a.other != b.other {
			return a.other < b.other
		}
		if a.edge.From != b.edge.From {
			return a.edge.From < b.edge.From
		}
		return a.edge.To < b.edge.To
	})
	return l
}

// ShortestPath is a deterministic undirected BFS from a to b over stored and
// derived relations, searching at most maxDepth hops. Neighbors are expanded
// in (type, other ID) order, so the same graph always yields the same path.
// Path edges carry Hops 1..n and a Direction relative to the walk.
func ShortestPath(g Reader, a, b graph.EntityID, maxDepth int, derived DerivedFn) PathResult {
	if a == b {
		return PathResult{Found: true, Exhausted: true}
	}
	type parent struct {
		prev graph.EntityID
		edge Edge
	}
	parents := map[graph.EntityID]parent{}
	visited := map[graph.EntityID]struct{}{a: {}}
	frontier := []graph.EntityID{a}
	res := PathResult{}
	for depth := 1; depth <= maxDepth; depth++ {
		var next []graph.EntityID
		for _, x := range frontier {
			for _, adj := range adjacents(g, x, derived) {
				if _, ok := visited[adj.other]; ok {
					continue
				}
				visited[adj.other] = struct{}{}
				parents[adj.other] = parent{x, adj.edge}
				if adj.other == b {
					var path []Edge
					for cur := b; cur != a; cur = parents[cur].prev {
						path = append(path, parents[cur].edge)
					}
					for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
						path[i], path[j] = path[j], path[i]
					}
					for i := range path {
						path[i].Hops = i + 1
					}
					return PathResult{Found: true, Path: path, DepthSearched: depth}
				}
				next = append(next, adj.other)
			}
		}
		res.DepthSearched = depth
		if len(next) == 0 {
			res.Exhausted = true
			return res
		}
		frontier = next
	}
	// The depth bound was reached. The component is still exhausted when no
	// node of the last level has an unvisited neighbor.
	res.Exhausted = true
	for _, x := range frontier {
		for _, adj := range adjacents(g, x, derived) {
			if _, ok := visited[adj.other]; !ok {
				res.Exhausted = false
				return res
			}
		}
	}
	return res
}

// neighborSet is the set of entities adjacent to x.
func neighborSet(g Reader, x graph.EntityID, derived DerivedFn) map[graph.EntityID]struct{} {
	s := map[graph.EntityID]struct{}{}
	for _, adj := range adjacents(g, x, derived) {
		s[adj.other] = struct{}{}
	}
	return s
}

// SharedNeighbors returns, sorted, the entities adjacent to both a and b.
func SharedNeighbors(g Reader, a, b graph.EntityID, derived DerivedFn) []graph.EntityID {
	sa, sb := neighborSet(g, a, derived), neighborSet(g, b, derived)
	out := []graph.EntityID{}
	for id := range sa {
		if _, ok := sb[id]; ok && id != a && id != b {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// SharedAttributes returns the identity and descriptive attribute pairs that
// a and b hold with equal values, omitting secret-named keys.
func SharedAttributes(g Reader, a, b graph.EntityID) map[string]string {
	out := map[string]string{}
	ea, ok1 := g.Entity(a)
	eb, ok2 := g.Entity(b)
	if !ok1 || !ok2 {
		return out
	}
	pairs := func(e *graph.EntityState) map[string]string {
		m := map[string]string{}
		for k, v := range e.Attrs {
			m[k] = valueString(v)
		}
		for k, v := range e.Identity {
			m[k] = v
		}
		return m
	}
	ma, mb := pairs(ea), pairs(eb)
	for k, v := range ma {
		if w, ok := mb[k]; ok && w == v && !ident.IsSecretName(k) {
			out[k] = v
		}
	}
	return out
}

func valueString(v codec.Value) string {
	switch v.T {
	case codec.TagString:
		return v.S
	case codec.TagBool:
		return strconv.FormatBool(v.B)
	case codec.TagInt:
		return strconv.FormatInt(v.I, 10)
	case codec.TagFloat:
		return strconv.FormatFloat(v.F, 'g', -1, 64)
	case codec.TagList:
		return strings.Join(v.L, ",")
	}
	return ""
}
