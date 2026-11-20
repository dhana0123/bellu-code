package query

import (
	"fmt"
	"sort"
	"testing"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/codec"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/graph"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
)

type propRel struct{ typ, from, to string }

// propGraph is a graph built by folding generated events plus the model's own
// record of what was folded.
type propGraph struct {
	g     *graph.Graph
	ids   []string
	attrs map[string]map[string]string // id -> comparable attrs (incl. identity)
	rels  map[propRel]struct{}
}

var propAttrKeys = []string{"os", "zone", "role", "password", "api_token", "Secret_Key", "arch"}

func drawPropGraph(t *rapid.T) *propGraph {
	return drawPropGraphOf(t, []string{"uses", "found_in", "t0", "t1"})
}

// drawPropGraphOf draws a graph whose relations use the given types.
func drawPropGraphOf(t *rapid.T, types []string) *propGraph {
	n := rapid.IntRange(1, 9).Draw(t, "entities")
	pg := &propGraph{g: graph.New(), attrs: map[string]map[string]string{}, rels: map[propRel]struct{}{}}
	seq := uint64(0)
	for i := 0; i < n; i++ {
		host := fmt.Sprintf("h%d", i)
		id, err := ident.Hash("host", map[string]string{"hostname": host})
		if err != nil {
			t.Fatal(err)
		}
		attrs := map[string]codec.Value{}
		cmp := map[string]string{"hostname": host}
		for _, k := range propAttrKeys {
			if rapid.Bool().Draw(t, "has-"+k) {
				v := rapid.SampledFrom([]string{"a", "b"}).Draw(t, "val-"+k)
				attrs[k] = codec.Value{T: codec.TagString, S: v}
				cmp[k] = v
			}
		}
		seq++
		pg.g.Fold(codec.Event{Seq: seq, Type: codec.EntityCreated, Collector: "c", Kind: "host",
			Identity: map[string]string{"hostname": host}, Attrs: attrs})
		pg.ids = append(pg.ids, id)
		pg.attrs[id] = cmp
	}
	m := rapid.IntRange(0, 16).Draw(t, "relations")
	for i := 0; i < m; i++ {
		r := propRel{
			rapid.SampledFrom(types).Draw(t, "type"),
			rapid.SampledFrom(pg.ids).Draw(t, "from"),
			rapid.SampledFrom(pg.ids).Draw(t, "to"),
		}
		seq++
		pg.g.Fold(codec.Event{Seq: seq, Type: codec.RelationAdded, Collector: "c", RelType: r.typ, From: r.from, To: r.to})
		pg.rels[r] = struct{}{}
	}
	return pg
}

// undirected adjacency from the model relation set.
func (pg *propGraph) undirected() map[string]map[string]bool {
	adj := map[string]map[string]bool{}
	for _, id := range pg.ids {
		adj[id] = map[string]bool{}
	}
	for r := range pg.rels {
		adj[r.from][r.to] = true
		adj[r.to][r.from] = true
	}
	return adj
}

// bfsDist is a brute-force BFS distance map (unreachable ids absent).
func bfsDist(adj map[string]map[string]bool, src string) map[string]int {
	dist := map[string]int{src: 0}
	q := []string{src}
	for len(q) > 0 {
		x := q[0]
		q = q[1:]
		for y := range adj[x] {
			if _, ok := dist[y]; !ok {
				dist[y] = dist[x] + 1
				q = append(q, y)
			}
		}
	}
	return dist
}

// Feature: bellu-graph-native, Property 16: Shortest path and definite non-connection
//
// Validates: Requirements 8.4, 8.5
func TestPropShortestPath(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		pg := drawPropGraph(t)
		a := rapid.SampledFrom(pg.ids).Draw(t, "a")
		b := rapid.SampledFrom(pg.ids).Draw(t, "b")
		maxDepth := rapid.IntRange(0, 7).Draw(t, "maxDepth")
		adj := pg.undirected()
		dist := bfsDist(adj, a)
		res := ShortestPath(pg.g, a, b, maxDepth, nil)

		d, reach := dist[b]
		if reach && d <= maxDepth {
			if !res.Found {
				t.Fatalf("model distance %d <= %d but not found", d, maxDepth)
			}
			if len(res.Path) != d {
				t.Fatalf("path length %d, model distance %d", len(res.Path), d)
			}
			cur := a
			for i, e := range res.Path {
				if _, ok := pg.rels[propRel{e.Type, e.From, e.To}]; !ok {
					t.Fatalf("edge %d not in graph: %+v", i, e)
				}
				switch cur {
				case e.From:
					cur = e.To
				case e.To:
					cur = e.From
				default:
					t.Fatalf("edge %d does not share endpoint with %s: %+v", i, cur, e)
				}
			}
			if cur != b {
				t.Fatalf("path ends at %s, want %s", cur, b)
			}
			return
		}
		if res.Found {
			t.Fatalf("found a path but model distance is %d (reach=%v, max %d)", d, reach, maxDepth)
		}
		ecc := 0
		for _, v := range dist {
			if v > ecc {
				ecc = v
			}
		}
		if want := ecc <= maxDepth; res.Exhausted != want {
			t.Fatalf("exhausted=%v, want %v (eccentricity %d, max %d)", res.Exhausted, want, ecc, maxDepth)
		}

		// Shared neighbors and attributes are plain set intersections.
		nb := func(x string) map[string]bool {
			s := map[string]bool{}
			for y := range adj[x] {
				s[y] = true
			}
			return s
		}
		na, nbb := nb(a), nb(b)
		want := []string{}
		for y := range na {
			if nbb[y] && y != a && y != b {
				want = append(want, y)
			}
		}
		sort.Strings(want)
		got := SharedNeighbors(pg.g, a, b, nil)
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("shared neighbors %v, want %v", got, want)
		}
		wantAttrs := map[string]string{}
		for k, v := range pg.attrs[a] {
			if w, ok := pg.attrs[b][k]; ok && w == v && !secretNamed(k) {
				wantAttrs[k] = v
			}
		}
		gotAttrs := SharedAttributes(pg.g, a, b)
		if fmt.Sprint(gotAttrs) != fmt.Sprint(wantAttrs) {
			t.Fatalf("shared attrs %v, want %v", gotAttrs, wantAttrs)
		}
	})
}

// secretNamed is the naive secret-name rule: the key (lowercased) contains one
// of the documented fragments.
func secretNamed(k string) bool {
	l := []byte(k)
	for i, c := range l {
		if c >= 'A' && c <= 'Z' {
			l[i] = c + 32
		}
	}
	s := string(l)
	for _, f := range []string{"secret", "token", "password", "passwd", "credential", "private", "apikey", "api_key", "hash"} {
		for i := 0; i+len(f) <= len(s); i++ {
			if s[i:i+len(f)] == f {
				return true
			}
		}
	}
	return false
}

// Feature: bellu-graph-native, Property 17: Impact follows declared directions
//
// Validates: Requirements 8.6, 8.7
func TestPropImpactDirections(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		pg := drawPropGraph(t)
		dirs := map[string]ident.Direction{}
		for _, ty := range []string{"uses", "found_in", "t0", "t1"} {
			dirs[ty] = rapid.SampledFrom([]ident.Direction{ident.Forward, ident.Reverse}).Draw(t, "dir-"+ty)
		}
		dirOf := func(ty string) ident.Direction { return dirs[ty] }
		start := rapid.SampledFrom(pg.ids).Draw(t, "start")
		depth := rapid.IntRange(0, 7).Draw(t, "depth")

		// Model: directed flow edges x -> y.
		flow := map[string]map[string]bool{}
		for _, id := range pg.ids {
			flow[id] = map[string]bool{}
		}
		for r := range pg.rels {
			if dirs[r.typ] == ident.Forward {
				flow[r.from][r.to] = true
			} else {
				flow[r.to][r.from] = true
			}
		}
		dist := bfsDist(flow, start)
		want := map[string]int{}
		for id, d := range dist {
			if id != start && d >= 1 && d <= depth {
				want[id] = d
			}
		}

		got := Impact(pg.g, start, depth, dirOf, nil)
		if len(got) != len(want) {
			t.Fatalf("impact returned %d entities, model %d (%v)", len(got), len(want), want)
		}
		for _, im := range got {
			if d, ok := want[im.ID]; !ok || d != im.Hops {
				t.Fatalf("entity %s hops %d, model %d (present %v)", im.ID, im.Hops, d, ok)
			}
			if len(im.Via) != im.Hops {
				t.Fatalf("via length %d != hops %d", len(im.Via), im.Hops)
			}
			cur := start
			for i, e := range im.Via {
				if _, ok := pg.rels[propRel{e.Type, e.From, e.To}]; !ok {
					t.Fatalf("via edge not in graph: %+v", e)
				}
				from, to := e.From, e.To
				if dirs[e.Type] == ident.Reverse {
					from, to = e.To, e.From
				}
				if from != cur {
					t.Fatalf("via edge %d does not flow from %s: %+v", i, cur, e)
				}
				cur = to
			}
			if cur != im.ID {
				t.Fatalf("via ends at %s, want %s", cur, im.ID)
			}
		}
	})
}

// Feature: aws-relationship-registry, Property 25: Impact follows registered directions only
//
// Validates: Requirements 13.1
func TestPropImpactRegisteredDirections(t *testing.T) {
	types := []string{"aws_in_vpc", "aws_routes_to", "aws_rule_of", "aws_member_of_sg", "aws_allows_ingress_from", "runs_on"}
	rapid.Check(t, func(t *rapid.T) {
		pg := drawPropGraphOf(t, types)
		start := rapid.SampledFrom(pg.ids).Draw(t, "start")
		depth := rapid.IntRange(1, 6).Draw(t, "depth")
		dirOf := func(ty string) ident.Direction {
			d, _ := ident.DirectionOf(ty)
			return d
		}
		flow := map[string]map[string]bool{}
		for _, id := range pg.ids {
			flow[id] = map[string]bool{}
		}
		for r := range pg.rels {
			if dirOf(r.typ) == ident.Forward {
				flow[r.from][r.to] = true
			} else {
				flow[r.to][r.from] = true
			}
		}
		dist := bfsDist(flow, start)
		got := Impact(pg.g, start, depth, dirOf, nil)
		reached := map[string]bool{}
		for _, im := range got {
			reached[im.ID] = true
			if d, ok := dist[im.ID]; !ok || d != im.Hops {
				t.Fatalf("%s reached in %d hops, registered directions give %d (%v)", im.ID, im.Hops, d, ok)
			}
		}
		for id, d := range dist {
			if id != start && d <= depth && !reached[id] {
				t.Fatalf("%s is %d hops downstream but not reached", id, d)
			}
		}
	})
}
