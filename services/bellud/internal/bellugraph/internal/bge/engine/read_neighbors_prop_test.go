package engine

import (
	"context"
	"sort"
	"testing"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/internal/gen/model"
)

// naiveNeighbors computes the reachable relations of start by entity-level
// BFS over the model's live relations: a relation's hop count is one more
// than the distance of the nearest endpoint it can be followed from.
func naiveNeighbors(rels []model.RelKey, start, dir, relType string, depth int) map[model.RelKey]int {
	var use []model.RelKey
	for _, r := range rels {
		if relType == "" || r.Type == relType {
			use = append(use, r)
		}
	}
	wantOut, wantIn := dir != DirIn, dir != DirOut
	dist := map[string]int{start: 0}
	queue := []string{start}
	for len(queue) > 0 {
		x := queue[0]
		queue = queue[1:]
		if dist[x] >= depth {
			continue
		}
		for _, r := range use {
			for _, far := range []struct {
				ok          bool
				near, other string
			}{{wantOut, r.From, r.To}, {wantIn, r.To, r.From}} {
				if _, seen := dist[far.other]; far.ok && far.near == x && !seen {
					dist[far.other] = dist[x] + 1
					queue = append(queue, far.other)
				}
			}
		}
	}
	out := map[model.RelKey]int{}
	for _, r := range use {
		h := depth + 1
		if d, ok := dist[r.From]; ok && wantOut && d+1 < h {
			h = d + 1
		}
		if d, ok := dist[r.To]; ok && wantIn && d+1 < h {
			h = d + 1
		}
		if h <= depth {
			out[r] = h
		}
	}
	return out
}

// Feature: bellu-graph-native, Property 15: Neighbors equal naive BFS
// Validates: Requirements 6.4, 12.6
func TestPropNeighborsNaiveBFS(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		f := buildPropFixture(t, false)
		ms := f.m.Current()
		live := ms.LiveIDs()
		if len(live) == 0 {
			return
		}
		start := rapid.SampledFrom(live).Draw(t, "start")
		dir := rapid.SampledFrom([]string{DirOut, DirIn, DirBoth}).Draw(t, "dir")
		relType := rapid.SampledFrom(append([]string{""}, append(ident.RelationTypes(), "custom_link", "talks_to")...)).Draw(t, "relType")
		depth := rapid.IntRange(1, 10).Draw(t, "depth")
		size := pageSize(t)

		hops := naiveNeighbors(ms.LiveRels(), start, dir, relType, depth)
		want := make([]model.RelKey, 0, len(hops))
		for r := range hops {
			want = append(want, r)
		}
		sort.Slice(want, func(i, j int) bool {
			a, b := want[i], want[j]
			if hops[a] != hops[b] {
				return hops[a] < hops[b]
			}
			if a.Type != b.Type {
				return a.Type < b.Type
			}
			if a.From != b.From {
				return a.From < b.From
			}
			return a.To < b.To
		})
		got, total := walkPages(t, size, func(cursor string) (Page[EdgeView], error) {
			return f.c.Neighbors(context.Background(), start, NeighborOpts{
				Direction: dir, RelationType: relType, Depth: depth, Paging: Paging{PageSize: size, Cursor: cursor},
			}, nil)
		})
		if total != len(want) {
			t.Fatalf("Total %d, model %d", total, len(want))
		}
		for i, w := range want {
			g := got[i]
			if g.Type != w.Type || g.From != w.From || g.To != w.To || g.Hops != hops[w] || g.Derived {
				t.Fatalf("edge %d: got %+v, model %+v at %d hops", i, g, w, hops[w])
			}
			if dir != DirBoth && g.Direction != dir {
				t.Fatalf("edge %d: direction %q for %q traversal", i, g.Direction, dir)
			}
		}
	})
}
