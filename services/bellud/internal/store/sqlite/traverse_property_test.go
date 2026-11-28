package sqlite

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// Feature: bellu-three-graph-security-intelligence, Property 36: SQLite
// recursive CTE equivalence.
//
// **Validates: Requirements 18.7, 18.8**

type refEdge struct {
	to   string
	conf float64
}

type refPath struct {
	nodes  []string
	weight float64
}

// enumerate lists every simple path from source with at most maxDepth edges,
// plus the number of simple paths with exactly maxDepth+1 edges.
func enumerate(adj map[string][]refEdge, source string, maxDepth int) (paths []refPath, beyond int) {
	var walk func(nodes []string, w float64)
	walk = func(nodes []string, w float64) {
		depth := len(nodes) - 1
		if depth > maxDepth {
			beyond++
			return
		}
		paths = append(paths, refPath{append([]string(nil), nodes...), w})
		last := nodes[len(nodes)-1]
		for _, e := range adj[last] {
			seen := false
			for _, n := range nodes {
				if n == e.to {
					seen = true
					break
				}
			}
			if !seen {
				walk(append(nodes, e.to), w-math.Log(math.Max(e.conf, 1e-6)))
			}
		}
	}
	walk([]string{source}, 0)
	// Same order as the store: depth, then the comma-joined path string.
	key := func(p refPath) string { return "," + strings.Join(p.nodes, ",") + "," }
	sort.Slice(paths, func(i, j int) bool {
		if len(paths[i].nodes) != len(paths[j].nodes) {
			return len(paths[i].nodes) < len(paths[j].nodes)
		}
		return key(paths[i]) < key(paths[j])
	})
	return paths, beyond
}

func TestPropertyTraverseEquivalence(t *testing.T) {
	s, ctx := openTest(t), context.Background()
	nodes := []string{"a", "b", "c", "d", "e", "f"}

	rapid.Check(t, func(rt *rapid.T) {
		if _, err := s.DB().Exec(`DELETE FROM relation`); err != nil {
			rt.Fatal(err)
		}
		adj := map[string][]refEdge{}
		for _, from := range nodes {
			for _, to := range nodes {
				if !rapid.Bool().Draw(rt, fmt.Sprintf("edge_%s_%s", from, to)) {
					continue
				}
				conf := rapid.Float64Range(0.01, 1).Draw(rt, "confidence")
				_, err := s.DB().Exec(`INSERT INTO relation(workspace_id,id,type,from_id,to_id,state,confidence,method,recorded_at,valid_from,observed_at,source_revision)
					VALUES('ws1',?,'calls',?,?,'confirmed',?,'static','x','2024-01-01','x','r')`, from+">"+to, from, to, conf)
				if err != nil {
					rt.Fatal(err)
				}
				adj[from] = append(adj[from], refEdge{to, conf})
			}
		}
		source := rapid.SampledFrom(nodes).Draw(rt, "source")
		maxDepth := rapid.IntRange(1, 7).Draw(rt, "maxDepth")
		rowCap := rapid.IntRange(1, 60).Draw(rt, "rowCap")

		want, beyond := enumerate(adj, source, maxDepth)
		wantTrunc, wantLimit := false, LimitNone
		switch {
		case len(want) > rowCap:
			want, wantTrunc, wantLimit = want[:rowCap], true, LimitRowCap
		case beyond > 0:
			wantTrunc, wantLimit = true, LimitDepth
		}

		got, err := s.Traverse(ctx, source, TraverseOptions{MaxDepth: maxDepth, RowCap: rowCap})
		if err != nil {
			rt.Fatal(err)
		}
		if got.Truncated != wantTrunc || got.Limit != wantLimit {
			rt.Fatalf("truncation: got (%v,%q) want (%v,%q)", got.Truncated, got.Limit, wantTrunc, wantLimit)
		}
		if len(got.Rows) != len(want) {
			rt.Fatalf("row count: got %d want %d", len(got.Rows), len(want))
		}
		for i, r := range got.Rows {
			if strings.Join(r.Path, ",") != strings.Join(want[i].nodes, ",") {
				rt.Fatalf("row %d path: got %v want %v", i, r.Path, want[i].nodes)
			}
			seen := map[string]bool{}
			for _, n := range r.Path {
				if seen[n] {
					rt.Fatalf("row %d revisits %s: %v", i, n, r.Path)
				}
				seen[n] = true
			}
			if r.Depth != len(r.Path)-1 || r.Node != r.Path[len(r.Path)-1] {
				rt.Fatalf("row %d inconsistent: %+v", i, r)
			}
			if math.Abs(r.Weight-want[i].weight) > 1e-9 {
				rt.Fatalf("row %d weight: got %v want %v", i, r.Weight, want[i].weight)
			}
		}
	})
}
