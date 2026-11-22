package seek

import (
	"fmt"
	"testing"

	"pgregory.net/rapid"
)

// Feature: bellu-seek-planner, Property 5: Scope stays within descendants, bounded and ordered
// **Validates: Requirements 5.1, 5.3, 5.6, 5.8**
func TestPropScopeBounds(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// A small id pool makes cycles, shared parents and unrelated nodes common.
		nodes := rapid.IntRange(2, 90).Draw(t, "nodes")
		id := func(n int) string { return fmt.Sprintf("CWE-%d", n*7+1) }
		node := rapid.IntRange(0, nodes-1)

		edgeGen := rapid.Custom(func(t *rapid.T) Edge {
			if rapid.IntRange(0, 9).Draw(t, "junk") == 0 {
				return Edge{
					Child:  rapid.SampledFrom([]string{"", "CWE-", "CWE-123456", "cwe-5", "CWE-1/2", id(0)}).Draw(t, "badChild"),
					Parent: id(node.Draw(t, "p")),
				}
			}
			return Edge{Child: id(node.Draw(t, "c")), Parent: id(node.Draw(t, "p"))}
		})
		edges := rapid.SliceOfN(edgeGen, 0, 400).Draw(t, "edges")
		predicted := id(node.Draw(t, "predicted"))
		maxDepth := rapid.IntRange(0, 3).Draw(t, "maxDepth")

		got := BuildScope(predicted, edges, maxDepth)

		// Reference distances by relaxation over valid edges, parent to child.
		dist := map[string]int{predicted: 0}
		for changed := true; changed; {
			changed = false
			for _, e := range edges {
				if !scopeIDPattern.MatchString(e.Child) || !scopeIDPattern.MatchString(e.Parent) {
					continue
				}
				d, ok := dist[e.Parent]
				if !ok || d+1 > maxDepth {
					continue
				}
				if old, seen := dist[e.Child]; !seen || d+1 < old {
					dist[e.Child] = d + 1
					changed = true
				}
			}
		}

		if len(got.CWEs) == 0 || got.CWEs[0] != predicted || got.Predicted != predicted {
			t.Fatalf("predicted must come first: %v", got.CWEs)
		}
		if len(got.CWEs) > MaxScope {
			t.Fatalf("scope has %d CWEs, max %d", len(got.CWEs), MaxScope)
		}
		if len(got.Depth) != len(got.CWEs) {
			t.Fatalf("Depth has %d entries for %d CWEs", len(got.Depth), len(got.CWEs))
		}
		if want := min(len(dist), MaxScope); len(got.CWEs) != want {
			t.Fatalf("scope has %d CWEs, want %d", len(got.CWEs), want)
		}
		seen := map[string]bool{}
		expanded := false
		for i, c := range got.CWEs {
			if seen[c] {
				t.Fatalf("duplicate %s in %v", c, got.CWEs)
			}
			seen[c] = true
			d, ok := dist[c]
			if !ok {
				t.Fatalf("%s is not a descendant of %s within depth %d", c, predicted, maxDepth)
			}
			if got.Depth[c] != d {
				t.Fatalf("depth of %s = %d, want shortest %d", c, got.Depth[c], d)
			}
			if d >= 2 {
				expanded = true
			}
			if i >= 2 && cweNumber(got.CWEs[i-1]) >= cweNumber(c) {
				t.Fatalf("not ascending after predicted: %v", got.CWEs)
			}
		}
		if got.Expanded != expanded {
			t.Fatalf("Expanded = %v, want %v", got.Expanded, expanded)
		}
		// With no truncation, every reachable CWE is present.
		if len(dist) <= MaxScope {
			for c := range dist {
				if !seen[c] {
					t.Fatalf("missing descendant %s", c)
				}
			}
		}
	})
}
