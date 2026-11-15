package lens

import (
	"reflect"
	"testing"

	"pgregory.net/rapid"
)

// Feature: unified-security-graph, Property 13: Pruned slices have no dangling edges
// Validates: Requirements 7.2, 7.9
func TestPropertyPruneNoDanglingEdges(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		ids := rapid.SliceOfNDistinct(rapid.StringMatching(`[a-h]`), 0, 8, func(s string) string { return s }).Draw(t, "ids")
		// Edge endpoints may reference ids outside the node universe.
		endpoint := rapid.SampledFrom(append([]string{"x", "y"}, ids...))
		edges := rapid.SliceOf(rapid.Custom(func(t *rapid.T) SliceEdge {
			return SliceEdge{From: endpoint.Draw(t, "from"), To: endpoint.Draw(t, "to")}
		})).Draw(t, "edges")

		kept := map[string]bool{}
		var nodes []Node
		for _, id := range ids {
			if rapid.Bool().Draw(t, "exclude "+id) {
				continue
			}
			kept[id] = true
			nodes = append(nodes, Node{ID: id})
		}

		got := Prune(nodes, edges)

		want := []SliceEdge{}
		for _, e := range edges {
			if kept[e.From] && kept[e.To] {
				want = append(want, e)
			}
		}
		for _, e := range got {
			if !kept[e.From] || !kept[e.To] {
				t.Fatalf("dangling edge %+v", e)
			}
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})
}
