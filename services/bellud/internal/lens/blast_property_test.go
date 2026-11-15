package lens

import (
	"context"
	"sort"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/facade"
	"pgregory.net/rapid"
)

// impactSource is a Source whose Impact result is fixed. Other reads return
// minimal entities; no method writes.
type impactSource struct {
	Source
	root   facade.EntityID
	result facade.ImpactResult
}

func (s impactSource) Resolve(context.Context, string) (facade.EntityID, error) { return s.root, nil }
func (s impactSource) Impact(context.Context, string, facade.ImpactOpts) (facade.ImpactResult, error) {
	return s.result, nil
}
func (s impactSource) Entity(_ context.Context, id facade.EntityID) (facade.Entity, error) {
	return facade.Entity{ID: id, Type: "service", Label: string(id)}, nil
}

// Feature: unified-security-graph, Property 14: Blast radius slice equals the impact result
// Validates: Requirements 7.3
func TestPropertyBlastRadiusSliceEqualsImpact(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		root := facade.EntityID("root")
		ids := rapid.SliceOfNDistinct(rapid.StringMatching(`n[a-h]`), 0, 8, func(s string) string { return s }).Draw(t, "ids")
		// Via hops connect the root and impacted entities only.
		universe := []facade.EntityID{root}
		for _, id := range ids {
			universe = append(universe, facade.EntityID(id))
		}
		ent := rapid.SampledFrom(universe)
		hop := rapid.Custom(func(t *rapid.T) facade.Edge {
			return facade.Edge{
				From: ent.Draw(t, "from"), To: ent.Draw(t, "to"),
				Type: rapid.SampledFrom([]string{"depends_on", "calls", "likely_same_as"}).Draw(t, "type"),
			}
		})
		var items []facade.Impacted
		wantEdges := map[SliceEdge]bool{}
		for _, id := range ids {
			via := rapid.SliceOfN(hop, 0, 3).Draw(t, "via "+id)
			for _, e := range via {
				wantEdges[SliceEdge{From: string(e.From), To: string(e.To), Type: e.Type, Confidence: Confidence(e.Type)}] = true
			}
			items = append(items, facade.Impacted{
				ID: facade.EntityID(id), Kind: "service",
				Hops: rapid.IntRange(1, 6).Draw(t, "hops "+id), Via: via,
			})
		}
		src := impactSource{root: root, result: facade.ImpactResult{Items: items}}
		s, err := NewEngine(src).Slice(context.Background(), "blast-radius", Params{Entity: "root"})
		if err != nil {
			t.Fatal(err)
		}
		if s.Truncated {
			t.Fatalf("slice unexpectedly truncated")
		}
		want := append([]string{"root"}, ids...)
		sort.Strings(want)
		var got []string
		for _, n := range s.Nodes {
			got = append(got, n.ID)
		}
		sort.Strings(got)
		if len(got) != len(want) {
			t.Fatalf("nodes %v, want %v", got, want)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("nodes %v, want %v", got, want)
			}
		}
		if len(s.Edges) != len(wantEdges) {
			t.Fatalf("edges %+v, want %v", s.Edges, wantEdges)
		}
		for _, e := range s.Edges {
			if !wantEdges[e] {
				t.Fatalf("edge %+v not from a Via hop", e)
			}
		}
	})
}
