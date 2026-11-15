package lens

import (
	"fmt"
	"testing"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/correlate"
)

// Feature: unified-security-graph, Property 4: Confidence is determined by
// relation type, and a path takes its weakest hop.
//
// **Validates: Requirements 2.7, 2.8**

// registeredRelations mirrors the relation registry (bge/ident, which is
// internal to bellugraph and not importable here).
var registeredRelations = []string{
	"contains", "owns", "runs", "uses", "attached_to", "mounts", "depends_on",
	"resolves_to", "found_in", "affected_by", "same_as", "likely_same_as",
}

func TestConfidenceByRelationTypeProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		rel := rapid.SampledFrom(registeredRelations).Draw(t, "rel")
		got := Confidence(rel)
		want := ConfExtracted
		if rel == "likely_same_as" {
			want = ConfInferred
		}
		if got != want {
			t.Fatalf("Confidence(%q) = %q, want %q", rel, got, want)
		}
	})
}

func TestPathConfidenceWeakestHopProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		hops := rapid.SliceOf(rapid.SampledFrom([]string{ConfExtracted, ConfInferred})).Draw(t, "hops")
		want := ConfExtracted
		for _, h := range hops {
			if h == ConfInferred {
				want = ConfInferred
			}
		}
		if got := PathConfidence(hops); got != want {
			t.Fatalf("PathConfidence(%v) = %q, want %q", hops, got, want)
		}

		// The same path expressed as edges whose confidence comes from type.
		edges := rapid.SliceOf(rapid.SampledFrom(registeredRelations)).Draw(t, "edgeTypes")
		se := make([]SliceEdge, len(edges))
		conf := make([]string, len(edges))
		for i, ty := range edges {
			se[i] = SliceEdge{From: fmt.Sprint(i), To: fmt.Sprint(i + 1), Type: ty, Confidence: Confidence(ty)}
			conf[i] = Confidence(ty)
		}
		if a, b := PathConfidenceOfEdges(se), PathConfidence(conf); a != b {
			t.Fatalf("PathConfidenceOfEdges = %q, PathConfidence = %q for %v", a, b, edges)
		}
	})
}

func TestPlannedRelationsHaveNoAttributesProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(0, 12).Draw(t, "n")
		ents := make([]correlate.KeyedEntity, n)
		for i := range ents {
			ents[i] = correlate.KeyedEntity{
				ID:         fmt.Sprintf("e%02d", i),
				Kind:       rapid.SampledFrom([]string{"github_repo", "aws_resource"}).Draw(t, "kind"),
				Connection: rapid.SampledFrom([]string{"c1", "c2", "c3"}).Draw(t, "conn"),
				Key:        rapid.SampledFrom([]string{"", "k1", "k2"}).Draw(t, "key"),
				Name:       rapid.SampledFrom([]string{"org/app", "app", "db"}).Draw(t, "name"),
			}
		}
		for _, r := range correlate.PlanSameAs(ents) {
			if len(r.Attributes) != 0 {
				t.Fatalf("relation %s %s->%s has attributes %v", r.Type, r.From, r.To, r.Attributes)
			}
			if r.Type != correlate.RelSameAs && r.Type != correlate.RelLikelySameAs {
				t.Fatalf("unexpected relation type %q", r.Type)
			}
			wantConf := ConfExtracted
			if r.Type == correlate.RelLikelySameAs {
				wantConf = ConfInferred
			}
			if got := Confidence(r.Type); got != wantConf {
				t.Fatalf("Confidence(%q) = %q, want %q", r.Type, got, wantConf)
			}
		}
	})
}
