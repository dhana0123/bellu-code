package lens

import (
	"fmt"
	"slices"
	"testing"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/correlate"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schemaall"
)

// Feature: unified-security-graph, Property 4: Confidence is determined by
// relation type, and a path takes its weakest hop.
//
// **Validates: Requirements 2.7, 2.8**

// registeredRelations lists the relation types of the merged registry plus
// unregistered names.
var registeredRelations = func() []string {
	r, err := schemaall.Default()
	if err != nil {
		panic(err)
	}
	out := []string{"contains", "owns", "runs"} // not registered
	for _, d := range r.Relations() {
		out = append(out, d.Name)
	}
	return out
}()

func TestConfidenceByRelationTypeProperty(t *testing.T) {
	r, _ := schemaall.Default()
	rapid.Check(t, func(t *rapid.T) {
		rel := rapid.SampledFrom(registeredRelations).Draw(t, "rel")
		want := ConfExtracted
		if d, ok := r.Relation(rel); ok {
			want = string(d.Confidence)
		}
		if got := Confidence(rel); got != want {
			t.Fatalf("Confidence(%q) = %q, want %q", rel, got, want)
		}
	})
	if Confidence("likely_same_as") != ConfInferred {
		t.Fatal("likely_same_as must be inferred")
	}
}

// Feature: aws-relationship-registry, Property 20: Edge and path confidence
//
// **Validates: Requirements 6.8, 13.6, 14.1, 14.2, 14.3, 14.4, 14.9**
func TestPropertyEdgeConfidence(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		rel := rapid.SampledFrom(registeredRelations).Draw(t, "rel")
		stored := rapid.SampledFrom([]string{"", ConfExtracted, ConfInferred, "maybe", "EXTRACTED"}).Draw(t, "stored")
		want := Confidence(rel)
		if stored == ConfExtracted || stored == ConfInferred {
			want = stored
		}
		if got := EdgeConfidence(rel, stored); got != want {
			t.Fatalf("EdgeConfidence(%q, %q) = %q, want %q", rel, stored, got, want)
		}
		hops := rapid.SliceOfN(rapid.SampledFrom(registeredRelations), 1, 6).Draw(t, "hops")
		edges := make([]SliceEdge, len(hops))
		inferred := false
		for i, h := range hops {
			edges[i] = SliceEdge{Type: h, Confidence: EdgeConfidence(h, "")}
			inferred = inferred || edges[i].Confidence == ConfInferred
		}
		if (PathConfidenceOfEdges(edges) == ConfInferred) != inferred {
			t.Fatalf("path %v confidence %s", hops, PathConfidenceOfEdges(edges))
		}
		if slices.Contains(hops, "likely_same_as") && PathConfidenceOfEdges(edges) != ConfInferred {
			t.Fatal("a path with likely_same_as must be inferred")
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

func TestPlannedRelationsUseOnlyFixedAttributesProperty(t *testing.T) {
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
			for name := range r.Attributes {
				if name != "evidence" && name != "confidence" && name != "observed_at" {
					t.Fatalf("relation %s %s->%s has attribute %q outside the fixed set", r.Type, r.From, r.To, name)
				}
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
