package plan_test

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/graph"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/internal/gen"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/plan"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

// Feature: aws-relationship-registry, Property 6: Edge attribute validation is all or nothing
//
// Validates: Requirements 6.1, 6.2, 6.3, 6.4, 6.5, 6.9, 16.4

var eaAllowed = map[string]bool{"evidence": true, "confidence": true, "observed_at": true}

// eaSeed returns a graph holding entities, a relation with attributes and a
// non-zero last sequence.
func eaSeed(t *rapid.T) *graph.Graph {
	g := graph.New()
	b := batch.Batch{
		Collector: "seed",
		Entities:  []batch.Entity{host("a", nil), host("b", map[string]any{"state": "up"}), host("c", nil)},
		Relations: []batch.Relation{{
			Type: "depends_on", From: hid("a"), To: hid("b"),
			Attributes: map[string]any{"evidence": "seed", "confidence": "extracted"},
		}},
	}
	r, err := plan.Plan(g, b, plan.ModeFull, t0)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	for _, ev := range r.Events {
		ev.Seq = g.LastSeq + 1
		ev.RecordedNS = t0.UnixNano()
		g.Fold(ev)
	}
	if g.LastSeq == 0 || g.RelationCount() == 0 {
		t.Fatalf("seed graph is empty")
	}
	return g
}

// eaBatch asserts the seeded relation with attrs, plus a new relation and a
// new entity that would be valid on their own.
func eaBatch(attrs map[string]any) batch.Batch {
	return batch.Batch{
		Collector: "seed",
		Entities:  []batch.Entity{host("a", nil), host("b", nil), host("d", nil)},
		Relations: []batch.Relation{
			{Type: "depends_on", From: hid("a"), To: hid("d")},
			{Type: "depends_on", From: hid("a"), To: hid("b"), Attributes: attrs},
		},
	}
}

// eaPlan plans attrs against a seeded graph. It reports the error and fails
// the test when the graph differs afterwards, whether or not planning failed.
func eaPlan(t *rapid.T, attrs map[string]any) error {
	g := eaSeed(t)
	before := g.Clone()
	seq, ents, rels := g.LastSeq, g.EntityCount(), g.RelationCount()
	_, err := plan.Plan(g, eaBatch(attrs), plan.ModeFull, t0)
	if err != nil {
		if !reflect.DeepEqual(before, g) || g.LastSeq != seq || g.EntityCount() != ents || g.RelationCount() != rels {
			t.Fatalf("stored graph changed after rejection: %v", err)
		}
	}
	return err
}

// eaAccepts asserts attrs are accepted.
func eaAccepts(t *rapid.T, attrs map[string]any) {
	t.Helper()
	if err := eaPlan(t, attrs); err != nil {
		t.Fatalf("attrs %#v rejected: %v", attrs, err)
	}
}

// eaRejects asserts attrs are rejected with a validation error that names
// every string in names.
func eaRejects(t *rapid.T, attrs map[string]any, names ...string) {
	t.Helper()
	err := eaPlan(t, attrs)
	if err == nil {
		t.Fatalf("attrs %#v accepted, want rejection", attrs)
	}
	if !errors.Is(err, errs.Validation) {
		t.Fatalf("attrs %#v: error %v is not a validation error", attrs, err)
	}
	for _, n := range names {
		if !strings.Contains(err.Error(), n) {
			t.Fatalf("attrs %#v: error %q does not name %q", attrs, err, n)
		}
	}
}

func TestEdgeAttrPropValidMapsAccepted(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		eaAccepts(t, gen.RelAttrs().Draw(t, "attrs"))
	})
}

func TestEdgeAttrPropDefectRejectedAndGraphUnchanged(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		bad := gen.BadRelAttrs().Draw(t, "bad")
		var name string
		switch bad.Defect {
		case "evidence_not_string", "evidence_too_long", "secret_value":
			name = "evidence"
		case "confidence_value", "confidence_not_string":
			name = "confidence"
		case "observed_at_format", "observed_at_not_string":
			name = "observed_at"
		}
		eaRejects(t, bad.Attributes, name)
	})
}

func TestEdgeAttrPropNameSet(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Every allowed name is accepted with a valid value.
		valid := map[string]any{"evidence": "e", "confidence": "inferred", "observed_at": "2025-01-01T00:00:00Z"}
		for n, v := range valid {
			eaAccepts(t, map[string]any{n: v})
		}
		// Every other name is rejected and named.
		name := rapid.OneOf(
			rapid.String(),
			rapid.SampledFrom([]string{"Evidence", "CONFIDENCE", "observed-at", "observedAt", "evidence ", "weight"}),
		).Filter(func(s string) bool { return !eaAllowed[s] }).Draw(t, "name")
		attrs := gen.RelAttrs().Draw(t, "attrs")
		attrs[name] = rapid.SampledFrom([]any{"x", 1, true, nil}).Draw(t, "value")
		eaRejects(t, attrs, strconv.Quote(name))
	})
}

func TestEdgeAttrPropConfidence(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		eaAccepts(t, map[string]any{"confidence": rapid.SampledFrom([]string{"extracted", "inferred"}).Draw(t, "ok")})
		s := rapid.String().Filter(func(s string) bool { return s != "extracted" && s != "inferred" }).Draw(t, "bad")
		eaRejects(t, map[string]any{"confidence": s}, "confidence")
	})
}

func TestEdgeAttrPropEvidenceLimit(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Byte boundary with ASCII.
		eaAccepts(t, map[string]any{"evidence": strings.Repeat("a", 512)})
		eaRejects(t, map[string]any{"evidence": strings.Repeat("a", 513)}, "evidence")
		// Any length around the limit, measured in bytes, with 2-byte runes.
		n := rapid.IntRange(0, 600).Draw(t, "runes")
		ev := strings.Repeat("é", n)
		if len(ev) <= 512 {
			eaAccepts(t, map[string]any{"evidence": ev})
		} else {
			eaRejects(t, map[string]any{"evidence": ev}, "evidence")
		}
		// Non-strings are rejected.
		eaRejects(t, map[string]any{"evidence": rapid.SampledFrom([]any{1, 1.5, true, nil, []string{"a"}}).Draw(t, "v")}, "evidence")
	})
}

func TestEdgeAttrPropObservedAt(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		ts := gen.ValidTime().Draw(t, "time")
		loc := time.FixedZone("z", rapid.IntRange(-14*60, 14*60).Draw(t, "offsetMin")*60)
		layout := rapid.SampledFrom([]string{time.RFC3339, time.RFC3339Nano}).Draw(t, "layout")
		s := ts.In(loc).Format(layout)
		if _, err := time.Parse(time.RFC3339, s); err != nil {
			t.Fatalf("generated %q is not RFC 3339: %v", s, err)
		}
		eaAccepts(t, map[string]any{"observed_at": s})

		bad := rapid.SampledFrom([]string{
			"", "yesterday", "2024-01-01", "2024-01-01 00:00:00", "2024-13-01T00:00:00Z",
			"2024-01-01T00:00:00", "2024-01-01T25:00:00Z", "2024-02-30T00:00:00Z",
		}).Draw(t, "bad")
		eaRejects(t, map[string]any{"observed_at": bad}, "observed_at")
		eaRejects(t, map[string]any{"observed_at": rapid.SampledFrom([]any{1, true, nil, ts}).Draw(t, "nonstr")}, "observed_at")
	})
}

func TestEdgeAttrPropSecretRejected(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		pre := rapid.StringMatching(`[a-z ]{0,10}`).Draw(t, "pre")
		suf := rapid.StringMatching(`[ a-z]{0,10}`).Draw(t, "suf")
		attrs := gen.RelAttrs().Draw(t, "attrs")
		attrs["evidence"] = pre + " AKIAABCDEFGHIJKLMNOP " + suf
		eaRejects(t, attrs, "evidence")
	})
}
