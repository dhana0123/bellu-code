package plan_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/codec"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/graph"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/plan"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

func relBatch(rels ...batch.Relation) batch.Batch {
	return batch.Batch{
		Collector: "c",
		Entities:  []batch.Entity{host("a", nil), host("b", nil)},
		Relations: rels,
	}
}

func rel(attrs map[string]any) batch.Relation {
	return batch.Relation{Type: "depends_on", From: hid("a"), To: hid("b"), Attributes: attrs}
}

func TestEdgeAttrsValidation(t *testing.T) {
	cases := []struct {
		name  string
		attrs map[string]any
		want  string // empty means accepted
	}{
		{"none", nil, ""},
		{"all valid", map[string]any{"evidence": "", "confidence": "inferred", "observed_at": "2025-01-01T00:00:00Z"}, ""},
		{"evidence at limit", map[string]any{"evidence": strings.Repeat("x", 512)}, ""},
		{"evidence over limit", map[string]any{"evidence": strings.Repeat("x", 513)}, "evidence"},
		{"evidence not string", map[string]any{"evidence": 3}, "evidence"},
		{"unknown name", map[string]any{"weight": "1"}, "weight"},
		{"confidence case", map[string]any{"confidence": "Extracted"}, "confidence"},
		{"confidence not string", map[string]any{"confidence": true}, "confidence"},
		{"observed_at bad", map[string]any{"observed_at": "yesterday"}, "observed_at"},
		{"observed_at not string", map[string]any{"observed_at": 5}, "observed_at"},
		{"secret value", map[string]any{"evidence": "key AKIAIOSFODNN7EXAMPLE"}, "evidence"},
	}
	for _, tc := range cases {
		_, err := plan.Plan(graph.New(), relBatch(rel(tc.attrs)), plan.ModeFull, t0)
		if tc.want == "" {
			if err != nil {
				t.Errorf("%s: unexpected error %v", tc.name, err)
			}
			continue
		}
		if !errors.Is(err, errs.Validation) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want validation error naming %q", tc.name, err, tc.want)
		}
	}
}

func TestEdgeAttrsAddedCarriesAttrs(t *testing.T) {
	r, err := plan.Plan(graph.New(), relBatch(rel(map[string]any{"evidence": "e", "confidence": "extracted"})), plan.ModeFull, t0)
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range r.Events {
		if ev.Type == codec.RelationAdded {
			want := codec.EdgeAttrs{Evidence: "e", Confidence: "extracted", Has: 3}
			if !ev.EdgeAttrs.Equal(want) {
				t.Fatalf("attrs = %+v, want %+v", ev.EdgeAttrs, want)
			}
			return
		}
	}
	t.Fatal("no RelationAdded event")
}

func TestEdgeAttrsDuplicateRelation(t *testing.T) {
	same := relBatch(rel(map[string]any{"evidence": "e"}), rel(map[string]any{"evidence": "e"}))
	if _, err := plan.Plan(graph.New(), same, plan.ModeFull, t0); err != nil {
		t.Fatalf("identical duplicates rejected: %v", err)
	}
	diff := relBatch(rel(map[string]any{"evidence": "e"}), rel(map[string]any{"evidence": "f"}))
	if _, err := plan.Plan(graph.New(), diff, plan.ModeFull, t0); !errors.Is(err, errs.Validation) {
		t.Fatalf("conflicting duplicates: got %v, want validation error", err)
	}
}
