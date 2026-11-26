package posture

import (
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
)

func TestFindingTypeAICategoryIsAIRisk(t *testing.T) {
	if got := findingType(Rule{Category: schema.OvAI}); got != findings.TypeAIRisk {
		t.Fatalf("got %q, want ai_risk", got)
	}
}
