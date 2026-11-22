package seek

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	"pgregory.net/rapid"
)

func genUnit() *rapid.Generator[Unit] {
	return rapid.Custom(func(t *rapid.T) Unit {
		return Unit{
			CWEID:     fmt.Sprintf("CWE-%d", rapid.IntRange(0, 99999).Draw(t, "cwe_num")),
			RootCause: rapid.StringOfN(rapid.Rune(), 1, MaxRootCause, -1).Draw(t, "root_cause"),
			Snippet:   rapid.StringOfN(rapid.Rune(), 1, MaxSnippet, -1).Draw(t, "code_snippet"),
		}
	})
}

func genValidPlan() *rapid.Generator[Plan] {
	return rapid.Custom(func(t *rapid.T) Plan {
		units := rapid.SliceOfNDistinct(genUnit(), 0, MaxWeaknesses, func(u Unit) string { return u.CWEID }).Draw(t, "weaknesses")
		if units == nil {
			units = []Unit{}
		}
		return Plan{
			Language:   rapid.StringOfN(rapid.Rune(), 1, MaxLanguage, -1).Draw(t, "language"),
			Reasoning:  rapid.StringOfN(rapid.Rune(), 0, MaxReasoning, -1).Draw(t, "reasoning"),
			Weaknesses: units,
		}
	})
}

// Feature: bellu-seek-planner, Property 1: Plan round trip
// **Validates: Requirements 3.8, 12.5**
func TestPlanRoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		p := genValidPlan().Draw(t, "plan")
		b, err := p.Marshal()
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		got, rejected, issues := ParsePlan(b)
		if len(issues) > 0 || len(rejected) > 0 {
			t.Fatalf("valid plan reported issues=%v rejected=%v", issues, rejected)
		}
		if !reflect.DeepEqual(got, p) {
			t.Fatalf("round trip changed plan:\nwant %#v\ngot  %#v", p, got)
		}
		b2, err := got.Marshal()
		if err != nil {
			t.Fatalf("re-marshal: %v", err)
		}
		if !bytes.Equal(b, b2) {
			t.Fatalf("re-marshal differs:\n%s\n%s", b, b2)
		}
	})
}
