package lens

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// Feature: bellu-three-graph-security-intelligence, Property 21: Existing
// contracts unchanged (weakest-hop path confidence and lens answers).
//
// The fixtures in testdata/contract use only relation types registered before
// the code schema existed. They run against the merged registry, which now
// includes the code kinds and relations.
//
// **Validates: Requirements 23.2, 23.3, 23.6**

type pathFixture struct {
	Name string   `json:"name"`
	Hops []string `json:"hops"`
	Want string   `json:"want"`
}

type budgetFixture struct {
	Name     string          `json:"name"`
	MaxNodes int             `json:"maxNodes"`
	MaxEdges int             `json:"maxEdges"`
	Root     string          `json:"root"`
	Slice    json.RawMessage `json:"slice"`
	// Want is the recorded answer: the budgeted slice in compact JSON.
	Want string `json:"want"`
}

func readFixtures[T any](t *testing.T, name string) []T {
	t.Helper()
	b, err := os.ReadFile("testdata/contract/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var out []T
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatalf("%s has no fixtures", name)
	}
	return out
}

// firstDiff describes the first differing byte of a and b, or "" when equal.
func firstDiff(got, want string) string {
	if got == want {
		return ""
	}
	n := min(len(got), len(want))
	for i := 0; i < n; i++ {
		if got[i] != want[i] {
			lo := max(0, i-20)
			return fmt.Sprintf("byte %d: got %q, want %q", i, got[lo:min(len(got), i+20)], want[lo:min(len(want), i+20)])
		}
	}
	return fmt.Sprintf("length: got %d bytes, want %d bytes", len(got), len(want))
}

func TestContractPathConfidenceWeakestHop(t *testing.T) {
	var diffs []string
	for _, f := range readFixtures[pathFixture](t, "path_confidence.json") {
		edges := make([]SliceEdge, len(f.Hops))
		hopConf := make([]string, len(f.Hops))
		for i, h := range f.Hops {
			hopConf[i] = Confidence(h)
			edges[i] = SliceEdge{Type: h, Confidence: hopConf[i]}
		}
		if got := PathConfidence(hopConf); got != f.Want {
			diffs = append(diffs, fmt.Sprintf("path fixture %s: PathConfidence = %q, want %q", f.Name, got, f.Want))
		}
		if got := PathConfidenceOfEdges(edges); got != f.Want {
			diffs = append(diffs, fmt.Sprintf("path fixture %s: PathConfidenceOfEdges = %q, want %q", f.Name, got, f.Want))
		}
	}
	if len(diffs) > 0 {
		t.Fatalf("%d difference(s):\n%s", len(diffs), strings.Join(diffs, "\n"))
	}
}

func TestContractLensAnswersByteIdentical(t *testing.T) {
	var diffs []string
	for _, f := range readFixtures[budgetFixture](t, "lens_budget.json") {
		var s Slice
		if err := json.Unmarshal(f.Slice, &s); err != nil {
			t.Fatalf("%s: %v", f.Name, err)
		}
		s.Root = f.Root
		b, err := json.Marshal(Budget(s, f.MaxNodes, f.MaxEdges))
		if err != nil {
			t.Fatal(err)
		}
		if d := firstDiff(string(b), f.Want); d != "" {
			diffs = append(diffs, fmt.Sprintf("lens fixture %s: first difference at %s", f.Name, d))
		}
	}
	if len(diffs) > 0 {
		t.Fatalf("%d difference(s):\n%s", len(diffs), strings.Join(diffs, "\n"))
	}
}

func TestContractFirstDiffNamesValue(t *testing.T) {
	if d := firstDiff(`{"a":1}`, `{"a":2}`); !strings.Contains(d, "byte 5") {
		t.Fatal(d)
	}
	if firstDiff("x", "x") != "" {
		t.Fatal("equal strings reported as different")
	}
}
