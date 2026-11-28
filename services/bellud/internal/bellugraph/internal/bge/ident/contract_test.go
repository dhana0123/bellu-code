package ident

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Feature: bellu-three-graph-security-intelligence, Property 21: Existing
// contracts unchanged (Entity_ID golden vectors).
//
// The pre-feature baseline in testdata/golden.json is compared on its own,
// without the extension file, after the code kinds and relations are
// registered. Every difference names the fixture and the first differing value.
//
// **Validates: Requirements 23.1, 23.6**

// firstDiff returns "" when a and b are equal, else a description of the first
// differing byte.
func firstDiff(a, b string) string {
	if a == b {
		return ""
	}
	n := min(len(a), len(b))
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return fmt.Sprintf("byte %d: got %q, want %q", i, a[i], b[i])
		}
	}
	return fmt.Sprintf("length: got %d bytes, want %d bytes", len(a), len(b))
}

func loadBaseline(t *testing.T) golden {
	t.Helper()
	b, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	var g golden
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	return g
}

// contractDiffs compares the baseline against the live registry and returns one
// line per difference, in sorted fixture order.
func contractDiffs(g golden) []string {
	var out []string
	kinds := make([]string, 0, len(g.Kinds))
	for k := range g.Kinds {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		want := g.Kinds[k]
		got, err := Hash(k, want.Attrs)
		if err != nil {
			out = append(out, fmt.Sprintf("golden kind %s: %v", k, err))
			continue
		}
		if d := firstDiff(got, want.Hash); d != "" {
			out = append(out, fmt.Sprintf("golden kind %s: Entity_ID %s, first difference at %s", k, got, d))
		}
		if ids, ok := IdentityAttributes(k); !ok || !reflect.DeepEqual(ids, want.Identity) {
			out = append(out, fmt.Sprintf("golden kind %s: identity attributes %v, want %v", k, ids, want.Identity))
		}
	}
	rels := make([]string, 0, len(g.Relations))
	for r := range g.Relations {
		rels = append(rels, r)
	}
	sort.Strings(rels)
	for _, r := range rels {
		d, isDefault := DirectionOf(r)
		if isDefault || d.String() != g.Relations[r] {
			out = append(out, fmt.Sprintf("golden relation %s: direction %s (default=%v), want %s", r, d, isDefault, g.Relations[r]))
		}
	}
	return out
}

func TestContractGoldenVectorsUnchangedAfterCodeSchema(t *testing.T) {
	g := loadBaseline(t)
	if len(g.Kinds) == 0 || len(g.Relations) == 0 {
		t.Fatal("baseline golden.json is empty")
	}
	// The registration under test must be in place, or the comparison is vacuous.
	have := map[string]bool{}
	for _, k := range Kinds() {
		have[k] = true
	}
	for _, k := range []string{"code_symbol", "code_file", "code_community", "finding"} {
		if !have[k] {
			t.Fatalf("kind %s is not registered; the contract test would not cover registration", k)
		}
	}
	if diffs := contractDiffs(g); len(diffs) > 0 {
		t.Fatalf("%d difference(s) from the pre-feature baseline:\n%s", len(diffs), strings.Join(diffs, "\n"))
	}
}

// The reporter must name the fixture and the first differing value.
func TestContractDiffReportsFixtureAndValue(t *testing.T) {
	g := loadBaseline(t)
	var name string
	for k := range g.Kinds {
		if name == "" || k < name {
			name = k
		}
	}
	want := g.Kinds[name]
	want.Hash = want.Hash[:len(want.Hash)-1] + "X"
	g.Kinds[name] = want
	diffs := contractDiffs(g)
	if len(diffs) != 1 || !strings.Contains(diffs[0], "golden kind "+name) || !strings.Contains(diffs[0], "first difference at byte") {
		t.Fatalf("unexpected report: %v", diffs)
	}
}
