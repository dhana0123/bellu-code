package seek

import (
	"encoding/json"
	"reflect"
	"testing"

	"pgregory.net/rapid"
)

// Feature: bellu-seek-planner, Property 3: Unit filtering keeps valid units in order
// **Validates: Requirements 3.4, 3.5**
func TestPropertyUnitFilteringKeepsValidUnitsInOrder(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		kinds := rapid.SliceOfN(rapid.SampledFrom([]string{"valid", "malformed", "duplicate"}), 0, 20).Draw(t, "kinds")
		malformed := rapid.OneOf(
			rapid.StringMatching(`[A-Za-z0-9 _-]{0,10}`),
			rapid.StringMatching(`CWE-[0-9]{6,8}`),
			rapid.StringMatching(`cwe-[0-9]{1,5}`),
			rapid.StringMatching(`CWE-[0-9]{1,5}[a-z ]{1,3}`),
			rapid.StringMatching(`CWE-`),
		).Filter(func(s string) bool { return !cweIDPattern.MatchString(s) })

		var (
			units    []map[string]any
			want     []Unit
			wantDrop = map[int]bool{}
			used     = map[string]bool{}
			firsts   []string
		)
		for i, k := range kinds {
			var id string
			switch {
			case k == "duplicate" && len(firsts) > 0:
				id = rapid.SampledFrom(firsts).Draw(t, "dup")
				wantDrop[i] = true
			case k == "malformed":
				id = malformed.Draw(t, "malformed")
				wantDrop[i] = true
			default: // valid first occurrence (also a duplicate slot with nothing to repeat)
				if len(firsts) >= MaxWeaknesses {
					id = malformed.Draw(t, "malformed")
					wantDrop[i] = true
					break
				}
				id = rapid.StringMatching(`CWE-[0-9]{1,5}`).
					Filter(func(s string) bool { return !used[s] }).Draw(t, "valid")
				used[id] = true
				firsts = append(firsts, id)
				u := Unit{CWEID: id, RootCause: "rc" + id, Snippet: "x()" + id}
				want = append(want, u)
				units = append(units, unit(id))
				units[len(units)-1]["root_cause"], units[len(units)-1]["code_snippet"] = u.RootCause, u.Snippet
				continue
			}
			units = append(units, unit(id))
			// Distinct payload so a kept duplicate would be detectable by content.
			units[len(units)-1]["root_cause"] = "dropped"
		}

		body, err := json.Marshal(plan(units...))
		if err != nil {
			t.Fatal(err)
		}
		got, rejected, issues := ParsePlan(body)
		if len(issues) != 0 {
			t.Fatalf("unexpected issues: %v", issues)
		}
		if len(want) == 0 {
			want = []Unit{}
		}
		if !reflect.DeepEqual(got.Weaknesses, want) {
			t.Fatalf("accepted units = %+v, want %+v", got.Weaknesses, want)
		}
		if len(rejected) != len(wantDrop) {
			t.Fatalf("rejected %d units, want %d: %+v", len(rejected), len(wantDrop), rejected)
		}
		seen := map[int]bool{}
		for _, d := range rejected {
			if !wantDrop[d.Index] || seen[d.Index] {
				t.Fatalf("unexpected or repeated rejected index %d in %+v", d.Index, rejected)
			}
			seen[d.Index] = true
			if d.Reason == "" {
				t.Fatalf("rejected index %d has no reason", d.Index)
			}
		}
	})
}
