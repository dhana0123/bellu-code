package seek_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/seek"
	"github.com/bellu/bellucode/services/bellud/internal/seek/seektest"
	"pgregory.net/rapid"
)

// rtIsoCWEs have pairwise disjoint scopes in the fixtures (CWE-999 is unknown),
// so failing one unit's endpoints cannot touch the scope of another unit.
var rtIsoCWEs = []string{"CWE-79", "CWE-89", "CWE-700", "CWE-710", "CWE-720", "CWE-730", "CWE-800", "CWE-999"}

// Feature: bellu-seek-planner, Property 12: One failing unit does not affect the others
//
// **Validates: Requirements 5.4, 10.5, 12.3**
func TestPropFailureIsolation(t *testing.T) {
	fake := seektest.New(t)
	r, _ := rtRetriever(t, fake.URL, rtConfig(2*time.Second, 10*time.Second))

	// rapid runs 100 generated cases by default.
	rapid.Check(t, func(t *rapid.T) {
		cwes := rapid.SliceOfNDistinct(rapid.SampledFrom(rtIsoCWEs), 1, len(rtIsoCWEs), func(s string) string { return s }).Draw(t, "cwes")
		topK := rapid.IntRange(seek.MinTopK, seek.MaxTopK).Draw(t, "topK")

		var full, rest seek.Plan
		full.Language, full.Reasoning = "go", "r"
		rest.Language, rest.Reasoning = "go", "r"
		failing := map[int]bool{}
		fake.Clear()
		for i, cwe := range cwes {
			u := rtUnit(cwe, "heap overflow in the parser when handling length")
			full.Weaknesses = append(full.Weaknesses, u)
			// Only known CWEs can be made to fail; the unknown CWE stays healthy.
			if cwe != "CWE-999" && rapid.Bool().Draw(t, "fail") {
				failing[i] = true
				path := "/v1/weaknesses/" + cwe
				if rapid.Bool().Draw(t, "on_references") {
					path += "/vulnerabilities"
				}
				status := rapid.SampledFrom([]int{500, 503, 429}).Draw(t, "status")
				fake.Inject(path, seektest.Rule{Status: status})
				continue
			}
			rest.Weaknesses = append(rest.Weaknesses, u)
		}

		got := r.Run(context.Background(), full, topK)

		// The failing units are removed from the reference plan, so Top_K
		// allocation and cross-unit dedupe see the same units in both runs.
		fake.Clear()
		want := r.Run(context.Background(), rest, topK)

		wantStatus := "ok"
		if len(rest.Weaknesses) == 0 {
			wantStatus = "cve_unavailable"
		}
		if got.Status != wantStatus {
			t.Fatalf("status = %q, want %q (%d of %d failing)", got.Status, wantStatus, len(failing), len(cwes))
		}
		if len(got.Units) != len(cwes) {
			t.Fatalf("got %d units, want %d", len(got.Units), len(cwes))
		}
		next := 0
		for i, u := range got.Units {
			if failing[i] {
				if u.Status != "unavailable" || u.Error == nil || len(u.Candidates) != 0 {
					t.Fatalf("unit %d %s = %+v, want unavailable with error and no candidates", i, u.CWEID, u)
				}
				continue
			}
			a, errA := json.Marshal(u)
			b, errB := json.Marshal(want.Units[next])
			next++
			if errA != nil || errB != nil {
				t.Fatal(errA, errB)
			}
			if string(a) != string(b) {
				t.Fatalf("unit %d %s differs from the run without failures:\n%s\n%s", i, u.CWEID, a, b)
			}
		}
	})
}
