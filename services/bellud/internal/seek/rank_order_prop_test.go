package seek

import (
	"slices"
	"sort"
	"testing"

	"pgregory.net/rapid"
)

// Feature: bellu-seek-planner, Property 8: Output is ordered, cut off and tie-broken
// **Validates: Requirements 4.3, 6.4, 6.6, 6.7**
func TestPropertyOutputIsOrderedCutOffAndTieBroken(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		ids := rapid.SliceOfNDistinct(rapid.StringMatching(`CVE-20[0-9]{2}-[0-9]{4,5}`), 0, 30, rapid.ID[string]).Draw(t, "ids")

		// A small score pool makes ties common; the sub-1e-6 jitter makes scores
		// that differ in raw value but are equal at 6 decimal places.
		base := rapid.SampledFrom([]float64{0, 0.1, 0.2, 0.2000004, 0.2000006, 0.5, 0.75, 1}).Draw(t, "base")
		scoreGen := rapid.OneOf(
			rapid.SampledFrom([]float64{0, 0.1, 0.2, 0.5, 0.75, 1}),
			rapid.Float64Range(0, 1),
			rapid.Map(rapid.Float64Range(-4e-7, 4e-7), func(j float64) float64 { return clamp01(base + j) }),
		)

		in := make([]Candidate, len(ids))
		for i, id := range ids {
			in[i] = Candidate{CVEID: id, Score: scoreGen.Draw(t, "score")}
		}

		min := rapid.OneOf(
			rapid.Float64Range(0, 1),
			rapid.SampledFrom([]float64{0, DefaultMinRelevance, 1}),
			rapid.Just(base),
		).Draw(t, "min")
		if len(in) > 0 && rapid.Bool().Draw(t, "minFromInput") {
			min = rapid.SampledFrom(in).Draw(t, "pick").Score // boundary: score == cutoff
		}

		inCopy := make([]Candidate, len(in))
		copy(inCopy, in)
		out := Cutoff(Rank(in), min)

		if !slices.Equal(in, inCopy) {
			t.Fatalf("input was modified")
		}

		// Cutoff: exactly the candidates with Score >= min are kept (6.6, 6.7).
		want := map[string]bool{}
		for _, c := range in {
			if c.Score >= min {
				want[c.CVEID] = true
			}
		}
		if len(out) != len(want) {
			t.Fatalf("kept %d candidates, want %d (min=%v)", len(out), len(want), min)
		}
		for _, c := range out {
			if !want[c.CVEID] {
				t.Fatalf("%s with score %v kept below cutoff %v", c.CVEID, c.Score, min)
			}
		}

		// Order: rounded score descending, then CVE id ascending (6.4).
		for i := 1; i < len(out); i++ {
			a, b := out[i-1], out[i]
			ra, rb := rounded(a.Score), rounded(b.Score)
			if ra < rb || (ra == rb && a.CVEID >= b.CVEID) {
				t.Fatalf("out of order at %d: %s(%v) before %s(%v)", i, a.CVEID, a.Score, b.CVEID, b.Score)
			}
		}

		// Cutting off before or after ranking gives the same list, and a
		// shuffled input gives the same list (no dependence on input order).
		if again := Rank(Cutoff(in, min)); !slices.Equal(out, again) {
			t.Fatalf("Rank/Cutoff order matters: %v vs %v", out, again)
		}
		shuffled := append([]Candidate(nil), in...)
		sort.SliceStable(shuffled, func(i, j int) bool { return shuffled[i].CVEID > shuffled[j].CVEID })
		if again := Cutoff(Rank(shuffled), min); !slices.Equal(out, again) {
			t.Fatalf("result depends on input order: %v vs %v", out, again)
		}
	})
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
