package seek

import (
	"testing"

	"pgregory.net/rapid"
)

// Feature: bellu-seek-planner, Property 9: Top-K allocation fills the budget fairly without overflow
// **Validates: Requirements 6.5, 6.9**
func TestPropAllocateFairNoOverflow(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		topK := rapid.IntRange(1, 10).Draw(t, "topK")
		have := rapid.SliceOfN(rapid.IntRange(0, 12), 0, 12).Draw(t, "have")
		orig := append([]int(nil), have...)

		out := Allocate(topK, have)

		if len(out) != len(have) {
			t.Fatalf("length %d, want %d", len(out), len(have))
		}
		sum, total, m := 0, 0, 0
		for i, n := range have {
			if n != orig[i] {
				t.Fatalf("have was modified: %v -> %v", orig, have)
			}
			if out[i] < 0 || out[i] > n {
				t.Fatalf("out[%d]=%d outside 0..%d (topK=%d have=%v out=%v)", i, out[i], n, topK, have, out)
			}
			sum += out[i]
			total += n
			if n > 0 {
				m++
			}
		}
		if want := min(topK, total); sum != want {
			t.Fatalf("sum(out)=%d, want %d (topK=%d have=%v out=%v)", sum, want, topK, have, out)
		}
		if m == 0 {
			return
		}

		if m > topK {
			seen := 0
			for i, n := range have {
				want := 0
				if n > 0 {
					if seen < topK {
						want = 1
					}
					seen++
				}
				if out[i] != want {
					t.Fatalf("m>topK: out[%d]=%d, want %d (topK=%d have=%v out=%v)", i, out[i], want, topK, have, out)
				}
			}
			return
		}

		base := topK / m
		// Fairness is exact only when no unit is capped below its quota. With
		// capped units the freed slots must go elsewhere, so spreads can exceed 1.
		need := base
		if topK%m > 0 {
			need++
		}
		for _, n := range have {
			if n > 0 && n < need {
				return
			}
		}
		for i, n := range have {
			if n == 0 {
				continue
			}
			if out[i] != base && out[i] != base+1 {
				t.Fatalf("out[%d]=%d not in {%d,%d} (topK=%d have=%v out=%v)", i, out[i], base, base+1, topK, have, out)
			}
			// Extra slots go to earlier units: an earlier unit that could take one must have it.
			if out[i] == base+1 {
				for j := 0; j < i; j++ {
					if have[j] > base && out[j] != base+1 {
						t.Fatalf("extra slot went to unit %d before earlier unit %d (topK=%d have=%v out=%v)", i, j, topK, have, out)
					}
				}
			}
		}
	})
}
