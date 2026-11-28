package seek

import (
	"math"
	"testing"

	"pgregory.net/rapid"
)

// Feature: bellu-seek-planner, Property 7: Score is bounded, monotone in each signal, and treats missing signals as zero
// **Validates: Requirements 6.2, 6.3**
func TestPropScoreBoundsAndMonotone(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		unit := rapid.Float64Range(0, 1)
		bin := rapid.SampledFrom([]float64{0, 1})
		s := Signals{
			IdentMatch: bin.Draw(t, "ident"),
			Overlap:    unit.Draw(t, "overlap"),
			KEV:        bin.Draw(t, "kev"),
			EPSS:       unit.Draw(t, "epss"),
			CVSS:       unit.Draw(t, "cvss"),
			Fix:        bin.Draw(t, "fix"),
		}
		base := Score(s)
		if base < 0 || base > 1 {
			t.Fatalf("score %v out of [0,1] for %+v", base, s)
		}

		// Raising any single signal never lowers the score.
		raised := []*Signals{{}, {}, {}, {}, {}, {}}
		for i := range raised {
			*raised[i] = s
		}
		raised[0].IdentMatch = 1
		raised[1].Overlap = rapid.Float64Range(s.Overlap, 1).Draw(t, "overlapUp")
		raised[2].KEV = 1
		raised[3].EPSS = rapid.Float64Range(s.EPSS, 1).Draw(t, "epssUp")
		raised[4].CVSS = rapid.Float64Range(s.CVSS, 1).Draw(t, "cvssUp")
		raised[5].Fix = 1
		for i, r := range raised {
			if got := Score(*r); got < base || got > 1 {
				t.Fatalf("raising signal %d: score %v -> %v (%+v -> %+v)", i, base, got, s, *r)
			}
		}
	})
}

// Feature: bellu-seek-planner, Property 7: Score is bounded, monotone in each signal, and treats missing signals as zero
// **Validates: Requirements 6.2, 6.3**
func TestPropScoreMissingSignalsAreZero(t *testing.T) {
	if got := Score(Signals{}); got != 0 {
		t.Fatalf("all-zero signals scored %v, want 0", got)
	}
	if got := Score(Signals{1, 1, 1, 1, 1, 1}); math.Abs(got-1) > 1e-9 {
		t.Fatalf("all-one signals scored %v, want 1.0", got)
	}
	rapid.Check(t, func(t *rapid.T) {
		// A CVE with no BSKG metadata has KEV, EPSS, CVSS and Fix signals of 0.
		u := Unit{
			Snippet:   rapid.StringN(0, 40, -1).Draw(t, "snippet"),
			RootCause: rapid.StringN(0, 40, -1).Draw(t, "rootCause"),
		}
		v := VulnDetail{Description: rapid.StringN(0, 40, -1).Draw(t, "desc")}
		s := SignalsFor(u, v)
		if s.KEV != 0 || s.EPSS != 0 || s.CVSS != 0 || s.Fix != 0 {
			t.Fatalf("missing metadata produced non-zero signals: %+v", s)
		}
		if sc := Score(s); sc < 0 || sc > WIdent+WOverlap+1e-9 {
			t.Fatalf("score %v exceeds text-only maximum for %+v", sc, s)
		}
	})
}
