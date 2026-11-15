package risk

import (
	"math"
	"testing"

	"pgregory.net/rapid"
)

// Feature: unified-security-graph, Property 11: Risk score is bounded,
// deterministic, monotone, and clamps inputs.
//
// **Validates: Requirements 6.1, 6.2, 6.3, 6.4, 6.5, 6.8**

// anyFloat draws finite, out-of-range, infinite, and NaN values.
func anyFloat() *rapid.Generator[float64] {
	return rapid.OneOf(
		rapid.Float64(),
		rapid.Float64Range(-20, 20),
		rapid.Float64Range(-2, 2),
		rapid.SampledFrom([]float64{math.NaN(), math.Inf(1), math.Inf(-1), 0, 1, 10, -1, 11}),
	)
}

func anyInputs() *rapid.Generator[Inputs] {
	return rapid.Custom(func(t *rapid.T) Inputs {
		return Inputs{
			CVSS:          anyFloat().Draw(t, "cvss"),
			EPSS:          anyFloat().Draw(t, "epss"),
			KEV:           rapid.Bool().Draw(t, "kev"),
			Reachable:     rapid.Bool().Draw(t, "reachable"),
			AICriticality: anyFloat().Draw(t, "ai"),
		}
	})
}

// refClamp is an independent restatement of the documented clamp rule: NaN
// counts as the lower bound.
func refClamp(v, lo, hi float64) float64 {
	switch {
	case math.IsNaN(v), v < lo:
		return lo
	case v > hi:
		return hi
	}
	return v
}

// lower reports a value that is never above v under the clamp ordering (NaN
// ranks lowest).
func lowerOf(t *rapid.T, v float64) float64 {
	if math.IsNaN(v) {
		return v
	}
	return v - math.Abs(rapid.Float64Range(0, 30).Draw(t, "delta"))
}

func TestScoreBoundedProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		s := Compute(anyInputs().Draw(t, "in"))
		if math.IsNaN(s) || s < 0 || s > 100 {
			t.Fatalf("score %v outside [0,100]", s)
		}
	})
}

func TestScoreDeterministicProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		in := anyInputs().Draw(t, "in")
		a, b := Compute(in), Compute(in)
		if a != b {
			t.Fatalf("Compute not deterministic: %v vs %v", a, b)
		}
	})
}

func TestScoreClampsInputsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		in := anyInputs().Draw(t, "in")
		clamped := in
		clamped.CVSS = refClamp(in.CVSS, 0, 10)
		clamped.EPSS = refClamp(in.EPSS, 0, 1)
		clamped.AICriticality = refClamp(in.AICriticality, 0, 1)
		if got, want := Compute(in), Compute(clamped); got != want {
			t.Fatalf("Compute(%+v)=%v, Compute(clamped %+v)=%v", in, got, clamped, want)
		}
	})
}

func TestScoreMonotoneProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		hi := anyInputs().Draw(t, "in")
		lo := hi
		switch rapid.IntRange(0, 4).Draw(t, "signal") {
		case 0:
			lo.CVSS = lowerOf(t, hi.CVSS)
		case 1:
			lo.EPSS = lowerOf(t, hi.EPSS)
		case 2:
			lo.AICriticality = lowerOf(t, hi.AICriticality)
		case 3:
			lo.Reachable = false
			hi.Reachable = true
		case 4:
			lo.KEV = false
			hi.KEV = true
		}
		if l, h := Compute(lo), Compute(hi); h < l {
			t.Fatalf("raising a signal lowered the score: lo=%+v (%v) hi=%+v (%v)", lo, l, hi, h)
		}
	})
}
