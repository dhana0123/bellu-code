package risk

import (
	"math"
	"testing"

	"pgregory.net/rapid"
)

// boundedInputs draws every Inputs field over its full domain, including the
// Exposure and AssetCriticality fields added for the Wiz platform, with
// arbitrary (often unknown) Exposure strings.
func boundedInputs() *rapid.Generator[Inputs] {
	return rapid.Custom(func(t *rapid.T) Inputs {
		return Inputs{
			CVSS:          anyFloat().Draw(t, "cvss"),
			EPSS:          anyFloat().Draw(t, "epss"),
			KEV:           rapid.Bool().Draw(t, "kev"),
			Reachable:     rapid.Bool().Draw(t, "reachable"),
			AICriticality: anyFloat().Draw(t, "ai"),
			Exposure: Exposure(rapid.OneOf(
				rapid.SampledFrom([]string{"", "internet", "internal", "unknown", "INTERNET", " internet"}),
				rapid.String(),
			).Draw(t, "exposure")),
			AssetCriticality: anyFloat().Draw(t, "assetCriticality"),
		}
	})
}

// Feature: bellu-wiz-security-platform, Property 20: Risk scores are bounded
//
// **Validates: Requirements 4.9, 7.7**
func TestRiskScoreBoundedProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		in := boundedInputs().Draw(t, "in")
		s := Compute(in) // must not panic
		if math.IsNaN(s) || math.IsInf(s, 0) || s < 0 || s > 100 {
			t.Fatalf("Compute(%+v)=%v, want finite value in [0,100]", in, s)
		}
		switch Bucket(s, in.KEV) {
		case SevCritical, SevHigh, SevMedium, SevLow, SevInfo:
		default:
			t.Fatalf("Bucket(%v,%v)=%q is not a valid severity", s, in.KEV, Bucket(s, in.KEV))
		}
	})
}

// Feature: bellu-wiz-security-platform, Property 20: Risk scores are bounded
// (Bucket accepts any float64, including NaN and ±Inf)
//
// **Validates: Requirements 4.9, 7.7**
func TestRiskBucketValidForAnyScoreProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		score := anyFloat().Draw(t, "score")
		kev := rapid.Bool().Draw(t, "kev")
		switch Bucket(score, kev) {
		case SevCritical, SevHigh, SevMedium, SevLow, SevInfo:
		default:
			t.Fatalf("Bucket(%v,%v)=%q is not a valid severity", score, kev, Bucket(score, kev))
		}
	})
}
