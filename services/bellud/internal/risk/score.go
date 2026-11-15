// Package risk computes a bounded, deterministic risk score for a finding and
// buckets it into a severity. It imports no engine, service, or net/http.
package risk

import "math"

// Severity is the risk severity bucket. The values match the intel severities.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

// Inputs are the signals the score consumes. Out-of-range values are clamped
// and NaN counts as the lower bound.
type Inputs struct {
	CVSS          float64 // 0..10
	EPSS          float64 // 0..1
	KEV           bool    // listed in the CISA Known Exploited catalog
	Reachable     bool    // an attack path reaches the vulnerable asset
	AICriticality float64 // 0..1
}

// Compute returns the score in [0,100]:
//
//	base     = clamp(cvss,0,10)/10 * 100
//	exploit  = max(clamp(epss,0,1), kev ? 0.95 : 0)
//	exposure = reachable ? 1.0 : 0.4
//	aiBoost  = 1 + 0.25 * clamp(aiCriticality,0,1)
//	score    = clamp(base * (0.5 + 0.5*exploit) * exposure * aiBoost, 0, 100)
func Compute(in Inputs) float64 {
	base := clamp(in.CVSS, 0, 10) / 10 * 100

	exploit := clamp(in.EPSS, 0, 1)
	if in.KEV {
		exploit = math.Max(exploit, 0.95)
	}

	exposure := 0.4
	if in.Reachable {
		exposure = 1.0
	}

	aiBoost := 1 + 0.25*clamp(in.AICriticality, 0, 1)

	return clamp(base*(0.5+0.5*exploit)*exposure*aiBoost, 0, 100)
}

// Bucket maps a score to a severity: >=90 critical, >=70 high, >=40 medium,
// >=10 low, else info. KEV raises anything below high to high. NaN is info.
func Bucket(score float64, kev bool) Severity {
	switch {
	case score >= 90:
		return SevCritical
	case score >= 70:
		return SevHigh
	case kev:
		return SevHigh
	case score >= 40:
		return SevMedium
	case score >= 10:
		return SevLow
	}
	return SevInfo
}

func clamp(v, lo, hi float64) float64 {
	if math.IsNaN(v) {
		return lo
	}
	return math.Min(math.Max(v, lo), hi)
}
