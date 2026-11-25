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

	// Exposure is the network exposure of the asset. The zero value is
	// ExposureUnknown and leaves the score unchanged.
	Exposure Exposure
	// AssetCriticality is the business importance of the asset, 0..1. The zero
	// value means unknown and leaves the score unchanged.
	AssetCriticality float64
}

// Exposure is the `exposure` attribute vocabulary: internet|internal|unknown.
// Any other value is treated as unknown.
type Exposure string

const (
	ExposureUnknown  Exposure = ""
	ExposureInternal Exposure = "internal"
	ExposureInternet Exposure = "internet"
)

// Compute returns the score in [0,100]:
//
//	base     = clamp(cvss,0,10)/10 * 100
//	exploit  = max(clamp(epss,0,1), kev ? 0.95 : 0)
//	exposure = reachable ? 1.0 : 0.4
//	aiBoost  = 1 + 0.25 * clamp(aiCriticality,0,1)
//	netBoost = internet ? 1.25 : 1.0   (internal and unknown are 1.0)
//	critBoost = 1 + 0.3*clamp(assetCriticality,0,1)
//	score    = clamp(base * (0.5 + 0.5*exploit) * exposure * aiBoost
//	                 * netBoost * critBoost, 0, 100)
//
// The two added boosts are 1.0 for zero-value inputs, so scores computed
// without them are unchanged. Missing EPSS counts as 0 and missing exposure or
// criticality as unknown; none of them can fail the computation.
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

	netBoost := 1.0
	if in.Exposure == ExposureInternet {
		netBoost = 1.25
	}
	critBoost := 1 + 0.3*clamp(in.AssetCriticality, 0, 1)
	return clamp(base*(0.5+0.5*exploit)*exposure*aiBoost*netBoost*critBoost, 0, 100)
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
