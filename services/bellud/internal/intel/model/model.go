// Package model defines the intel vulnerability model used by Bellud. Field
// names match the records in the bundle's intel.jsonl, which is written by
// json.Marshal on untagged structs. Do not add JSON tags.
package model

import "time"

// Vuln is one vulnerability, merged from every source that references it.
type Vuln struct {
	// ID is the canonical id (CVE preferred, else GHSA, else OSV id).
	ID string
	// Aliases are all external identifiers that resolve to this vulnerability.
	Aliases  []string
	Summary  string
	Affected []AffectedPackage
	CVSS     CVSS
	Severity Severity
	// KnownExploited is true if present in CISA KEV.
	KnownExploited bool
	// EPSS is the exploit-prediction score in [0,1].
	EPSS      float64
	Published time.Time
	Modified  time.Time
	// Sources lists which intel sources contributed.
	Sources []string
}

// AffectedPackage names a vulnerable package (purl without version) and the
// version ranges in which it is affected.
type AffectedPackage struct {
	Purl      string // "pkg:pypi/requests" (name without version)
	Ecosystem string // "PyPI", "npm", "Go", ...
	Ranges    []SemverRange
	FixedIn   []string // explicit fixed versions when provided
}

// SemverRange is a half-open version interval [Introduced, Fixed).
// Introduced is inclusive ("0" or "" means from the start); Fixed is
// exclusive ("" means unbounded above).
type SemverRange struct {
	Introduced string
	Fixed      string
}

// CVSS captures a Common Vulnerability Scoring System result.
type CVSS struct {
	Vector  string
	Score   float64 // 0..10
	Version string  // "3.1", "4.0"
}

// Severity is the qualitative severity bucket for a vulnerability.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)
