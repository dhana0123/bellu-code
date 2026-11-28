package findings

import "strings"

// severityTable is the documented (scanner, raw) mapping (Requirement 3.13).
// Scanner and raw keys are lower case; MapSeverity folds case before lookup.
var severityTable = map[string]map[string]Severity{
	"grype":  grypeScale,
	"osv":    grypeScale,
	"cvss":   grypeScale,
	"trivy":  {"critical": SevCritical, "high": SevHigh, "medium": SevMedium, "low": SevLow, "unknown": SevInfo},
	"rego":   metadataScale,
	"sensor": metadataScale,
}

var grypeScale = map[string]Severity{
	"critical": SevCritical, "high": SevHigh, "medium": SevMedium, "low": SevLow,
	"negligible": SevInfo, "unknown": SevInfo,
}

// metadataScale is the five valid values for rule metadata severity.
var metadataScale = map[string]Severity{
	"critical": SevCritical, "high": SevHigh, "medium": SevMedium, "low": SevLow, "info": SevInfo,
}

// gitleaksCritical lists rule id fragments for cloud credentials and private keys.
var gitleaksCritical = []string{"private-key", "aws", "gcp", "google", "azure", "alibaba", "gcloud"}

// MapSeverity maps a scanner's severity word onto the common scale. It is
// total over strings. A scanner or raw value outside the table returns info
// with unmapped=true (Requirement 3.14).
//
// Gitleaks reports no severity, so raw is its rule id: cloud credentials and
// private keys map to critical, every other rule to high.
func MapSeverity(scanner, raw string) (sev Severity, unmapped bool) {
	s := strings.ToLower(strings.TrimSpace(scanner))
	r := strings.ToLower(strings.TrimSpace(raw))
	if s == "gitleaks" {
		for _, f := range gitleaksCritical {
			if strings.Contains(r, f) {
				return SevCritical, false
			}
		}
		return SevHigh, false
	}
	if v, ok := severityTable[s][r]; ok {
		return v, false
	}
	return SevInfo, true
}
