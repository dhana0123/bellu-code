// Package aiattr holds the attribute helpers the cloud connectors share when
// they emit AI inventory entities (task 49.3). Attribute names match what the
// bellu pack AI rules read: public_access ("enabled"), authentication
// ("none", "disabled" or another value), has_write_tool, external_input,
// input_validated and serialization_format.
package aiattr

import (
	"strconv"
	"strings"
)

// Attribute names.
const (
	Criticality  = "criticality" // number in 0..1, feeds risk.Inputs.AICriticality
	PublicAccess = "public_access"
	Auth         = "authentication"

	Enabled = "enabled"
)

// ParseCriticality reads a criticality tag or label: a number in 0..1 (clamped)
// or one of low, medium, high, critical. ok is false for anything else.
func ParseCriticality(s string) (v float64, ok bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "low":
		return 0.25, true
	case "medium":
		return 0.5, true
	case "high":
		return 0.75, true
	case "critical":
		return 1, true
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f != f {
		return 0, false
	}
	return min(max(f, 0), 1), true
}

// Set stores the criticality parsed from raw in attrs, when it parses.
func Set(attrs map[string]any, raw string) {
	if v, ok := ParseCriticality(raw); ok {
		attrs[Criticality] = v
	}
}
