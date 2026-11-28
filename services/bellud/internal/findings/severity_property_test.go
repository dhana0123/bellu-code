package findings

import (
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// Feature: bellu-wiz-security-platform, Property 7: Severity mapping is total. For any (scanner, raw) string pair, MapSeverity returns exactly one of critical, high, medium, low, info without panic or error; any pair not in the table returns info with unmapped true.
//
// **Validates: Requirements 3.13, 3.14**
func TestSeverityMappingTotalProperty(t *testing.T) {
	scanners := []string{"gitleaks"}
	raws := []string{"", "private-key", "generic-api-key"}
	for s, m := range severityTable {
		scanners = append(scanners, s)
		for r := range m {
			raws = append(raws, r)
		}
	}
	scannerGen := rapid.OneOf(rapid.SampledFrom(scanners), rapid.String())
	rawGen := rapid.OneOf(rapid.SampledFrom(raws), rapid.String())
	valid := map[Severity]bool{SevCritical: true, SevHigh: true, SevMedium: true, SevLow: true, SevInfo: true}

	rapid.Check(t, func(t *rapid.T) {
		scanner := scannerGen.Draw(t, "scanner")
		raw := rawGen.Draw(t, "raw")
		// Vary case and padding to exercise normalization.
		if rapid.Bool().Draw(t, "upper") {
			scanner, raw = strings.ToUpper(scanner), strings.ToUpper(raw)
		}

		sev, unmapped := MapSeverity(scanner, raw)
		if !valid[sev] {
			t.Fatalf("MapSeverity(%q, %q) = %q, not a valid severity", scanner, raw, sev)
		}

		s := strings.ToLower(strings.TrimSpace(scanner))
		r := strings.ToLower(strings.TrimSpace(raw))
		want, inTable := severityTable[s][r]
		switch {
		case s == "gitleaks":
			if unmapped {
				t.Fatalf("gitleaks is always mapped, got unmapped for %q", raw)
			}
		case inTable:
			if unmapped || sev != want {
				t.Fatalf("(%q, %q): got (%q, %v), want (%q, false)", scanner, raw, sev, unmapped, want)
			}
		default:
			if !unmapped || sev != SevInfo {
				t.Fatalf("(%q, %q) not in table: got (%q, %v), want (info, true)", scanner, raw, sev, unmapped)
			}
		}
	})
}
