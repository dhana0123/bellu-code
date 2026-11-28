package findings

import "testing"

func TestIDStable(t *testing.T) {
	// sha256("r\x00a\x00d") first 32 hex chars.
	a := ID("r", "a", "d")
	if len(a) != 32 || a != ID("r", "a", "d") {
		t.Fatalf("unstable or wrong length: %q", a)
	}
	if a != "e4998ca16243e3775227aec2b31c9681" {
		t.Fatalf("golden vector mismatch: %q", a)
	}
	if ID("r", "a", "d2") == a || ID("r", "a2", "d") == a || ID("r2", "a", "d") == a {
		t.Fatal("distinct inputs collided")
	}
	// The separator keeps field boundaries distinct.
	if ID("ab", "c", "d") == ID("a", "bc", "d") {
		t.Fatal("boundary collision")
	}
}

func TestMapSeverityTable(t *testing.T) {
	cases := []struct {
		scanner, raw string
		want         Severity
		unmapped     bool
	}{
		{"grype", "Critical", SevCritical, false},
		{"grype", "High", SevHigh, false},
		{"osv", "Medium", SevMedium, false},
		{"cvss", "Low", SevLow, false},
		{"grype", "Negligible", SevInfo, false},
		{"grype", "Unknown", SevInfo, false},
		{"trivy", "CRITICAL", SevCritical, false},
		{"trivy", "HIGH", SevHigh, false},
		{"trivy", "MEDIUM", SevMedium, false},
		{"trivy", "LOW", SevLow, false},
		{"trivy", "UNKNOWN", SevInfo, false},
		{"gitleaks", "aws-access-token", SevCritical, false},
		{"gitleaks", "private-key", SevCritical, false},
		{"gitleaks", "generic-api-key", SevHigh, false},
		{"rego", "info", SevInfo, false},
		{"rego", "high", SevHigh, false},
		{"sensor", "critical", SevCritical, false},
		{"rego", "bogus", SevInfo, true},
		{"trivy", "NEGLIGIBLE", SevInfo, true},
		{"grype", "", SevInfo, true},
		{"nosuchscanner", "high", SevInfo, true},
	}
	for _, c := range cases {
		got, un := MapSeverity(c.scanner, c.raw)
		if got != c.want || un != c.unmapped {
			t.Errorf("MapSeverity(%q,%q) = %s,%v want %s,%v", c.scanner, c.raw, got, un, c.want, c.unmapped)
		}
	}
}
