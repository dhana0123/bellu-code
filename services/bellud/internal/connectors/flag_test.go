package connectors

import (
	"testing"
)

func TestEnabled(t *testing.T) {
	tests := []struct {
		name    string
		flags   string
		release bool
		want    bool
	}{
		{"dev default on", "", false, true},
		{"release default off", "", true, false},
		{"release explicit on", "connectors", true, true},
		{"release all", "all", true, true},
		{"release other flag only", "todo", true, false},
		{"dev opt out", "-connectors", false, false},
		{"opt out beats all", "all,-connectors", true, false},
		{"opt out beats key, any order", "-connectors,connectors", false, false},
		{"whitespace tolerated", " todo , connectors ", true, true},
		{"dev other opt out keeps default", "-todo", false, true},
		{"similar key ignored", "connectors2", true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prev := isRelease
			isRelease = func() bool { return tc.release }
			defer func() { isRelease = prev }()
			got := Enabled(func(k string) string {
				if k == "BELLUCODE_FLAGS" {
					return tc.flags
				}
				return ""
			})
			if got != tc.want {
				t.Fatalf("Enabled(%q, release=%v) = %v, want %v", tc.flags, tc.release, got, tc.want)
			}
		})
	}
}
