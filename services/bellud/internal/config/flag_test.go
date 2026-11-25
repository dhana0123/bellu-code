package config

import "testing"

func TestFeatureEnabled(t *testing.T) {
	cases := []struct {
		flags   string
		release bool
		want    bool
	}{
		{"", false, true},
		{"", true, false},
		{"security_findings", true, true},
		{"all", true, true},
		{"all,-security_findings", true, false},
		{"security_findings,-security_findings", false, false},
		{"-security_findings", false, false},
		{" other , security_findings ", true, true},
		{"security_findings_x", true, false},
		{"-other", false, true},
	}
	for _, c := range cases {
		got := FeatureEnabled(func(string) string { return c.flags }, "security_findings", c.release)
		if got != c.want {
			t.Errorf("flags %q release %v: got %v, want %v", c.flags, c.release, got, c.want)
		}
	}
}
