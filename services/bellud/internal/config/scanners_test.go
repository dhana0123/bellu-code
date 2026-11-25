package config

import (
	"testing"
	"time"
)

func TestLoadScanners(t *testing.T) {
	env := func(m map[string]string) func(string) (string, bool) {
		return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
	}
	c, err := LoadScanners(env(nil))
	if err != nil || c.Parallel != 2 || c.JobTimeout != time.Hour || c.AutoScan {
		t.Fatalf("defaults %+v %v", c, err)
	}
	c, err = LoadScanners(env(map[string]string{"BELLUCODE_SCANNERS_PARALLEL": "16", "BELLUCODE_SCANNERS_JOB_TIMEOUT": "30s", "BELLUCODE_SCANNERS_AUTO_SCAN": "true"}))
	if err != nil || c.Parallel != 16 || c.JobTimeout != 30*time.Second || !c.AutoScan {
		t.Fatalf("%+v %v", c, err)
	}
	for _, m := range []map[string]string{
		{"BELLUCODE_SCANNERS_PARALLEL": "0"}, {"BELLUCODE_SCANNERS_PARALLEL": "17"},
		{"BELLUCODE_SCANNERS_JOB_TIMEOUT": "29s"}, {"BELLUCODE_SCANNERS_JOB_TIMEOUT": "25h"},
		{"BELLUCODE_SCANNERS_AUTO_SCAN": "maybe"},
	} {
		if _, err := LoadScanners(env(m)); err == nil {
			t.Fatalf("accepted %v", m)
		}
	}
}
