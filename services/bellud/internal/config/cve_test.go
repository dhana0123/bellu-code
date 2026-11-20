package config

import (
	"testing"
	"time"
)

func lookupMap(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestLoadCVEDefaults(t *testing.T) {
	c, err := LoadCVE(lookupMap(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.AutoUpdate != AutoUpdateOff || c.WarnAfter != 7*24*time.Hour || c.StaleAfter != 30*24*time.Hour ||
		c.MaxChain != 30 || c.MirrorURL != "" || c.UserAgentSet {
		t.Fatalf("%+v", c)
	}
}

func TestLoadCVEValues(t *testing.T) {
	c, err := LoadCVE(lookupMap(map[string]string{
		"BELLUCODE_CVE_MIRROR_URL": "https://m.example/x", "BELLUCODE_CVE_AUTO_UPDATE": "weekly",
		"BELLUCODE_CVE_WARN_AFTER": "3d", "BELLUCODE_CVE_STALE_AFTER": "240h",
		"BELLUCODE_CVE_USER_AGENT": "", "BELLUCODE_CVE_MAX_DELTA_CHAIN": "365",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.AutoUpdate != AutoUpdateWeekly || c.WarnAfter != 72*time.Hour || c.StaleAfter != 240*time.Hour ||
		c.MaxChain != 365 || !c.UserAgentSet || c.UserAgent != "" || c.MirrorURL != "https://m.example/x" {
		t.Fatalf("%+v", c)
	}
}

func TestLoadCVERejectsInvalid(t *testing.T) {
	for k, v := range map[string]string{
		"BELLUCODE_CVE_AUTO_UPDATE": "hourly", "BELLUCODE_CVE_MAX_DELTA_CHAIN": "0",
		"BELLUCODE_CVE_MIRROR_URL": "ftp://x", "BELLUCODE_CVE_WARN_AFTER": "40d",
		"BELLUCODE_CVE_STALE_AFTER": "-1d",
	} {
		if _, err := LoadCVE(lookupMap(map[string]string{k: v})); err == nil {
			t.Errorf("%s=%s accepted", k, v)
		}
	}
}
