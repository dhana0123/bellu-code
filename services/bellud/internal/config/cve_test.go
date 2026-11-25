package config

import (
	"fmt"
	"strings"
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

func TestLoadCVEModeAndStaleLimit(t *testing.T) {
	c, err := LoadCVE(lookupMap(nil))
	if err != nil || c.Mode != CVEModeDB || c.StaleLimit != 7*24*time.Hour {
		t.Fatalf("defaults %+v %v", c, err)
	}
	c, err = LoadCVE(lookupMap(map[string]string{"BELLUCODE_CVE_MODE": "Both", "BELLUCODE_CVE_STALE_LIMIT": "2d"}))
	if err != nil || c.Mode != CVEModeBoth || c.StaleLimit != 48*time.Hour {
		t.Fatalf("values %+v %v", c, err)
	}
	if _, err := LoadCVE(lookupMap(map[string]string{"BELLUCODE_CVE_STALE_LIMIT": "0d"})); err == nil {
		t.Fatal("zero stale limit accepted")
	}
}

func TestParseCVEModeKeepsPrevious(t *testing.T) {
	m, err := ParseCVEMode(CVEModeBoth, "nope")
	if m != CVEModeBoth || err == nil {
		t.Fatalf("got %q %v", m, err)
	}
	for _, want := range []string{"cve.mode", "db", "graph", "both"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q lacks %q", err, want)
		}
	}
	c, err := LoadCVE(lookupMap(map[string]string{"BELLUCODE_CVE_MODE": "x"}))
	if err == nil || c.Mode != CVEModeDB {
		t.Fatalf("%+v %v", c, err)
	}
}

func bskgEnv(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestBSKGURLHTTPS(t *testing.T) {
	for _, u := range []string{"https://bskg.example.com", "http://127.0.0.1:8080", "http://localhost:1", "http://[::1]:9"} {
		if _, err := LoadCVE(bskgEnv(map[string]string{"BELLUCODE_CVE_BSKG_URL": u})); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	_, err := LoadCVE(bskgEnv(map[string]string{"BELLUCODE_CVE_BSKG_URL": "http://bskg.example.com"}))
	if err == nil || !strings.Contains(err.Error(), "cve.bskg_url") {
		t.Fatalf("want cve.bskg_url error, got %v", err)
	}
}

func TestGraphCacheTTLBounds(t *testing.T) {
	c, _ := LoadCVE(bskgEnv(nil))
	if c.GraphCacheTTL != 10*time.Minute || c.BSKGTimeout != 10*time.Second {
		t.Fatalf("defaults: %v %v", c.GraphCacheTTL, c.BSKGTimeout)
	}
	for _, v := range []string{"1s", "24h"} {
		if _, err := LoadCVE(bskgEnv(map[string]string{"BELLUCODE_CVE_GRAPH_CACHE_TTL": v})); err != nil {
			t.Errorf("%s: %v", v, err)
		}
	}
	for _, v := range []string{"999ms", "24h1s", "x"} {
		if _, err := LoadCVE(bskgEnv(map[string]string{"BELLUCODE_CVE_GRAPH_CACHE_TTL": v})); err == nil {
			t.Errorf("%s accepted", v)
		}
	}
}

func TestBSKGKeyEnvAndRedaction(t *testing.T) {
	c, err := LoadCVE(bskgEnv(map[string]string{"BELLUCODE_CVE_BSKG_API_KEY": "sekrit-123"}))
	if err != nil || c.BSKGKey.Reveal() != "sekrit-123" {
		t.Fatalf("key: %v", err)
	}
	for _, out := range []string{fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c), c.String(), fmt.Sprint(c.BSKGKey), fmt.Sprintf("%s", c.BSKGKey)} {
		if strings.Contains(out, "sekrit") {
			t.Errorf("leaked: %s", out)
		}
	}
	if c.BSKGKey.String() != "[REDACTED:bskg_key]" {
		t.Error("bad redaction text")
	}
	VaultLookup = func(string) (string, bool) { return "vk", true }
	defer func() { VaultLookup = nil }()
	if c, _ := LoadCVE(bskgEnv(nil)); c.BSKGKey.Reveal() != "vk" {
		t.Error("vault fallback")
	}
}
