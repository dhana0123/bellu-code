package config

import (
	"strings"
	"testing"
)

// Contract assumed for LoadSeek (task 5.5), modeled on LoadCVE:
//
//	type Seek struct {
//		BSKGURL      string   // empty when unconfigured
//		BSKGKey      string   // empty when unconfigured
//		MinRelevance float64  // default 0.20
//		Warnings     []string // one entry per unconfigured cause; names the variable, never the value
//	}
//	func LoadSeek(env func(string) (string, bool)) (Seek, error)
//
// Configured means both BSKGURL and BSKGKey are non-empty after loading.

const (
	seekURLVar = "BELLUCODE_SEEK_BSKG_URL"
	seekKeyVar = "BELLUCODE_SEEK_BSKG_KEY"
	seekMinVar = "BELLUCODE_SEEK_MIN_RELEVANCE"

	secretKey = "k-SECRET-0123456789"
)

func TestLoadSeekDefaults(t *testing.T) {
	s, err := LoadSeek(lookupMap(nil))
	if err != nil {
		t.Fatal(err)
	}
	if s.MinRelevance != 0.20 || s.BSKGURL != "" || s.BSKGKey != "" {
		t.Fatalf("%+v", s)
	}
}

func TestLoadSeekValues(t *testing.T) {
	s, err := LoadSeek(lookupMap(map[string]string{
		seekURLVar: " https://bskg.example/base ", seekKeyVar: " " + secretKey + " ", seekMinVar: "0.35",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if s.BSKGURL != "https://bskg.example/base" || s.BSKGKey != secretKey || s.MinRelevance != 0.35 {
		t.Fatalf("%+v", s)
	}
	if len(s.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", s.Warnings)
	}
}

func TestLoadSeekLoopbackHTTPAllowed(t *testing.T) {
	for _, u := range []string{"http://localhost:8080", "http://127.0.0.1:9", "http://[::1]:9"} {
		s, err := LoadSeek(lookupMap(map[string]string{seekURLVar: u, seekKeyVar: secretKey}))
		if err != nil || s.BSKGURL != u {
			t.Fatalf("%s: %+v %v", u, s, err)
		}
	}
}

func TestLoadSeekMinRelevanceRange(t *testing.T) {
	for _, v := range []string{"0", "0.0", "0.2", "1", "1.0"} {
		if _, err := LoadSeek(lookupMap(map[string]string{seekMinVar: v})); err != nil {
			t.Errorf("%q should be valid: %v", v, err)
		}
	}
	for _, v := range []string{"-0.01", "1.01", "2", "abc", "NaN", "Inf", "-Inf", "0,5", "0.2x"} {
		_, err := LoadSeek(lookupMap(map[string]string{
			seekMinVar: v, seekURLVar: "https://bskg.example", seekKeyVar: secretKey,
		}))
		if err == nil {
			t.Errorf("%q should be a startup error", v)
			continue
		}
		if !strings.Contains(err.Error(), seekMinVar) && !strings.Contains(err.Error(), "seek.min_relevance") {
			t.Errorf("%q: error should name the setting: %v", v, err)
		}
		if strings.Contains(err.Error(), secretKey) {
			t.Errorf("%q: error leaks the key: %v", v, err)
		}
	}
}

func TestLoadSeekEmptyMinRelevanceIsDefault(t *testing.T) {
	s, err := LoadSeek(lookupMap(map[string]string{seekMinVar: "  "}))
	if err != nil || s.MinRelevance != 0.20 {
		t.Fatalf("%+v %v", s, err)
	}
}

func TestLoadSeekUnconfigured(t *testing.T) {
	const goodURL = "https://bskg.example"
	cases := []struct {
		name    string
		env     map[string]string
		varName string // variable the warning must name
	}{
		{"missing url", map[string]string{seekKeyVar: secretKey}, seekURLVar},
		{"blank url", map[string]string{seekURLVar: "  ", seekKeyVar: secretKey}, seekURLVar},
		{"missing key", map[string]string{seekURLVar: goodURL}, seekKeyVar},
		{"blank key", map[string]string{seekURLVar: goodURL, seekKeyVar: " "}, seekKeyVar},
		{"plain http remote", map[string]string{seekURLVar: "http://bskg.example", seekKeyVar: secretKey}, seekURLVar},
		{"relative url", map[string]string{seekURLVar: "bskg.example/x", seekKeyVar: secretKey}, seekURLVar},
		{"ftp scheme", map[string]string{seekURLVar: "ftp://bskg.example", seekKeyVar: secretKey}, seekURLVar},
		{"userinfo", map[string]string{seekURLVar: "https://user:pw@bskg.example", seekKeyVar: secretKey}, seekURLVar},
		{"query", map[string]string{seekURLVar: goodURL + "?a=1", seekKeyVar: secretKey}, seekURLVar},
		{"fragment", map[string]string{seekURLVar: goodURL + "#f", seekKeyVar: secretKey}, seekURLVar},
		{"no host", map[string]string{seekURLVar: "https://", seekKeyVar: secretKey}, seekURLVar},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := LoadSeek(lookupMap(tc.env))
			if err != nil {
				t.Fatalf("unconfigured must not be a startup error: %v", err)
			}
			if s.BSKGURL != "" || s.BSKGKey != "" {
				t.Fatalf("expected unconfigured, got %+v", s)
			}
			if s.MinRelevance != 0.20 {
				t.Fatalf("min relevance should keep its default: %v", s.MinRelevance)
			}
			if len(s.Warnings) != 1 {
				t.Fatalf("want exactly one warning, got %q", s.Warnings)
			}
			w := s.Warnings[0]
			if !strings.Contains(w, tc.varName) {
				t.Errorf("warning must name %s: %q", tc.varName, w)
			}
			for _, v := range tc.env {
				if v = strings.TrimSpace(v); v != "" && strings.Contains(w, v) {
					t.Errorf("warning leaks value %q: %q", v, w)
				}
			}
		})
	}
}

func TestLoadSeekBothMissingWarnsWithoutValues(t *testing.T) {
	s, err := LoadSeek(lookupMap(nil))
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(s.Warnings, "\n")
	if !strings.Contains(joined, seekURLVar) && !strings.Contains(joined, seekKeyVar) {
		t.Fatalf("warnings must name a variable: %q", joined)
	}
}

func TestLoadSeekEnvironmentIsTheOnlySource(t *testing.T) {
	// R9.1: the process environment is the configuration; reading goes through env only.
	t.Setenv(seekURLVar, "https://from-process.example")
	t.Setenv(seekKeyVar, secretKey)
	s, err := LoadSeek(lookupMap(map[string]string{seekURLVar: "https://injected.example", seekKeyVar: "other"}))
	if err != nil || s.BSKGURL != "https://injected.example" || s.BSKGKey != "other" {
		t.Fatalf("%+v %v", s, err)
	}
}
