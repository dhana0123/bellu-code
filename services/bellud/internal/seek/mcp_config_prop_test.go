package seek_test

import (
	"testing"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/seek/bskg"
	"github.com/bellu/bellucode/services/bellud/internal/seek/seektest"
)

// Feature: bellu-seek-planner, Property 14: Configuration validity decides whether any request is made
//
// **Validates: Requirements 4.7, 9.1, 9.2**
func TestPropertyConfigurationValidity(t *testing.T) {
	type host struct {
		text     string
		nonEmpty bool
		loopback bool
	}
	hosts := []host{
		{"localhost", true, true},
		{"127.0.0.1", true, true},
		{"127.0.0.2", true, true},
		{"[::1]", true, true},
		{"example.com", true, false},
		{"localhost.example.com", true, false},
		{"10.0.0.1", true, false},
		{"0.0.0.0", true, false},
		{"", false, false},
	}
	blankKeys := []string{"", " ", "\t\n  "}

	rapid.Check(t, func(rt *rapid.T) {
		scheme := rapid.SampledFrom([]string{"https", "http", "ftp", "file"}).Draw(rt, "scheme")
		h := rapid.SampledFrom(hosts).Draw(rt, "host")
		userinfo := rapid.SampledFrom([]string{"", "user@", "user:pw@"}).Draw(rt, "userinfo")
		port := rapid.SampledFrom([]string{"", ":8443"}).Draw(rt, "port")
		path := rapid.SampledFrom([]string{"", "/", "/api"}).Draw(rt, "path")
		query := rapid.SampledFrom([]string{"", "?x=1"}).Draw(rt, "query")
		fragment := rapid.SampledFrom([]string{"", "#f"}).Draw(rt, "fragment")
		key := rapid.OneOf(
			rapid.SampledFrom(blankKeys),
			rapid.StringMatching(`[A-Za-z0-9_-]{1,40}`),
		).Draw(rt, "key")

		hostOK := h.nonEmpty && (scheme == "https" || (scheme == "http" && h.loopback))
		valid := hostOK && userinfo == "" && query == "" && fragment == "" && !isBlank(key)

		fake := seektest.New(t)
		url := scheme + "://" + userinfo + h.text + port + path + query + fragment
		if valid {
			url = fake.URL
		}

		cfg := bskg.Config{BaseURL: url, Key: bskg.Secret(key)}
		if got := cfg.Configured(); got != valid {
			rt.Fatalf("Configured() = %v for url %q (key blank: %v), want %v", got, url, isBlank(key), valid)
		}

		_, listed := listTools(t, connect(t, envFor(url, key), liveRetriever))[toolName]
		if listed != valid {
			rt.Fatalf("%s listed = %v for url %q, want %v", toolName, listed, url, valid)
		}
		if !valid {
			if n := len(fake.Requests()); n != 0 {
				rt.Fatalf("%d requests reached the fake server for an invalid pair", n)
			}
		}
	})
}

func isBlank(s string) bool {
	for _, r := range s {
		if r != ' ' && r != '\t' && r != '\n' {
			return false
		}
	}
	return true
}
