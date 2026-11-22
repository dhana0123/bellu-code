package config

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

const (
	seekURLEnv = "BELLUCODE_SEEK_BSKG_URL"
	seekKeyEnv = "BELLUCODE_SEEK_BSKG_KEY"

	DefaultSeekMinRelevance = 0.20
)

// Seek holds the seek.* configuration (Requirements 6.6, 9.1, 9.2), read from
// BELLUCODE_SEEK_BSKG_URL, BELLUCODE_SEEK_BSKG_KEY and
// BELLUCODE_SEEK_MIN_RELEVANCE.
type Seek struct {
	// BSKGURL and BSKGKey are both empty when seek is unconfigured. Seek is
	// configured only when both are present and the URL is valid.
	BSKGURL      string
	BSKGKey      string
	MinRelevance float64  // 0 to 1, default 0.20
	Warnings     []string // one per unconfigured cause; names the variable, never its value
}

// LoadSeek reads and validates the seek.* settings through env (use
// os.LookupEnv in production). A missing or invalid URL or key leaves seek
// unconfigured with a warning; an invalid min relevance is an error.
func LoadSeek(env func(string) (string, bool)) (Seek, error) {
	s := Seek{MinRelevance: DefaultSeekMinRelevance}
	get := func(name string) string {
		v, _ := env(name)
		return strings.TrimSpace(v)
	}

	if v := get("BELLUCODE_SEEK_MIN_RELEVANCE"); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		// The negated comparison also rejects NaN.
		if err != nil || !(f >= 0 && f <= 1) {
			return Seek{MinRelevance: DefaultSeekMinRelevance}, fmt.Errorf("invalid BELLUCODE_SEEK_MIN_RELEVANCE %q: want a number from 0 to 1", v)
		}
		s.MinRelevance = f
	}

	rawURL, key := get(seekURLEnv), get(seekKeyEnv)
	switch {
	case rawURL == "":
		s.Warnings = append(s.Warnings, seekURLEnv+" is not set; seek is unconfigured")
	case !validSeekURL(rawURL):
		s.Warnings = append(s.Warnings, seekURLEnv+" is not a valid URL (want https, or http on a loopback host, with no credentials, query or fragment); seek is unconfigured")
	}
	if key == "" {
		s.Warnings = append(s.Warnings, seekKeyEnv+" is not set; seek is unconfigured")
	}
	if len(s.Warnings) > 0 {
		return s, nil
	}
	s.BSKGURL, s.BSKGKey = rawURL, key
	return s, nil
}

func validSeekURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Contains(raw, "?") || strings.Contains(raw, "#") {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		h := u.Hostname()
		return h == "localhost" || h == "127.0.0.1" || h == "::1"
	}
	return false
}
