package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Auto-update modes for cve.auto_update.
const (
	AutoUpdateOff    = "off"
	AutoUpdateDaily  = "daily"
	AutoUpdateWeekly = "weekly"
)

// CVEMode is the cve.mode value (Requirement 17.3).
type CVEMode string

// Modes for cve.mode.
const (
	CVEModeDB    CVEMode = "db"
	CVEModeGraph CVEMode = "graph"
	CVEModeBoth  CVEMode = "both"
)

// ParseCVEMode validates a cve.mode value. On an invalid value it returns prev
// unchanged with an error naming cve.mode and the allowed values (Requirement
// 17.13), so callers keep the previously effective mode.
func ParseCVEMode(prev CVEMode, v string) (CVEMode, error) {
	switch m := CVEMode(strings.ToLower(strings.TrimSpace(v))); m {
	case CVEModeDB, CVEModeGraph, CVEModeBoth:
		return m, nil
	}
	return prev, fmt.Errorf("invalid cve.mode %q: want db, graph or both", v)
}

const (
	day = 24 * time.Hour

	DefaultCVEWarnAfter  = 7 * day
	DefaultCVEStaleAfter = 30 * day
	DefaultCVEMaxChain   = 30
	// DefaultCVEStaleLimit is the cve.stale_limit default: DB_Mode data older
	// than this adds a stale warning (Requirement 17.7).
	DefaultCVEStaleLimit = 7 * day
)

// CVE holds the cve.* configuration keys (Requirements 19.9, 19.13, 19.14,
// 19.17, 19.19). Each key is read from the environment variable named
// BELLUCODE_ plus the key in upper case with "." replaced by "_", for example
// BELLUCODE_CVE_MIRROR_URL.
type CVE struct {
	MirrorURL  string        // cve.mirror_url: empty means the default host
	AutoUpdate string        // cve.auto_update: off (default), daily or weekly
	WarnAfter  time.Duration // cve.warn_after: default 7 days
	StaleAfter time.Duration // cve.stale_after: default 30 days
	// UserAgent is cve.user_agent. UserAgentSet distinguishes "set to empty"
	// (send an empty User-Agent) from "not set" (send the fixed default).
	UserAgent    string
	UserAgentSet bool
	MaxChain     int           // cve.max_delta_chain: 1 to 365, default 30
	Mode         CVEMode       // cve.mode: db (default), graph or both
	StaleLimit   time.Duration // cve.stale_limit: default 7 days

	// Graph_Mode (Requirements 17.3, 17.8-17.10).
	BSKGURL       string        // cve.bskg_url: https, or http only for a loopback host
	BSKGKey       Secret        // BELLUCODE_CVE_BSKG_API_KEY or vault entry cve/bskg_api_key
	GraphCacheTTL time.Duration // cve.graph_cache_ttl: 1 s to 24 h, default 10 min
	BSKGTimeout   time.Duration // cve.bskg_timeout: default 10 s
}

// Graph_Mode defaults and bounds.
const (
	DefaultGraphCacheTTL = 10 * time.Minute
	MinGraphCacheTTL     = time.Second
	MaxGraphCacheTTL     = 24 * time.Hour
	DefaultBSKGTimeout   = 10 * time.Second
	// BSKGVaultEntry is the connectors vault entry holding the BSKG API key.
	BSKGVaultEntry = "cve/bskg_api_key"
)

// Secret is a credential value. Its String, GoString, Format and MarshalText
// never reveal the value; use Reveal at the single point of use.
type Secret string

const redactedBSKGKey = "[REDACTED:bskg_key]"

func (s Secret) String() string   { return redactedBSKGKey }
func (s Secret) GoString() string { return redactedBSKGKey }
func (s Secret) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte(redactedBSKGKey))
}
func (s Secret) MarshalText() ([]byte, error) { return []byte(redactedBSKGKey), nil }

// Reveal returns the raw key for use in an Authorization header.
func (s Secret) Reveal() string { return string(s) }

// VaultLookup reads an entry from the connectors vault. The daemon sets it at
// startup; it is nil when no vault is open. The key is never read from a file.
var VaultLookup func(entry string) (string, bool)

// ValidateBSKGURL requires https, except for a loopback host. The error names
// cve.bskg_url and maps to the gap cause not_configured.
func ValidateBSKGURL(raw string) error {
	u, err := url.Parse(raw)
	bad := fmt.Errorf("invalid cve.bskg_url %q: want an https URL (http only for a loopback host)", raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return bad
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		h := u.Hostname()
		if h == "localhost" {
			return nil
		}
		if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return bad
}

// String and Format redact the key so a CVE value is safe to log.
func (c CVE) String() string {
	return fmt.Sprintf("cve{mode=%s bskg_url=%s bskg_key=%s graph_cache_ttl=%s bskg_timeout=%s}",
		c.Mode, c.BSKGURL, c.BSKGKey, c.GraphCacheTTL, c.BSKGTimeout)
}

// Format makes %v and %+v use String; the key is a Secret regardless.
func (c CVE) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(c.String())) }

// LoadCVE reads and validates the cve.* keys through env (use os.LookupEnv
// in production). An empty cve.user_agent counts as set; an empty value of any
// other key counts as unset.
func LoadCVE(env func(string) (string, bool)) (CVE, error) {
	c := CVE{
		AutoUpdate: AutoUpdateOff,
		WarnAfter:  DefaultCVEWarnAfter,
		StaleAfter: DefaultCVEStaleAfter,
		MaxChain:   DefaultCVEMaxChain,
		Mode:       CVEModeDB,
		StaleLimit: DefaultCVEStaleLimit,

		GraphCacheTTL: DefaultGraphCacheTTL,
		BSKGTimeout:   DefaultBSKGTimeout,
	}
	lookup := func(key string) (string, bool) {
		v, _ := env(envName(key))
		v = strings.TrimSpace(v)
		return v, v != ""
	}

	if v, ok := lookup("cve.mirror_url"); ok {
		if err := ValidateMirrorURL(v); err != nil {
			return c, err
		}
		c.MirrorURL = v
	}
	if v, ok := lookup("cve.auto_update"); ok {
		switch strings.ToLower(v) {
		case AutoUpdateOff, AutoUpdateDaily, AutoUpdateWeekly:
			c.AutoUpdate = strings.ToLower(v)
		default:
			return c, fmt.Errorf("invalid cve.auto_update %q: want off, daily or weekly", v)
		}
	}
	if v, ok := lookup("cve.mode"); ok {
		m, err := ParseCVEMode(c.Mode, v)
		if err != nil {
			return c, err
		}
		c.Mode = m
	}
	var err error
	if v, ok := lookup("cve.stale_limit"); ok {
		if c.StaleLimit, err = parseAge("cve.stale_limit", v); err != nil {
			return c, err
		}
	}
	if v, ok := lookup("cve.warn_after"); ok {
		if c.WarnAfter, err = parseAge("cve.warn_after", v); err != nil {
			return c, err
		}
	}
	if v, ok := lookup("cve.stale_after"); ok {
		if c.StaleAfter, err = parseAge("cve.stale_after", v); err != nil {
			return c, err
		}
	}
	if c.WarnAfter > c.StaleAfter {
		return c, fmt.Errorf("cve.warn_after (%s) must not exceed cve.stale_after (%s)", c.WarnAfter, c.StaleAfter)
	}
	if v, ok := env(envName("cve.user_agent")); ok {
		c.UserAgent, c.UserAgentSet = v, true
	}
	if v, ok := lookup("cve.max_delta_chain"); ok {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 365 {
			return c, fmt.Errorf("invalid cve.max_delta_chain %q: want an integer from 1 to 365", v)
		}
		c.MaxChain = n
	}
	if v, ok := lookup("cve.bskg_url"); ok {
		if err := ValidateBSKGURL(v); err != nil {
			return c, err
		}
		c.BSKGURL = v
	}
	if v, ok := lookup("cve.graph_cache_ttl"); ok {
		d, err := time.ParseDuration(v)
		if err != nil || d < MinGraphCacheTTL || d > MaxGraphCacheTTL {
			return c, fmt.Errorf("invalid cve.graph_cache_ttl %q: want a duration from 1s to 24h", v)
		}
		c.GraphCacheTTL = d
	}
	if v, ok := lookup("cve.bskg_timeout"); ok {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return c, fmt.Errorf("invalid cve.bskg_timeout %q: want a positive duration", v)
		}
		c.BSKGTimeout = d
	}
	if v, ok := lookup("cve.bskg_api_key"); ok {
		c.BSKGKey = Secret(v)
	} else if VaultLookup != nil {
		if v, ok := VaultLookup(BSKGVaultEntry); ok && strings.TrimSpace(v) != "" {
			c.BSKGKey = Secret(strings.TrimSpace(v))
		}
	}
	return c, nil
}

func envName(key string) string {
	return "BELLUCODE_" + strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
}

// ValidateMirrorURL checks cve.mirror_url / --mirror: an http or https URL with
// a host and no query, fragment or credentials.
func ValidateMirrorURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" ||
		u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return fmt.Errorf("invalid cve.mirror_url %q: want an http(s) URL with no query, fragment or credentials", raw)
	}
	return nil
}

// parseAge accepts "<n>d" (days) or any time.ParseDuration value.
func parseAge(key, v string) (time.Duration, error) {
	var d time.Duration
	if n, ok := strings.CutSuffix(v, "d"); ok {
		days, err := strconv.Atoi(n)
		if err != nil {
			return 0, fmt.Errorf("invalid %s %q", key, v)
		}
		d = time.Duration(days) * day
	} else {
		var err error
		if d, err = time.ParseDuration(v); err != nil {
			return 0, fmt.Errorf("invalid %s %q", key, v)
		}
	}
	if d <= 0 {
		return 0, fmt.Errorf("invalid %s %q: must be positive", key, v)
	}
	return d, nil
}

// LoadCVEEnv loads the cve.* keys from the process environment.
func LoadCVEEnv() (CVE, error) { return LoadCVE(os.LookupEnv) }
