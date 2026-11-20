package config

import (
	"fmt"
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

const (
	day = 24 * time.Hour

	DefaultCVEWarnAfter  = 7 * day
	DefaultCVEStaleAfter = 30 * day
	DefaultCVEMaxChain   = 30
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
	MaxChain     int // cve.max_delta_chain: 1 to 365, default 30
}

// LoadCVE reads and validates the cve.* keys through env (use os.LookupEnv
// in production). An empty cve.user_agent counts as set; an empty value of any
// other key counts as unset.
func LoadCVE(env func(string) (string, bool)) (CVE, error) {
	c := CVE{
		AutoUpdate: AutoUpdateOff,
		WarnAfter:  DefaultCVEWarnAfter,
		StaleAfter: DefaultCVEStaleAfter,
		MaxChain:   DefaultCVEMaxChain,
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
	var err error
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
