// Package bskg is the read-only client for the Bellu security knowledge graph
// (BSKG) used by the seek retrieval core.
package bskg

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

const (
	envURL = "BELLUCODE_SEEK_BSKG_URL"
	envKey = "BELLUCODE_SEEK_BSKG_KEY"

	redacted = "[REDACTED]"
)

// Secret is an API key that never prints its value.
type Secret string

func (Secret) String() string   { return redacted }
func (Secret) GoString() string { return redacted }

// Format redacts the key for every fmt verb.
func (Secret) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// Config is the BSKG connection setting.
type Config struct {
	BaseURL string
	Key     Secret
	Timeout time.Duration
}

// Configured reports whether the config is usable: a non-blank key and a base
// URL that is https (or http to a loopback host) with no userinfo, query or
// fragment.
func (c Config) Configured() bool {
	_, ok := c.baseURL()
	return ok && strings.TrimSpace(string(c.Key)) != ""
}

func (c Config) baseURL() (*url.URL, bool) {
	raw := strings.TrimSpace(c.BaseURL)
	if raw == "" || strings.ContainsAny(raw, "?#") {
		return nil, false
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Host == "" || u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, false
	}
	switch u.Scheme {
	case "https":
		return u, true
	case "http":
		return u, loopback(u.Hostname())
	}
	return nil, false
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Load reads the config from the environment. A missing pair is not an error
// (ok is false); an invalid one also returns ok=false with an error that names
// the variable and never its value.
func Load(env func(string) (string, bool)) (Config, bool, error) {
	rawURL, _ := env(envURL)
	rawKey, _ := env(envKey)
	cfg := Config{BaseURL: strings.TrimSpace(rawURL), Key: Secret(strings.TrimSpace(rawKey))}
	if cfg.BaseURL == "" || cfg.Key == "" {
		return Config{}, false, nil
	}
	if !cfg.Configured() {
		return Config{}, false, fmt.Errorf("%s is not a valid https URL (http is allowed for loopback only, without userinfo, query or fragment)", envURL)
	}
	return cfg, true, nil
}
