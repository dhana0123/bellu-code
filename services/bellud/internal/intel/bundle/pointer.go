package bundle

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"time"
)

// MaxBundleSize is the largest bundle_size a pointer may declare.
const MaxBundleSize = 1 << 30

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Pointer is the parsed latest.json.
type Pointer struct {
	Schema       int       `json:"schema"`
	Version      string    `json:"version"`
	CreatedAt    time.Time `json:"created_at"`
	BundleURL    string    `json:"bundle_url"`
	BundleSHA256 string    `json:"bundle_sha256"`
	BundleSize   int64     `json:"bundle_size"`
}

// ParsePointer decodes and validates a latest.json document. Unknown fields are
// ignored.
func ParsePointer(data []byte) (Pointer, error) {
	var p Pointer
	if err := json.Unmarshal(data, &p); err != nil {
		return Pointer{}, fmt.Errorf("pointer_invalid: %w", err)
	}
	switch {
	case p.Schema != 1:
		return Pointer{}, fmt.Errorf("pointer_invalid: schema %d", p.Schema)
	case p.Version == "" || len(p.Version) > 64:
		return Pointer{}, fmt.Errorf("pointer_invalid: version")
	case p.CreatedAt.IsZero():
		return Pointer{}, fmt.Errorf("pointer_invalid: created_at")
	case !validBundleURL(p.BundleURL):
		return Pointer{}, fmt.Errorf("pointer_invalid: bundle_url")
	case !sha256Hex.MatchString(p.BundleSHA256):
		return Pointer{}, fmt.Errorf("pointer_invalid: bundle_sha256")
	case p.BundleSize <= 0 || p.BundleSize > MaxBundleSize:
		return Pointer{}, fmt.Errorf("pointer_invalid: bundle_size")
	}
	p.CreatedAt = p.CreatedAt.UTC()
	return p, nil
}

// validBundleURL accepts an https URL, an http URL on a loopback host, or a
// relative reference.
func validBundleURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil || s == "" || u.Fragment != "" || u.User != nil {
		return false
	}
	switch u.Scheme {
	case "https":
		return u.Host != ""
	case "http":
		host := u.Hostname()
		ip := net.ParseIP(host)
		return host == "localhost" || (ip != nil && ip.IsLoopback())
	case "":
		return u.Host == ""
	}
	return false
}
