// Package canonical derives normalized cross-provider keys for entities.
// It is pure: it imports only the standard library.
package canonical

import (
	"net/url"
	"regexp"
	"strings"
)

// AttrCanonicalKey is the descriptive entity attribute that holds a key. It is
// never an identity attribute.
const AttrCanonicalKey = "canonical_key"

// Source identifier kinds accepted by Key.
const (
	KindARN   = "arn"
	KindPurl  = "purl"
	KindVuln  = "vuln"
	KindImage = "image"
	KindGit   = "git"
)

var (
	vulnPattern  = regexp.MustCompile(`^(CVE-\d{4}-\d{4,}|GHSA(-[A-Z0-9]{4}){3})$`)
	imagePattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Key returns the canonical key for raw interpreted as kind. It returns false
// when no key can be derived. Key(kind, Key(kind, x)) equals Key(kind, x).
func Key(kind, raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	switch kind {
	case KindARN:
		return arnKey(raw)
	case KindPurl:
		return purlKey(raw)
	case KindVuln:
		return vulnKey(raw)
	case KindImage:
		return imageKey(raw)
	case KindGit:
		return gitKey(raw)
	}
	return "", false
}

func arnKey(raw string) (string, bool) {
	parts := strings.SplitN(raw, ":", 6)
	if len(parts) != 6 || !strings.EqualFold(parts[0], "arn") || parts[1] == "" || parts[2] == "" || parts[5] == "" {
		return "", false
	}
	for i := range 5 {
		parts[i] = strings.ToLower(parts[i])
	}
	return strings.Join(parts, ":"), true
}

func purlKey(raw string) (string, bool) {
	if i := strings.IndexByte(raw, '#'); i >= 0 {
		raw = raw[:i]
	}
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		raw = raw[:i]
	}
	if len(raw) < 4 || !strings.EqualFold(raw[:4], "pkg:") {
		return "", false
	}
	// The version separator is the last "@" after the final "/"; an earlier
	// "@" belongs to an npm scope.
	slash := strings.LastIndexByte(raw, '/')
	at := strings.LastIndexByte(raw, '@')
	var out string
	if at > slash {
		out = strings.ToLower(raw[:at]) + raw[at:]
	} else {
		out = strings.ToLower(raw)
	}
	if slash < 0 || slash == len(raw)-1 {
		return "", false
	}
	return out, true
}

func vulnKey(raw string) (string, bool) {
	id := strings.ToUpper(raw)
	id = strings.TrimPrefix(id, "VULN:")
	if !vulnPattern.MatchString(id) {
		return "", false
	}
	return "vuln:" + id, true
}

func imageKey(raw string) (string, bool) {
	raw = strings.ToLower(raw)
	if !imagePattern.MatchString(raw) {
		return "", false
	}
	return raw, true
}

func gitKey(raw string) (string, bool) {
	lower := strings.ToLower(raw)
	var host, path string
	switch {
	case strings.Contains(lower, "://"):
		u, err := url.Parse(lower)
		if err != nil {
			return "", false
		}
		host, path = u.Hostname(), u.Path
	case strings.HasPrefix(lower, "git:"):
		// An already normalized key: git:<host>/<owner>/<repo>.
		rest := strings.TrimPrefix(lower, "git:")
		host, path, _ = strings.Cut(rest, "/")
	default:
		// scp-like form: [user@]host:owner/repo
		authority, p, ok := strings.Cut(lower, ":")
		if !ok {
			return "", false
		}
		if i := strings.LastIndexByte(authority, '@'); i >= 0 {
			authority = authority[i+1:]
		}
		host, path = authority, p
		if i := strings.IndexAny(path, "?#"); i >= 0 {
			path = path[:i]
		}
	}
	path = strings.Trim(path, "/")
	path = strings.TrimSuffix(path, ".git")
	path = strings.Trim(path, "/")
	if host == "" || strings.ContainsAny(host, " /@") || strings.Count(path, "/") < 1 || strings.Contains(path, "//") {
		return "", false
	}
	return "git:" + host + "/" + path, true
}
