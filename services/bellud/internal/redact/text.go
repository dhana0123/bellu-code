package redact

import (
	"regexp"
	"strings"
)

// FailedPlaceholder is what callers store when Text returns an error.
const FailedPlaceholder = "[REDACTED:failed]"

// pemBlock matches a whole PEM private key so the body is removed, not only the header.
var pemBlock = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|$)`)

// assignment matches key=value and key: value pairs, with optional quotes.
// Groups: 1 key, 2 separator (with quotes and spaces), 3 value.
var assignment = regexp.MustCompile(`([A-Za-z0-9_.-]+)(["']?\s*[=:]\s*)("[^"\n]*"|'[^'\n]*'|[^\s,;&"']+)`)

// Text hides secrets inside free text using ValueRules and KeyRules.
// On error callers must store FailedPlaceholder instead of the input.
func Text(s string) (string, error) {
	out := pemBlock.ReplaceAllString(s, marker("value_private_key_header"))
	out = scrubString(out)
	out = assignment.ReplaceAllStringFunc(out, func(m string) string {
		g := assignment.FindStringSubmatch(m)
		id, ok := keyRule(g[1])
		if !ok {
			return m
		}
		v := strings.Trim(g[3], `"'`)
		if v == "" || isMarker(v) {
			return m
		}
		q := ""
		if c := g[3][0]; c == '"' || c == '\'' {
			q = string(c)
		}
		return g[1] + g[2] + q + marker(id) + q
	})
	if _, leaked := firstValueRule(out); leaked {
		return "", ErrSecretLeak
	}
	return out, nil
}
