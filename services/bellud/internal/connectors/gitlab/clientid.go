package gitlab

import "strings"

// ClientID is the public OAuth application ID for GitLab device sign-in. It is
// not a secret. Empty means GitLab device sign-in is unavailable until a fork
// or user sets BELLUCODE_GITLAB_CLIENT_ID.
const ClientID = ""

// EnvClientID overrides ClientID.
const EnvClientID = "BELLUCODE_GITLAB_CLIENT_ID"

// EffectiveClientID returns the trimmed, non-empty environment override, else
// the compiled ClientID.
func EffectiveClientID(getenv func(string) string) string {
	if v := strings.TrimSpace(getenv(EnvClientID)); v != "" {
		return v
	}
	return ClientID
}
