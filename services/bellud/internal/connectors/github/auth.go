// Package github is the typed GitHub wrapper for the GitHub connector. It
// speaks plain net/http through the *http.Client that broker.HTTPClient
// builds, so every request passes the policy transport. The MVP supports
// fine-grained personal access tokens only; there is no GitHub App or device
// flow code here.
package github

import (
	"errors"
	"strings"
	"time"
)

// PATPrefix is the prefix of every fine-grained personal access token.
const PATPrefix = "github_pat_"

// UserTokenPrefix is the prefix of a GitHub App user access token.
const UserTokenPrefix = "ghu_"

// ClassicTokenMessage is shown when a token without PATPrefix is submitted.
const ClassicTokenMessage = "Classic tokens are not supported because they cannot be limited to read-only permissions and specific repositories. Create a fine-grained personal access token instead."

// ErrClassicToken is returned for a token that is not a fine-grained PAT.
// Callers must reject before storing anything or creating or changing a
// connection. The error never contains the submitted value.
var ErrClassicToken = errors.New(ClassicTokenMessage)

// ValidateToken enforces the github_pat_ prefix. It is a pure check, with no
// I/O, meant to run before the secret reaches the vault. Surrounding
// whitespace is not trimmed: a token with leading space is rejected.
func ValidateToken(secret []byte) error {
	if len(secret) <= len(PATPrefix) || !strings.HasPrefix(string(secret), PATPrefix) {
		return ErrClassicToken
	}
	return nil
}

// TokenExpiryHeader is the response header GitHub sets on authenticated
// requests made with an expiring token.
const TokenExpiryHeader = "github-authentication-token-expiration"

const tokenExpiryLayout = "2006-01-02 15:04:05 MST"

// ParseTokenExpiry reads the token expiry from a response header value such
// as "2025-08-10 04:00:00 UTC". ok is false when the header is absent or
// malformed (tokens without an expiry omit it).
func ParseTokenExpiry(v string) (t time.Time, ok bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(tokenExpiryLayout, v)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}
