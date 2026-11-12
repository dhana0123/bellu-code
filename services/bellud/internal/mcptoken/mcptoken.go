// Package mcptoken holds the per-start bearer token that guards the graph MCP
// endpoint. The token lives in memory only and is accepted on that endpoint
// alone; every other route authorizes with Basic/session credentials, so a
// Bearer header never satisfies them.
package mcptoken

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
)

// Path is the only route that accepts the token.
const Path = "/api/experimental/graph/mcp"

const tokenBytes = 32

// Token is an opaque per-start MCP bearer token.
type Token struct{ value string }

// New generates a token from 32 bytes of crypto/rand (base64url, unpadded).
func New() (Token, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return Token{}, err
	}
	return Token{value: base64.RawURLEncoding.EncodeToString(b)}, nil
}

// String returns the raw token (for Config.MCPToken and handing to clients).
func (t Token) String() string { return t.value }

// Header returns the Authorization header value for the token.
func (t Token) Header() string { return "Bearer " + t.value }

// Identity returns a non-reversible audit identity ("token:<sha256 prefix>");
// it matches facade.TokenIdentity.
func (t Token) Identity() string {
	sum := sha256.Sum256([]byte(t.value))
	return "token:" + hex.EncodeToString(sum[:6])
}

// Verify reports whether r carries this token as a Bearer credential. The
// comparison is constant time (over fixed-length digests).
func (t Token) Verify(r *http.Request) bool {
	if t.value == "" {
		return false
	}
	const p = "bearer "
	h := r.Header.Get("Authorization")
	if len(h) < len(p) || !strings.EqualFold(h[:len(p)], p) {
		return false
	}
	got := sha256.Sum256([]byte(strings.TrimSpace(h[len(p):])))
	want := sha256.Sum256([]byte(t.value))
	return subtle.ConstantTimeCompare(got[:], want[:]) == 1
}
