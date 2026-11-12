// Package mcptoken holds the per-start bearer tokens that guard the graph
// routes (MCP, GraphQL, subscribe, HTTP reads, batches, debug and metrics).
// A Set carries one token per role (read, ingest, write). Tokens live in
// memory only and are accepted on graph routes alone; every other route
// authorizes with Basic/session credentials, so a Bearer header never
// satisfies them.
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

// Role is the capability level a graph token grants.
type Role string

const (
	RoleRead   Role = "read"
	RoleIngest Role = "ingest"
	RoleWrite  Role = "write"
)

// Set holds one token per role.
type Set struct{ Read, Ingest, Write Token }

// NewSet returns a Set using write as the write token and minting fresh read
// and ingest tokens.
func NewSet(write Token) (Set, error) {
	read, err := New()
	if err != nil {
		return Set{}, err
	}
	ingest, err := New()
	if err != nil {
		return Set{}, err
	}
	return Set{Read: read, Ingest: ingest, Write: write}, nil
}

// RoleOf reports which role's token r carries as a Bearer credential, checking
// write first. Every comparison is constant time.
func (s Set) RoleOf(r *http.Request) (Role, Token, bool) {
	for _, c := range []struct {
		role Role
		tok  Token
	}{{RoleWrite, s.Write}, {RoleIngest, s.Ingest}, {RoleRead, s.Read}} {
		if c.tok.Verify(r) {
			return c.role, c.tok, true
		}
	}
	return "", Token{}, false
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
