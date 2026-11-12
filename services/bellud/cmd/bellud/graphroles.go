package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	apigraph "github.com/bellu/bellucode/services/bellud/internal/api/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/mcptoken"
	"github.com/bellu/bellucode/services/bellud/internal/server/routes"
)

const (
	graphTokensFile = "graph-tokens.json"
	frontDoor       = "front-door"
)

// grantsOf returns the bearer grants for every role in set.
func grantsOf(set mcptoken.Set) []graph.Grant {
	return []graph.Grant{
		{Token: set.Read.String(), Role: graph.RoleRead},
		{Token: set.Ingest.String(), Role: graph.RoleIngest},
		{Token: set.Write.String(), Role: graph.RoleWrite},
	}
}

// writeGraphTokens replaces dir/graph-tokens.json with the read and ingest
// tokens (mode 0600, temp file in the same directory, then rename).
func writeGraphTokens(dir string, set mcptoken.Set) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(map[string]string{"read": set.Read.String(), "ingest": set.Ingest.String()})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, graphTokensFile+".*.tmp") // created 0600
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, graphTokensFile))
}

// graphTokenRoute reports whether the route pattern accepts graph tokens in
// addition to bellud credentials. MCP is token-only and handled separately;
// debug and metrics take bellud credentials only.
func graphTokenRoute(pattern string) bool {
	p := strings.TrimPrefix(pattern, apigraph.Prefix)
	if p == pattern {
		return false
	}
	switch {
	case p == "/mcp", p == "/debug", p == "/metrics", strings.HasPrefix(p, "/debug/"):
		return false
	}
	return true
}

// requiredRole is the role a request to a graph route needs. Annotation needs
// write but is enforced inside the MCP and GraphQL layers via the Caller.
func requiredRole(r *http.Request) graph.Role {
	if r.Method == http.MethodPost && strings.TrimPrefix(r.URL.Path, apigraph.Prefix) == "/batches" {
		return graph.RoleIngest
	}
	return graph.RoleRead
}

// roleMiddleware attaches the Caller (token role, or write for bellud
// credentials) and rejects callers whose role does not allow the route.
func roleMiddleware(set mcptoken.Set, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller := graph.Caller{Role: graph.RoleWrite, Identity: frontDoor}
		if role, tok, ok := set.RoleOf(r); ok {
			caller = graph.Caller{Role: graph.Role(role), Identity: tok.Identity()}
		}
		if !caller.Role.Allows(requiredRole(r)) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"code":"graph_forbidden"}`))
			return
		}
		next.ServeHTTP(w, r.WithContext(graph.WithCaller(r.Context(), caller)))
	})
}

// graphGoAuth builds the per-route authorizers: MCP is bearer-token-only (any role), token
// routes accept any graph token or bellud credentials, debug and metrics keep
// the default (bellud credentials only).
func graphGoAuth(table *routes.Table, set mcptoken.Set, authorize func(*http.Request) bool) map[string]func(*http.Request) bool {
	// MCP is bearer-only: any graph token passes here and the role middleware
	// and tool layer enforce its role; bellud credentials do not open it.
	m := map[string]func(*http.Request) bool{apigraph.Prefix + "/mcp": func(r *http.Request) bool {
		_, _, ok := set.RoleOf(r)
		return ok
	}}
	tokenOrAuth := func(r *http.Request) bool {
		_, _, ok := set.RoleOf(r)
		return ok || authorize(r)
	}
	for _, rt := range table.Routes() {
		if rt.Owner == routes.OwnerGo && graphTokenRoute(rt.Pattern) {
			m[rt.Pattern] = tokenOrAuth
		}
	}
	return m
}
