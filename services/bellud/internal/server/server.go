// Package server is the Bellud front door: it resolves routes, applies CORS
// and authentication, and dispatches to Go handlers or the TS proxy.
package server

import (
	"net/http"
	"strings"

	"github.com/bellu/bellucode/services/bellud/internal/auth"
	"github.com/bellu/bellucode/services/bellud/internal/server/routes"
)

// Server is the http.Handler on the public port.
type Server struct {
	Table routes.RouteTable
	Auth  auth.Authenticator
	// Go serves routes owned by Go; Proxy serves routes owned by TS.
	Go    http.Handler
	Proxy http.Handler
	// CORS lists allowed origins (BELLUCODE_CORS); matched exactly.
	CORS []string
	// GoAuth overrides authentication for non-public routes, keyed by
	// Route.Pattern. A route with an entry is authorized by that function
	// instead of Auth (e.g. the graph MCP endpoint's bearer token).
	GoAuth map[string]func(*http.Request) bool
	// StrictAPI makes unmatched API-side paths answer 404 after
	// authentication instead of falling through to the default owner (ts).
	// Enable once the Go side owns the whole API surface.
	StrictAPI bool
}

// IsAPIPath reports whether the cleaned path belongs to the API side.
func IsAPIPath(p string) bool {
	return p == "/api" || strings.HasPrefix(p, "/api/") ||
		strings.HasPrefix(p, "/auth/") || p == "/auth" || p == "/openapi.json"
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.applyCORS(w, r) && r.Method == http.MethodOptions &&
		r.Header.Get("Access-Control-Request-Method") != "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	clean := routes.CleanPath(r.URL.Path)
	route, found := s.Table.Lookup(r.Method, clean)

	if found && route.Public {
		s.dispatch(w, r, route.Owner)
		return
	}
	if !found && s.StrictAPI && IsAPIPath(clean) {
		if !s.Auth.Authorize(r) {
			auth.WriteUnauthorized(w)
			return
		}
		http.NotFound(w, r)
		return
	}
	authorize := s.Auth.Authorize
	if found {
		if fn, ok := s.GoAuth[route.Pattern]; ok && fn != nil {
			authorize = fn
		}
	}
	if !authorize(r) {
		auth.WriteUnauthorized(w)
		return
	}
	owner := routes.OwnerTS
	if found {
		owner = route.Owner
	}
	s.dispatch(w, r, owner)
}

func (s *Server) dispatch(w http.ResponseWriter, r *http.Request, o routes.Owner) {
	if o == routes.OwnerGo {
		s.Go.ServeHTTP(w, r)
		return
	}
	s.Proxy.ServeHTTP(w, r)
}

// applyCORS adds headers when Origin exactly matches a configured origin and
// reports whether it did.
func (s *Server) applyCORS(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	for _, o := range s.CORS {
		if o == origin {
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", origin)
			h.Add("Vary", "Origin")
			if r.Method == http.MethodOptions {
				h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
				if rh := r.Header.Get("Access-Control-Request-Headers"); rh != "" {
					h.Set("Access-Control-Allow-Headers", rh)
				} else {
					h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				}
			}
			return true
		}
	}
	return false
}
