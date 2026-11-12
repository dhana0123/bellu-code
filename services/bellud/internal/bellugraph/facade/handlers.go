package facade

import (
	"bytes"
	"context"
	"io"
	"net/http"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/debugui"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/gql"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/sse"
)

const (
	maxGraphQLBodyBytes = 4 << 20
	graphBasePath       = "/api/experimental/graph"
)

// Handlers are the HTTP handlers served under /api/experimental/graph.
// GraphQL and Subscribe resolve the caller like MCPHandler. Debug and Metrics
// do no caller resolution: bellud's front door admits only its own credential.
type Handlers struct {
	GraphQL, Subscribe, Debug, Metrics http.Handler
}

// HandlersOf returns e's handlers, or 503 graph_unavailable handlers when e
// is disabled, failed or not the ready engine.
func HandlersOf(e Engine) Handlers {
	en, ok := e.(*engine)
	if !ok || en.State().Kind != StateReady {
		reason := ""
		if e != nil {
			reason = StateOf(e).Reason
		}
		u := UnavailableHandler(reason)
		return Handlers{GraphQL: u, Subscribe: u, Debug: u, Metrics: u}
	}
	return Handlers{
		GraphQL: en.guarded(gql.New(gql.Options{
			Core:     en.stack,
			Annotate: en.annotateAudited,
			CallerRole: func(ctx context.Context) string {
				c, _ := CallerFrom(ctx)
				return string(c.Role)
			},
		}), maxGraphQLBodyBytes, true),
		Subscribe: en.guarded(sse.New(en.stack, sse.Options{}), 0, true),
		Debug:     en.guarded(debugui.New(en.stack, graphBasePath), 0, false),
		Metrics:   en.guarded(en.stack.Metrics(), 0, false),
	}
}

// guarded checks readiness on every request and, when resolve is set,
// resolves the caller (401 with a Bearer challenge on failure). A positive
// limit caps POST bodies (413).
func (e *engine) guarded(inner http.Handler, limit int, resolve bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if e.State().Kind != StateReady {
			UnavailableHandler(e.State().Reason).ServeHTTP(w, r)
			return
		}
		if resolve {
			caller, err := e.resolveCaller(r)
			if err != nil {
				w.Header().Set("WWW-Authenticate", `Bearer realm="bellu-graph"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			r = r.WithContext(WithCaller(r.Context(), caller))
		}
		if limit > 0 && r.Method == http.MethodPost && r.Body != nil {
			body, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)+1))
			if err != nil || len(body) > limit {
				http.Error(w, "request body unreadable or too large", http.StatusRequestEntityTooLarge)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		inner.ServeHTTP(w, r)
	})
}
