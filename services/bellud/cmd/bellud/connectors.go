package main

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	apiconn "github.com/bellu/bellucode/services/bellud/internal/api/connectors"
	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/config"
	"github.com/bellu/bellucode/services/bellud/internal/connectors"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/mcptoken"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
)

// connectorWiring is the connector surface of the process. It is nil while the
// flag is off or the graph engine is unavailable, in which case nothing is
// registered, opened or injected.
type connectorWiring struct {
	svc   *connectors.Service
	token mcptoken.Token // separate from the graph token set; opens only the MCP route
	api   http.Handler
	mcp   http.Handler
}

// openConnectors builds and starts the connector service. A disabled flag, a
// missing graph engine or any failure yields nil and serving continues.
func openConnectors(logger interface{ Println(...any) }, eng graph.Engine, set mcptoken.Set, allowedHosts []string, fnd *findingsWiring) *connectorWiring {
	if !connectors.Enabled(os.Getenv) {
		return nil
	}
	if eng == nil {
		logger.Println("warning: connectors unavailable: graph engine is not open")
		return nil
	}
	dd, err := config.DataDir()
	if err != nil {
		logger.Println("warning: connectors unavailable:", err)
		return nil
	}
	ctx := context.Background()
	svc, err := connectors.New(ctx, connectors.Options{
		Engine: eng, Dir: filepath.Join(dd, "connectors"), Getenv: os.Getenv, Logger: logger,
		// Key material sources; the values are never logged and both variables
		// are stripped from the TS child environment.
		KeyFile:    os.Getenv("BELLUCODE_MASTER_KEY_FILE"),
		Passphrase: envPassphrase(os.Getenv),
		GapSink:    fnd.gapSink(),
		GapsFor:    fnd.gapsFor(),
	})
	if err != nil || !svc.Enabled() {
		if err != nil {
			logger.Println("warning: connectors unavailable:", err)
		}
		return nil
	}
	if err := svc.Start(ctx); err != nil {
		logger.Println("warning: connectors start:", err)
		_ = svc.Close(ctx)
		return nil
	}
	tok, err := mcptoken.New()
	if err != nil {
		logger.Println("warning: connectors mcp token:", err)
		_ = svc.Close(ctx)
		return nil
	}
	w := &connectorWiring{svc: svc, token: tok}
	mcp, err := apiconn.NewMCP(apiconn.Config{
		Token: tok, Broker: svc.Broker(), Resolver: connectors.NewResolver(svc), Audit: svc.Audit(),
		Enabled: svc.Enabled,
	})
	if err != nil {
		logger.Println("warning: connectors mcp:", err)
		_ = svc.Close(ctx)
		return nil
	}
	w.mcp = mcp
	w.api = apiconn.NewAPI(apiconn.APIConfig{Service: svc, Scope: svc.Scope(), Role: connectorRole(set, tok), AllowedHosts: allowedHosts})
	return w
}

// connectorRole names the caller role of a request that already passed bellud
// authentication. Anything carrying a graph or connector token is never "user",
// so it can never write a credential.
func connectorRole(set mcptoken.Set, tok mcptoken.Token) func(*http.Request) string {
	return func(r *http.Request) string {
		if _, _, ok := set.RoleOf(r); ok {
			return "mcp"
		}
		if tok.Verify(r) {
			return "agent"
		}
		return apiconn.RoleUser
	}
}

// close stops the service; safe on nil.
func (w *connectorWiring) close(logger interface{ Println(...any) }) {
	if w == nil {
		return
	}
	c, cancel := context.WithTimeout(context.Background(), childStopTimeout)
	defer cancel()
	if err := w.svc.Close(c); err != nil {
		logger.Println("connectors close:", err)
	}
}

// wrap mounts the connector routes on a top-level mux in front of next (the
// graph handler with its role middleware). With w nil it returns next.
func (w *connectorWiring) wrap(next http.Handler) http.Handler {
	if w == nil {
		return next
	}
	mux := http.NewServeMux()
	mux.Handle(apiconn.Path, w.mcp)
	mux.Handle(apiconn.Prefix+"/", w.api)
	mux.Handle("/", next)
	return mux
}

// auth adds the bearer-only authorizer of the connector MCP path. Every other
// connector route keeps the default bellud authorizer, which accepts neither
// graph tokens nor the connector token.
func (w *connectorWiring) auth(m map[string]func(*http.Request) bool) map[string]func(*http.Request) bool {
	if w != nil {
		m[apiconn.Path] = w.token.Verify
	}
	return m
}

// allowedHostsOf returns the configured listen hostname as an extra allowed
// Host for credential writes (wildcard binds add nothing).
func allowedHostsOf(hostname string) []string {
	h := strings.ToLower(strings.Trim(strings.TrimSpace(hostname), "[]"))
	switch h {
	case "", "0.0.0.0", "::":
		return nil
	}
	return []string{h}
}

// envPassphrase answers the passphrase key source from
// BELLUCODE_VAULT_PASSPHRASE. It returns nil when the variable is unset, so the
// source then waits for an Unlock call.
func envPassphrase(getenv func(string) string) func(context.Context) ([]byte, error) {
	pw := getenv("BELLUCODE_VAULT_PASSPHRASE")
	if pw == "" {
		return nil
	}
	return func(context.Context) ([]byte, error) { return []byte(pw), nil }
}

// gapSink writes the gaps of each collector run to collector_gap. Nil without
// the findings database.
func (w *findingsWiring) gapSink() collectors.GapSink {
	if w == nil {
		return nil
	}
	return func(ctx context.Context, collector string, gaps []collectors.Gap, runAt time.Time) error {
		rows := make([]sqlite.CollectorGap, 0, len(gaps))
		for _, g := range gaps {
			rows = append(rows, sqlite.CollectorGap{Connector: collector, ResourceType: g.ResourceType, Scope: g.Scope, Reason: g.Reason, Detail: g.Detail})
		}
		return w.db.ReplaceCollectorGaps(ctx, collector, rows, runAt)
	}
}

// gapsFor reads the stored gaps for the connector status route.
func (w *findingsWiring) gapsFor() func(context.Context, string) ([]store.Gap, error) {
	if w == nil {
		return nil
	}
	return func(ctx context.Context, collector string) ([]store.Gap, error) {
		rows, err := w.db.ListCollectorGaps(ctx, collector)
		out := make([]store.Gap, 0, len(rows))
		for _, g := range rows {
			out = append(out, store.Gap{ResourceType: g.ResourceType, Scope: g.Scope, Reason: g.Reason, Detail: g.Detail})
		}
		return out, err
	}
}
