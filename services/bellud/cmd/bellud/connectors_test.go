package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	apiconn "github.com/bellu/bellucode/services/bellud/internal/api/connectors"
	apigraph "github.com/bellu/bellucode/services/bellud/internal/api/graph"
	"github.com/bellu/bellucode/services/bellud/internal/auth"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/server"
	"github.com/bellu/bellucode/services/bellud/internal/server/routes"
)

type nopLog struct{}

func (nopLog) Println(...any) {}

func openTestEngine(t *testing.T) graph.Engine {
	t.Helper()
	set := newSet(t)
	env := map[string]string{"BELLU_GRAPH_ENABLED": "true", "BELLU_GRAPH_DIR": filepath.Join(t.TempDir(), "g")}
	cfg, err := graph.LoadConfigFrom(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	cfg.MCPToken = set.Write.String()
	cfg.Grants = grantsOf(set)
	eng, err := graph.Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { eng.Close(context.Background()) })
	return eng
}

func TestConnectorsFlagOffRegistersNothing(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("BELLUCODE_FLAGS", "-connectors")
	if w := openConnectors(nopLog{}, openTestEngine(t), newSet(t), nil); w != nil {
		t.Fatal("wiring must be nil with the flag off")
	}
	if _, err := os.Stat(filepath.Join(home, ".local", "share", "bellucode", "connectors")); !os.IsNotExist(err) {
		t.Fatalf("connectors dir created while flag off: %v", err)
	}
	var w *connectorWiring
	next := http.NotFoundHandler()
	if w.wrap(next) == nil || len(w.auth(map[string]func(*http.Request) bool{})) != 0 {
		t.Fatal("nil wiring must be a no-op")
	}
	w.close(nopLog{}) // must not panic
}

func TestConnectorsFlagOnSkippedWithoutGraph(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("BELLUCODE_FLAGS", "connectors")
	if w := openConnectors(nopLog{}, nil, newSet(t), nil); w != nil {
		t.Fatal("no graph engine must skip connectors")
	}
}

func TestConnectorsRouteOwnershipAndAuth(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("BELLUCODE_FLAGS", "connectors")
	set := newSet(t)
	eng := openTestEngine(t)
	w := openConnectors(nopLog{}, eng, set, nil)
	if w == nil {
		t.Fatal("expected wiring")
	}
	t.Cleanup(func() { w.close(nopLog{}) })

	table := routes.MustLoadEmbedded()
	authn := auth.New("pw")
	srv := &server.Server{
		Table:  table,
		Auth:   authn,
		Go:     w.wrap(goHandler(eng, set, func() apigraph.ChildState { return apigraph.ChildReady })),
		GoAuth: w.auth(graphGoAuth(table, set, authn.Authorize)),
		Proxy:  http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusTeapot) }),
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	do := func(path string, c caller) int {
		code, _ := c.do(t, http.MethodGet, ts.URL+path, "", nil)
		return code
	}
	status := apiconn.Prefix + "/status"
	if got := do(status, caller{basic: true}); got != http.StatusOK {
		t.Fatalf("status with bellud credentials: %d", got)
	}
	for name, c := range map[string]caller{
		"none": {}, "graph write": {bearer: set.Write.String()}, "graph read": {bearer: set.Read.String()},
		"connector token": {bearer: w.token.String()},
	} {
		if got := do(status, c); got != http.StatusUnauthorized {
			t.Errorf("%s on connector API: %d, want 401", name, got)
		}
	}
	// The MCP route takes the connector token only.
	for name, c := range map[string]caller{
		"none": {}, "basic": {basic: true}, "graph write": {bearer: set.Write.String()},
	} {
		if got := do(apiconn.Path, c); got != http.StatusUnauthorized {
			t.Errorf("%s on connector MCP: %d, want 401", name, got)
		}
	}
	if got := do(apiconn.Path, caller{bearer: w.token.String()}); got == http.StatusUnauthorized || got == http.StatusNotFound || got == http.StatusTeapot {
		t.Errorf("connector token on MCP: %d", got)
	}
	// The graph MCP does not accept the connector token.
	if got := do(apigraph.Prefix+"/mcp", caller{bearer: w.token.String()}); got != http.StatusUnauthorized {
		t.Errorf("connector token on graph MCP: %d, want 401", got)
	}
}

func TestConnectorRoutesAreGoOwned(t *testing.T) {
	table := routes.MustLoadEmbedded()
	n := 0
	for _, rt := range table.Routes() {
		if len(rt.Pattern) >= len(apiconn.Prefix) && rt.Pattern[:len(apiconn.Prefix)] == apiconn.Prefix {
			n++
			if rt.Owner != routes.OwnerGo {
				t.Errorf("%s %s owned by %v", rt.Method, rt.Pattern, rt.Owner)
			}
		}
	}
	if n == 0 {
		t.Fatal("no connector routes in table")
	}
}
