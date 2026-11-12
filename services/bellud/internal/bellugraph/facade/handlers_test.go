package facade

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestHandlersOfReadyEngineServes(t *testing.T) {
	e, _ := mcpEngine(t, "")
	h := HandlersOf(e)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"{ __typename }"}`))
	req.Header.Set("Content-Type", "application/json")
	h.GraphQL.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Query") {
		t.Fatalf("graphql: %d %s", rec.Code, rec.Body)
	}

	rec = httptest.NewRecorder()
	h.Debug.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, graphBasePath+"/debug", nil))
	if rec.Code != 200 || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("debug: %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.Metrics.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != 200 || rec.Body.Len() == 0 {
		t.Fatalf("metrics: %d", rec.Code)
	}

	// Subscribe: a bad method proves the sse handler (not 503) is mounted.
	rec = httptest.NewRecorder()
	h.Subscribe.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/subscribe", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("subscribe: %d", rec.Code)
	}
}

func TestHandlersGraphQLRequiresTokenWhenConfigured(t *testing.T) {
	e, _ := mcpEngine(t, "secret")
	rec := httptest.NewRecorder()
	HandlersOf(e).GraphQL.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/graphql",
		strings.NewReader(`{"query":"{ __typename }"}`)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestHandlersGraphQLBodyLimit(t *testing.T) {
	e, _ := mcpEngine(t, "")
	rec := httptest.NewRecorder()
	HandlersOf(e).GraphQL.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/graphql",
		bytes.NewReader(make([]byte, maxGraphQLBodyBytes+1))))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestHandlersOfFailedEngineUnavailable(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	e, _ := Open(context.Background(), testCfg(dir, &bytes.Buffer{}))
	h := HandlersOf(e)
	for name, hd := range map[string]http.Handler{"graphql": h.GraphQL, "subscribe": h.Subscribe, "debug": h.Debug, "metrics": h.Metrics} {
		rec := httptest.NewRecorder()
		hd.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
		if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "graph_unavailable") {
			t.Fatalf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
}
