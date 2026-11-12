package openapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/server/routes"
	"github.com/bellu/bellucode/services/bellud/internal/tschild"
)

func table(t *testing.T) routes.RouteTable {
	t.Helper()
	tb, err := routes.NewTable([]routes.Route{
		{Method: "GET", Pattern: "/api/experimental/graph/entities", Group: "g", Owner: routes.OwnerGo},
	})
	if err != nil {
		t.Fatal(err)
	}
	return tb
}

func childFor(t *testing.T, s *httptest.Server) *tschild.Child {
	u, _ := url.Parse(s.URL)
	return &tschild.Child{URL: u, Password: "pw"}
}

func decode(t *testing.T, b []byte) map[string]any {
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

const childDoc = `{"openapi":"3.1.0","paths":{
 "/api/info":{"get":{"operationId":"info"}},
 "/api/experimental/graph/entities":{"get":{"operationId":"stale"}}}}`

func TestMergeAndCache(t *testing.T) {
	var hits atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if u, p, ok := r.BasicAuth(); !ok || u != tschild.Username || p != "pw" {
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write([]byte(childDoc))
	}))
	defer s.Close()
	c := childFor(t, s)
	m := New(func() *tschild.Child { return c }, table(t))
	b, err := m.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	paths := decode(t, b)["paths"].(map[string]any)
	if _, ok := paths["/api/info"]; !ok {
		t.Fatal("child path missing")
	}
	op := paths["/api/experimental/graph/entities"].(map[string]any)["get"].(map[string]any)
	if op["operationId"] == "stale" {
		t.Fatal("child's go-owned operation not replaced")
	}
	if _, err := m.Get(context.Background()); err != nil || hits.Load() != 1 {
		t.Fatalf("expected cache, hits=%d err=%v", hits.Load(), err)
	}
	// Restart: new child pointer discards the cache.
	c2 := childFor(t, s)
	c = c2
	if _, err := m.Get(context.Background()); err != nil || hits.Load() != 2 {
		t.Fatalf("expected refetch, hits=%d", hits.Load())
	}
	m.Invalidate()
	_, _ = m.Get(context.Background())
	if hits.Load() != 3 {
		t.Fatalf("expected refetch after Invalidate, hits=%d", hits.Load())
	}
}

func TestFallbackNotCached(t *testing.T) {
	var hits atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`not json`))
	}))
	defer s.Close()
	c := childFor(t, s)
	m := New(func() *tschild.Child { return c }, table(t))
	m.Interval = time.Millisecond
	b, err := m.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 4 {
		t.Fatalf("want 4 attempts, got %d", hits.Load())
	}
	paths := decode(t, b)["paths"].(map[string]any)
	if _, ok := paths["/api/info"]; ok || len(paths) == 0 {
		t.Fatalf("expected Go-only document, got %v", paths)
	}
	_, _ = m.Get(context.Background())
	if hits.Load() != 8 {
		t.Fatalf("fallback was cached, hits=%d", hits.Load())
	}
}

func TestNoChildServesGoOnly(t *testing.T) {
	m := New(func() *tschild.Child { return nil }, table(t))
	b, err := m.Get(context.Background())
	if err != nil || len(decode(t, b)["paths"].(map[string]any)) == 0 {
		t.Fatalf("err=%v", err)
	}
}
