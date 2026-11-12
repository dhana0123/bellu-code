package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/mcptoken"
	"github.com/bellu/bellucode/services/bellud/internal/server/routes"
)

func newSet(t *testing.T) mcptoken.Set {
	t.Helper()
	w, err := mcptoken.New()
	if err != nil {
		t.Fatal(err)
	}
	s, err := mcptoken.NewSet(w)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestWriteGraphTokens(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, graphTokensFile), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := newSet(t)
	if err := writeGraphTokens(dir, s); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, graphTokensFile)
	st, err := os.Stat(p)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("stat %v mode %v", err, st.Mode())
	}
	b, _ := os.ReadFile(p)
	var got map[string]string
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["read"] != s.Read.String() || got["ingest"] != s.Ingest.String() {
		t.Fatalf("content %v", got)
	}
	if es, _ := os.ReadDir(dir); len(es) != 1 {
		t.Fatalf("leftover files: %v", es)
	}
}

func TestRoleMiddleware(t *testing.T) {
	s := newSet(t)
	var seen graph.Caller
	h := roleMiddleware(s, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = graph.CallerFrom(r.Context())
	}))
	do := func(method, path string, tok *mcptoken.Token) (int, string) {
		seen = graph.Caller{}
		r := httptest.NewRequest(method, path, nil)
		if tok != nil {
			r.Header.Set("Authorization", tok.Header())
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code, w.Body.String()
	}
	const get = "/api/experimental/graph/entities"
	const post = "/api/experimental/graph/batches"
	cases := []struct {
		name         string
		method, path string
		tok          *mcptoken.Token
		code         int
		role         graph.Role
	}{
		{"read gets read", "GET", get, &s.Read, 200, graph.RoleRead},
		{"read cannot ingest", "POST", post, &s.Read, 403, ""},
		{"ingest cannot read", "GET", get, &s.Ingest, 403, ""},
		{"ingest posts", "POST", post, &s.Ingest, 200, graph.RoleIngest},
		{"write reads", "GET", get, &s.Write, 200, graph.RoleWrite},
		{"write ingests", "POST", post, &s.Write, 200, graph.RoleWrite},
		{"bellud creds are write", "POST", post, nil, 200, graph.RoleWrite},
	}
	for _, c := range cases {
		code, body := do(c.method, c.path, c.tok)
		if code != c.code || seen.Role != c.role {
			t.Errorf("%s: code %d role %q", c.name, code, seen.Role)
		}
		if code == 403 && body != `{"code":"graph_forbidden"}` {
			t.Errorf("%s: body %q", c.name, body)
		}
	}
	do("GET", get, nil)
	if seen.Identity != frontDoor {
		t.Errorf("identity %q", seen.Identity)
	}
	do("GET", get, &s.Read)
	if seen.Identity != s.Read.Identity() {
		t.Errorf("identity %q", seen.Identity)
	}
}

func TestGraphGoAuth(t *testing.T) {
	s := newSet(t)
	m := graphGoAuth(routes.MustLoadEmbedded(), s, func(*http.Request) bool { return false })
	p := "/api/experimental/graph"
	withTok := func(tok mcptoken.Token) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Authorization", tok.Header())
		return r
	}
	for _, pat := range []string{"/graphql", "/subscribe", "/batches"} {
		if fn := m[p+pat]; fn == nil || !fn(withTok(s.Read)) {
			t.Errorf("%s should accept a read token", pat)
		}
	}
	if fn := m[p+"/mcp"]; fn == nil || !fn(withTok(s.Read)) || !fn(withTok(s.Write)) ||
		fn(httptest.NewRequest("GET", "/", nil)) {
		t.Error("mcp must accept graph tokens of any role and nothing else")
	}
	for _, pat := range []string{"/debug", "/debug/*", "/metrics"} {
		if m[p+pat] != nil {
			t.Errorf("%s must use bellud credentials only", pat)
		}
	}
}
