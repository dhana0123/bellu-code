package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/auth"
	"github.com/bellu/bellucode/services/bellud/internal/server/routes"
)

func tag(s string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(s)) })
}

func newServer(t *testing.T) *Server {
	tbl, err := routes.NewTable([]routes.Route{
		{Method: "GET", Pattern: "/api/go", Group: "g", Owner: routes.OwnerGo},
		{Method: "GET", Pattern: "/api/mcp", Group: "g", Owner: routes.OwnerGo},
		{Method: "GET", Pattern: "/auth/*", Group: "a", Owner: routes.OwnerTS, Public: true},
		{Method: "GET", Pattern: "/api/ts", Group: "t", Owner: routes.OwnerTS},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &Server{
		Table: tbl, Auth: auth.New("pw"), Go: tag("go"), Proxy: tag("ts"),
		CORS: []string{"https://ok.example"},
		GoAuth: map[string]func(*http.Request) bool{
			"/api/mcp": func(r *http.Request) bool { return r.Header.Get("Authorization") == "Bearer tok" },
		},
	}
}

func do(s *Server, method, path string, mut func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	if mut != nil {
		mut(r)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func basic(r *http.Request) { r.SetBasicAuth("bellucode", "pw") }

func TestDispatch(t *testing.T) {
	s := newServer(t)
	cases := []struct {
		path string
		mut  func(*http.Request)
		code int
		body string
	}{
		{"/api/go", basic, 200, "go"},
		{"/api//x/../go/", basic, 200, "go"},
		{"/api/ts", basic, 200, "ts"},
		{"/api/go", nil, 401, ""},
		{"/api/ts", nil, 401, ""},
		{"/auth/login", nil, 200, "ts"},
		{"/unknown", basic, 200, "ts"},
		{"/unknown", nil, 401, ""},
		{"/api/mcp", func(r *http.Request) { r.Header.Set("Authorization", "Bearer tok") }, 200, "go"},
		{"/api/mcp", basic, 401, ""},
	}
	for _, c := range cases {
		w := do(s, "GET", c.path, c.mut)
		if w.Code != c.code || (c.body != "" && w.Body.String() != c.body) {
			t.Errorf("%s: got %d %q", c.path, w.Code, w.Body.String())
		}
	}
}

func TestStrictAPI(t *testing.T) {
	s := newServer(t)
	s.StrictAPI = true
	if w := do(s, "GET", "/api/nope", basic); w.Code != 404 {
		t.Errorf("authed unmatched api: %d", w.Code)
	}
	if w := do(s, "GET", "/api/nope", nil); w.Code != 401 {
		t.Errorf("unauthed unmatched api: %d", w.Code)
	}
	if w := do(s, "GET", "/openapi.json", basic); w.Code != 404 {
		t.Errorf("openapi: %d", w.Code)
	}
	if w := do(s, "GET", "/other", basic); w.Body.String() != "ts" {
		t.Errorf("non-api unmatched should proxy")
	}
}

func TestCORS(t *testing.T) {
	s := newServer(t)
	w := do(s, "GET", "/api/go", func(r *http.Request) { basic(r); r.Header.Set("Origin", "https://ok.example") })
	if w.Header().Get("Access-Control-Allow-Origin") != "https://ok.example" {
		t.Error("missing CORS header")
	}
	for _, o := range []string{"https://ok.example.evil", "https://OK.example", "null"} {
		w = do(s, "GET", "/api/go", func(r *http.Request) { basic(r); r.Header.Set("Origin", o) })
		if w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("CORS header for %q", o)
		}
	}
	w = do(s, "OPTIONS", "/api/go", func(r *http.Request) {
		r.Header.Set("Origin", "https://ok.example")
		r.Header.Set("Access-Control-Request-Method", "POST")
	})
	if w.Code != 204 || w.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Errorf("preflight: %d %v", w.Code, w.Header())
	}
}
