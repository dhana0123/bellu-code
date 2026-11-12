package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	apigraph "github.com/bellu/bellucode/services/bellud/internal/api/graph"
	"github.com/bellu/bellucode/services/bellud/internal/auth"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/facade"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/mcptoken"
	"github.com/bellu/bellucode/services/bellud/internal/server/routes"
)

const mcpPath = apigraph.Prefix + "/mcp"

// graphServer wires a real engine into a Server like serve does.
func graphServer(t *testing.T, dir string) (*httptest.Server, mcptoken.Token, string) {
	t.Helper()
	tok, err := mcptoken.New()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	en, err := facade.Open(ctx, facade.Config{Enabled: true, Dir: dir, MCPToken: tok.String()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { en.Close(ctx) })
	hid, err := facade.Hash("host", map[string]string{"hostname": "h1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := en.Ingest().Apply(ctx, batch.Batch{
		Collector: "host", ObservedAt: time.Now().UTC(),
		Entities: []batch.Entity{{Type: "host", Identity: map[string]string{"hostname": "h1"}, Attributes: map[string]any{"os": "linux"}}},
	}); err != nil {
		t.Fatal(err)
	}
	api := apigraph.New(en, func() apigraph.ChildState { return apigraph.ChildReady })
	mcp := en.MCPHandler()
	s := &Server{
		Table: routes.MustLoadEmbedded(), Auth: auth.New("pw"), Proxy: tag("ts"),
		Go: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == mcpPath {
				mcp.ServeHTTP(w, r)
				return
			}
			api.ServeHTTP(w, r)
		}),
		GoAuth: map[string]func(*http.Request) bool{mcpPath: tok.Verify},
	}
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)
	return ts, tok, string(hid)
}

func call(t *testing.T, method, url string, hdr map[string]string, basicAuth bool, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if basicAuth {
		req.SetBasicAuth("bellucode", "pw")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestGraphRoutesAuth(t *testing.T) {
	ts, tok, hid := graphServer(t, filepath.Join(t.TempDir(), "g"))
	for _, p := range []string{"/entities", "/entities/" + hid, "/changes", "/schema", "/status"} {
		u := ts.URL + apigraph.Prefix + p
		if c := call(t, "GET", u, nil, false, "").StatusCode; c != 401 {
			t.Errorf("%s no creds: %d", p, c)
		}
		if c := call(t, "GET", u, nil, true, "").StatusCode; c != 200 {
			t.Errorf("%s basic: %d", p, c)
		}
		// the MCP token must not open ordinary graph routes
		if c := call(t, "GET", u, map[string]string{"Authorization": tok.Header()}, false, "").StatusCode; c != 401 {
			t.Errorf("%s with mcp token: %d", p, c)
		}
	}
	if c := call(t, "GET", ts.URL+apigraph.Prefix+"/entities/bogus", nil, true, "").StatusCode; c != 400 {
		t.Errorf("bad id: %d", c)
	}
}

const initBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`

func TestMCPTokenMatrix(t *testing.T) {
	ts, tok, _ := graphServer(t, filepath.Join(t.TempDir(), "g"))
	h := func(auth string) map[string]string {
		m := map[string]string{"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
		if auth != "" {
			m["Authorization"] = auth
		}
		return m
	}
	url := ts.URL + mcpPath
	cases := []struct {
		name  string
		hdr   map[string]string
		basic bool
		code  int
	}{
		{"no header", h(""), false, 401},
		{"basic only", h(""), true, 401},
		{"wrong token", h("Bearer nope"), false, 401},
		{"non-bearer scheme", h("Token " + tok.String()), false, 401},
		{"basic plus wrong bearer", h("Bearer nope"), true, 401},
		{"valid token", h(tok.Header()), false, 200},
	}
	for _, c := range cases {
		hdr := c.hdr
		if c.basic && hdr["Authorization"] == "" {
			hdr = h("")
		}
		resp := call(t, "POST", url, hdr, false, initBody)
		if c.name == "basic only" {
			resp = call(t, "POST", url, h(""), true, initBody)
		}
		if resp.StatusCode != c.code {
			t.Errorf("%s: %d want %d", c.name, resp.StatusCode, c.code)
		}
	}
	// a session cookie is not a credential for the MCP route
	hdr := h("")
	hdr["Cookie"] = "session=abc"
	if c := call(t, "POST", url, hdr, false, initBody).StatusCode; c != 401 {
		t.Errorf("session cookie: %d", c)
	}
}

func annotateVia(t *testing.T, url, bearer, id string) *mcpsdk.CallToolResult {
	t.Helper()
	c := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "t", Version: "1"}, nil)
	s, err := c.Connect(context.Background(), &mcpsdk.StreamableClientTransport{
		Endpoint: url, DisableStandaloneSSE: true,
		HTTPClient: &http.Client{Transport: bearerRT(bearer)},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	res, err := s.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name: "annotate_entity", Arguments: map[string]any{"entity_id": id, "annotations": map[string]string{"note": "hi"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

type bearerRT string

func (b bearerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+string(b))
	return http.DefaultTransport.RoundTrip(r)
}

func TestMCPAnnotateAudit(t *testing.T) {
	// Healthy audit log: annotate succeeds and is recorded.
	dir := filepath.Join(t.TempDir(), "g")
	ts, tok, id := graphServer(t, dir)
	if res := annotateVia(t, ts.URL+mcpPath, tok.String(), id); res.IsError {
		t.Fatalf("annotate failed: %+v", res.Content)
	}
	b, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil || !strings.Contains(string(b), id) || !strings.Contains(string(b), tok.Identity()) {
		t.Fatalf("audit log %q %v", b, err)
	}

	// Unwritable audit log (a directory occupies the file name): the engine
	// refuses annotations and nothing is applied.
	bad := filepath.Join(t.TempDir(), "g")
	if err := os.MkdirAll(filepath.Join(bad, "audit.jsonl"), 0o700); err != nil {
		t.Fatal(err)
	}
	ts2, tok2, id2 := graphServer(t, bad)
	if res := annotateVia(t, ts2.URL+mcpPath, tok2.String(), id2); !res.IsError {
		t.Fatalf("want error result, got %+v", res)
	}
	resp := call(t, "GET", ts2.URL+apigraph.Prefix+"/entities/"+id2, nil, true, "")
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	if resp.StatusCode != 200 || strings.Contains(sb.String(), `"note"`) {
		t.Fatalf("annotation leaked: %d %s", resp.StatusCode, sb.String())
	}
}
