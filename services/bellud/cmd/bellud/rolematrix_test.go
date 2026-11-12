package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	apigraph "github.com/bellu/bellucode/services/bellud/internal/api/graph"
	"github.com/bellu/bellucode/services/bellud/internal/auth"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/facade"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/mcptoken"
	"github.com/bellu/bellucode/services/bellud/internal/server"
	"github.com/bellu/bellucode/services/bellud/internal/server/routes"
)

// matrixStack builds the real front door (routes table, auth, graphGoAuth,
// goHandler) over a real engine with a stub TS proxy.
func matrixStack(t *testing.T) (*httptest.Server, mcptoken.Set, string) {
	t.Helper()
	set := newSet(t)
	env := map[string]string{"BELLU_GRAPH_ENABLED": "true", "BELLU_GRAPH_DIR": filepath.Join(t.TempDir(), "g")}
	cfg, err := graph.LoadConfigFrom(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	cfg.MCPToken = set.Write.String()
	cfg.Grants = grantsOf(set)
	ctx := context.Background()
	eng, err := graph.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { eng.Close(ctx) })
	if graph.StateOf(eng).Kind != graph.StateReady {
		t.Fatalf("engine not ready: %+v", graph.StateOf(eng))
	}
	if _, err := eng.Ingest().Apply(ctx, matrixBatch()); err != nil {
		t.Fatal(err)
	}
	hid, err := facade.Hash("host", map[string]string{"hostname": "h1"})
	if err != nil {
		t.Fatal(err)
	}
	table := routes.MustLoadEmbedded()
	authn := auth.New("pw")
	srv := &server.Server{
		Table:  table,
		Auth:   authn,
		Go:     goHandler(eng, set, func() apigraph.ChildState { return apigraph.ChildReady }),
		GoAuth: graphGoAuth(table, set, authn.Authorize),
		Proxy: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		}),
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return ts, set, string(hid)
}

func matrixBatch() batch.Batch {
	return batch.Batch{
		Collector: "host", ObservedAt: time.Now().UTC(),
		Entities: []batch.Entity{{Type: "host", Identity: map[string]string{"hostname": "h1"}, Attributes: map[string]any{"os": "linux"}}},
	}
}

type caller struct {
	name   string
	bearer string // "" none
	basic  bool
}

func (c caller) apply(r *http.Request) {
	if c.bearer != "" {
		r.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	if c.basic {
		r.SetBasicAuth("bellucode", "pw")
	}
}

func (c caller) do(t *testing.T, method, url, body string, hdr map[string]string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	c.apply(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		return resp.StatusCode, "" // never drain a stream
	}
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestRoleMatrix(t *testing.T) {
	ts, set, hid := matrixStack(t)
	base := ts.URL + apigraph.Prefix
	batchJSON, err := json.Marshal(matrixBatch())
	if err != nil {
		t.Fatal(err)
	}
	callers := []caller{
		{name: "read", bearer: set.Read.String()},
		{name: "ingest", bearer: set.Ingest.String()},
		{name: "write", bearer: set.Write.String()},
		{name: "bellud", basic: true},
		{name: "none"},
	}
	const (
		ok  = 200
		no  = 403
		unq = 401
	)
	type row struct {
		name, method, path, body string
		hdr                      map[string]string
		want                     [5]int // read, ingest, write, bellud, none
		// deny, when set, must appear in the 200 body of the read caller
		// (a role denial reported inside a 200 response).
		readBodyHas, writeBodyLacks string
	}
	js := map[string]string{"Content-Type": "application/json"}
	gql := func(q string) string { b, _ := json.Marshal(map[string]any{"query": q}); return string(b) }
	rows := []row{
		{name: "graphql query", method: "POST", path: "/graphql", body: gql(`{ find(kind: "host") { total } }`), hdr: js,
			want: [5]int{ok, no, ok, ok, unq}, writeBodyLacks: `"errors"`},
		{name: "graphql annotateEntity", method: "POST", path: "/graphql",
			body: gql(`mutation { annotateEntity(id: "` + hid + `", set: {owner: "ops"}) { annotations } }`), hdr: js,
			want: [5]int{ok, no, ok, ok, unq}, readBodyHas: "FORBIDDEN", writeBodyLacks: "FORBIDDEN"},
		{name: "sse subscribe", method: "GET", path: "/subscribe", want: [5]int{ok, no, ok, ok, unq}},
		{name: "GET entities", method: "GET", path: "/entities", want: [5]int{ok, no, ok, ok, unq}},
		{name: "GET entity", method: "GET", path: "/entities/" + hid, want: [5]int{ok, no, ok, ok, unq}},
		{name: "GET status", method: "GET", path: "/status", want: [5]int{ok, no, ok, ok, unq}},
		{name: "POST batches", method: "POST", path: "/batches", body: string(batchJSON), hdr: js,
			want: [5]int{no, ok, ok, ok, unq}},
		{name: "GET debug", method: "GET", path: "/debug", want: [5]int{unq, unq, unq, ok, unq}},
		// bellud credentials reach the debug handler (its own 404), tokens never do
		{name: "GET debug subpath", method: "GET", path: "/debug/x", want: [5]int{unq, unq, unq, 404, unq}},
		{name: "GET metrics", method: "GET", path: "/metrics", want: [5]int{unq, unq, unq, ok, unq}},
	}
	for _, rw := range rows {
		for i, c := range callers {
			code, body := c.do(t, rw.method, base+rw.path, rw.body, rw.hdr)
			if code != rw.want[i] {
				t.Errorf("%s as %s: %d want %d (%s)", rw.name, c.name, code, rw.want[i], body)
				continue
			}
			if code == no && body != `{"code":"graph_forbidden"}` {
				t.Errorf("%s as %s: forbidden body %q", rw.name, c.name, body)
			}
			if c.name == "read" && rw.readBodyHas != "" && !strings.Contains(body, rw.readBodyHas) {
				t.Errorf("%s as read: body lacks %q: %s", rw.name, rw.readBodyHas, body)
			}
			if (c.name == "write" || c.name == "bellud") && rw.writeBodyLacks != "" && strings.Contains(body, rw.writeBodyLacks) {
				t.Errorf("%s as %s: unexpected %q: %s", rw.name, c.name, rw.writeBodyLacks, body)
			}
		}
	}
	t.Run("mcp", func(t *testing.T) { mcpMatrix(t, ts.URL+apigraph.Prefix+"/mcp", callers, hid) })
}

const mcpInit = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`

type headerRT struct{ bearer string }

func (h headerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+h.bearer)
	return http.DefaultTransport.RoundTrip(r)
}

// MCP is bearer-only: any graph token reaches it (ingest is then 403 as the
// route needs read), bellud credentials and anonymous callers get 401. Tool
// roles: read lists tools but annotate_entity needs write.
func mcpMatrix(t *testing.T, url string, callers []caller, hid string) {
	status := map[string]int{"read": 200, "ingest": 403, "write": 200, "bellud": 401, "none": 401}
	hdr := map[string]string{"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
	for _, c := range callers {
		if code, body := c.do(t, "POST", url, mcpInit, hdr); code != status[c.name] {
			t.Errorf("mcp initialize as %s: %d want %d (%s)", c.name, code, status[c.name], body)
		}
		if status[c.name] != 200 {
			continue
		}
		cl := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "t", Version: "1"}, nil)
		sess, err := cl.Connect(context.Background(), &mcpsdk.StreamableClientTransport{
			Endpoint: url, DisableStandaloneSSE: true,
			HTTPClient: &http.Client{Transport: headerRT{c.bearer}},
		}, nil)
		if err != nil {
			t.Fatalf("mcp connect as %s: %v", c.name, err)
		}
		tools, err := sess.ListTools(context.Background(), nil)
		if err != nil || len(tools.Tools) == 0 {
			t.Errorf("tools/list as %s: %v", c.name, err)
		}
		res, err := sess.CallTool(context.Background(), &mcpsdk.CallToolParams{
			Name: "annotate_entity", Arguments: map[string]any{"entity_id": hid, "annotations": map[string]string{"note": "hi"}},
		})
		sess.Close()
		if err != nil {
			t.Fatalf("annotate as %s: %v", c.name, err)
		}
		wantErr := c.name == "read"
		if res.IsError != wantErr {
			t.Errorf("annotate_entity as %s: isError=%v want %v", c.name, res.IsError, wantErr)
		}
		if wantErr {
			if txt, _ := json.Marshal(res.Content); !strings.Contains(string(txt), "write") {
				t.Errorf("annotate denial should name the write role: %s", txt)
			}
		}
	}
}
