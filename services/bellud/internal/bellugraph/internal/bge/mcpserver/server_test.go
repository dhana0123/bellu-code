package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/engine"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

type fixture struct {
	core *engine.Core
	ids  map[string]string
	cs   *mcp.ClientSession
	role string
	ann  []string
}

func hash(t *testing.T, kind string, id map[string]string) string {
	t.Helper()
	h, err := ident.Hash(kind, id)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	t0 := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	core, err := engine.Open(t.TempDir(), engine.Options{Clock: func() time.Time { return t0.Add(time.Hour) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = core.Close(context.Background()) })
	f := &fixture{core: core, role: RoleRead, ids: map[string]string{
		"host": hash(t, "host", map[string]string{"hostname": "web-1"}),
		"cont": hash(t, "container", map[string]string{"id": "c1"}),
		"ep":   hash(t, "endpoint", map[string]string{"protocol": "tcp", "address": "10.0.0.5", "port": "80"}),
		"lp":   hash(t, "listening_port", map[string]string{"host": "web-1", "protocol": "tcp", "address": "0.0.0.0", "port": "80"}),
		"proc": hash(t, "process", map[string]string{"host": "web-1", "pid": "7", "start_time": "1"}),
		"lone": hash(t, "host", map[string]string{"hostname": "lone"}),
	}}
	long := strings.Repeat("x", 300)
	_, err = core.Apply(context.Background(), batch.Batch{Collector: "t", ObservedAt: t0, Entities: []batch.Entity{
		{Type: "host", Identity: map[string]string{"hostname": "web-1"}, Attributes: map[string]any{"addresses": []string{"10.0.0.5"}, "os": "linux", "note": long}},
		{Type: "host", Identity: map[string]string{"hostname": "lone"}, Attributes: map[string]any{"os": "linux", "api_token": "s3cret"}},
		{Type: "container", Identity: map[string]string{"id": "c1"}},
		{Type: "endpoint", Identity: map[string]string{"protocol": "tcp", "address": "10.0.0.5", "port": "80"}},
		{Type: "listening_port", Identity: map[string]string{"host": "web-1", "protocol": "tcp", "address": "0.0.0.0", "port": "80"}},
		{Type: "process", Identity: map[string]string{"host": "web-1", "pid": "7", "start_time": "1"}},
	}, Relations: []batch.Relation{
		{Type: "depends_on", From: f.ids["cont"], To: f.ids["ep"]},
		{Type: "owned_by", From: f.ids["lp"], To: f.ids["proc"]},
		{Type: "on", From: f.ids["lp"], To: f.ids["host"]},
	}}, engine.ModeFull)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Config{
		Core:       core,
		CallerRole: func(context.Context) string { return f.role },
		Annotate: func(ctx context.Context, id string, set map[string]string, unset []string) error {
			f.ann = append(f.ann, id)
			_, err := core.Annotate(ctx, id, set, unset, "test")
			return err
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := srv.MCP().Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	f.cs, err = mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.cs.Close() })
	return f
}

// call runs a tool and returns the decoded structured result and isError.
func (f *fixture) call(t *testing.T, name string, args map[string]any) (map[string]any, string, bool) {
	t.Helper()
	res, err := f.cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		// Schema-level argument errors surface as protocol errors.
		return nil, err.Error(), true
	}
	text := ""
	if len(res.Content) > 0 {
		if tc, ok := res.Content[0].(*mcp.TextContent); ok {
			text = tc.Text
		}
	}
	if res.IsError {
		return nil, text, true
	}
	b, _ := json.Marshal(res.StructuredContent)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m, text, false
}

func TestServerIdentityAndTools(t *testing.T) {
	f := newFixture(t)
	init := f.cs.InitializeResult()
	if init.ServerInfo.Title != "Bellu Graph Engine" || init.ServerInfo.Name != "bellugraph" || !strings.Contains(init.Instructions, "Bellu Graph Engine") {
		t.Fatalf("server info = %+v instructions=%q", init.ServerInfo, init.Instructions)
	}
	list, err := f.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, tl := range list.Tools {
		got[tl.Name] = true
		if tl.Description == "" || tl.InputSchema == nil {
			t.Errorf("tool %s lacks description or schema", tl.Name)
		}
	}
	if len(list.Tools) != len(ToolNames) {
		t.Errorf("tools = %d, want %d", len(list.Tools), len(ToolNames))
	}
	for _, n := range ToolNames {
		if !got[n] {
			t.Errorf("missing tool %s", n)
		}
	}
}

func TestVerbosityTiers(t *testing.T) {
	f := newFixture(t)
	get := func(v string) map[string]any {
		args := map[string]any{"entity_id": f.ids["host"]}
		if v != "" {
			args["verbosity"] = v
		}
		m, txt, isErr := f.call(t, "get_entity", args)
		if isErr {
			t.Fatalf("get_entity %q: %s", v, txt)
		}
		return m["entity"].(map[string]any)
	}
	brief := get("brief")
	if len(brief) != 4 || brief["identity_fingerprint"] != f.ids["host"] || !strings.HasPrefix(brief["id"].(string), "@") || brief["label"] != "web-1" {
		t.Fatalf("brief = %v", brief)
	}
	normal := get("")
	note := normal["attributes"].(map[string]any)["note"].(string)
	if len(note) != 256 || normal["truncated_attributes"].([]any)[0] != "note" || normal["observed_at"] != nil {
		t.Fatalf("normal = %v", normal)
	}
	full := get("full")
	if len(full["attributes"].(map[string]any)["note"].(string)) != 300 || full["uri"] != "bellugraph://"+strings.Replace(f.ids["host"], ":", "/", 1) || full["observed_at"] == nil || full["recorded_at"] == nil {
		t.Fatalf("full = %v", full)
	}
	_, txt, isErr := f.call(t, "get_entity", map[string]any{"entity_id": f.ids["host"], "verbosity": "loud"})
	if !isErr || !strings.Contains(txt, "verbosity") {
		t.Fatalf("bad verbosity: %v %q", isErr, txt)
	}
}

func TestEntityRefsAndNotFound(t *testing.T) {
	f := newFixture(t)
	m, _, _ := f.call(t, "get_entity", map[string]any{"entity_id": f.ids["host"], "verbosity": "brief"})
	local := m["entity"].(map[string]any)["id"].(string)
	for _, ref := range []string{local, "bellugraph://" + strings.Replace(f.ids["host"], ":", "/", 1)} {
		m, txt, isErr := f.call(t, "get_entity", map[string]any{"entity_id": ref, "verbosity": "brief"})
		if isErr || m["entity"].(map[string]any)["identity_fingerprint"] != f.ids["host"] {
			t.Fatalf("ref %q: %v %s", ref, isErr, txt)
		}
	}
	for _, ref := range []string{"@zzzzzz", "host:" + strings.Repeat("0", 32), ""} {
		if _, txt, isErr := f.call(t, "get_entity", map[string]any{"entity_id": ref}); !isErr {
			t.Errorf("ref %q: want error result, got %s", ref, txt)
		}
	}
}

func TestFindAndNeighborsResolve(t *testing.T) {
	f := newFixture(t)
	m, _, _ := f.call(t, "find_entities", map[string]any{"kind": "host", "attributes": map[string]any{"os": "linux"}, "page_size": 1, "verbosity": "brief"})
	if m["total"].(float64) != 2 || m["truncated"] != true || m["next_cursor"] == "" || len(m["items"].([]any)) != 1 {
		t.Fatalf("find = %v", m)
	}
	derived := func(args map[string]any) int {
		args["entity_id"] = f.ids["cont"]
		args["depth"] = 2
		m, txt, isErr := f.call(t, "get_neighbors", args)
		if isErr {
			t.Fatal(txt)
		}
		n := 0
		for _, e := range m["items"].([]any) {
			if e.(map[string]any)["derived"] == true {
				n++
			}
		}
		return n
	}
	if derived(map[string]any{}) == 0 {
		t.Error("resolve default should include derived edges")
	}
	if derived(map[string]any{"resolve": false}) != 0 {
		t.Error("resolve=false must return stored relations only")
	}
}

func TestPathImpactAndFullConnectedFrom(t *testing.T) {
	f := newFixture(t)
	m, _, _ := f.call(t, "find_path", map[string]any{"from": f.ids["cont"], "to": f.ids["proc"]})
	if m["connected"] != true || len(m["path"].([]any)) != 2 {
		t.Fatalf("path = %v", m)
	}
	m, _, _ = f.call(t, "find_path", map[string]any{"from": f.ids["lone"], "to": f.ids["cont"]})
	if m["connected"] != false || m["exhausted"] != true || m["depth_searched"] == nil || m["shared_neighbors"] == nil {
		t.Fatalf("not connected = %v", m)
	}
	if attrs := m["shared_attributes"]; attrs != nil {
		for k := range attrs.(map[string]any) {
			if ident.IsSecretName(k) {
				t.Errorf("secret key %s in shared_attributes", k)
			}
		}
	}
	m, _, _ = f.call(t, "impact_of", map[string]any{"entity_id": f.ids["proc"], "depth": 5})
	if len(m["items"].([]any)) == 0 {
		t.Fatalf("impact = %v", m)
	}
	m, _, _ = f.call(t, "get_entity", map[string]any{"entity_id": f.ids["lp"], "verbosity": "full"})
	cf, _ := m["connected_from"].([]any)
	if len(cf) != 1 || cf[0].(map[string]any)["identity_fingerprint"] != f.ids["cont"] {
		t.Fatalf("connected_from = %v", m["connected_from"])
	}
	m, _, _ = f.call(t, "get_entity", map[string]any{"entity_id": f.ids["lp"]})
	if m["connected_from"] != nil {
		t.Error("connected_from only at full")
	}
}

func TestTelemetryKeysOmitSecrets(t *testing.T) {
	f := newFixture(t)
	m, _, _ := f.call(t, "telemetry_keys", map[string]any{"entity_id": f.ids["lp"]})
	keys := m["keys"].(map[string]any)
	if keys["host"] != "web-1" || keys["port"] != "80" {
		t.Fatalf("keys = %v", keys)
	}
	for k := range keys {
		if ident.IsSecretName(k) {
			t.Errorf("secret key %s", k)
		}
	}
}

func TestRecentChangesBudgetAndDigest(t *testing.T) {
	f := newFixture(t)
	args := map[string]any{"since": "2000-01-01T00:00:00Z", "max_bytes": 300, "verbosity": "brief"}
	m, txt, isErr := f.call(t, "recent_changes", args)
	if isErr {
		t.Fatal(txt)
	}
	digest := m["digest"].(map[string]any)
	total := int(digest["total"].(float64))
	if total < 9 || m["truncated"] != true || m["next_cursor"] == nil {
		t.Fatalf("recent = %v", m)
	}
	seen := len(m["items"].([]any))
	prev := m["items"].([]any)[0].(map[string]any)["observed_at"].(string)
	for m["truncated"] == true {
		args["cursor"] = m["next_cursor"]
		if m, txt, isErr = f.call(t, "recent_changes", args); isErr {
			t.Fatal(txt)
		}
		if m["digest"] != nil {
			t.Error("digest only on the first page")
		}
		seen += len(m["items"].([]any))
		for _, it := range m["items"].([]any) {
			ts := it.(map[string]any)["observed_at"].(string)
			if ts > prev {
				t.Fatalf("not newest first: %s after %s", ts, prev)
			}
			prev = ts
		}
	}
	if seen != total {
		t.Fatalf("paged %d items, digest total %d", seen, total)
	}
	if _, _, isErr := f.call(t, "recent_changes", map[string]any{"max_bytes": -1}); !isErr {
		t.Error("negative max_bytes should be an error")
	}
}

func TestAnnotateNeedsWrite(t *testing.T) {
	f := newFixture(t)
	args := map[string]any{"entity_id": f.ids["host"], "annotations": map[string]any{"owner": "ops"}}
	_, txt, isErr := f.call(t, "annotate_entity", args)
	if !isErr || txt != "forbidden: needs write role" || len(f.ann) != 0 {
		t.Fatalf("read role: err=%v %q ann=%v", isErr, txt, f.ann)
	}
	f.role = RoleWrite
	m, txt, isErr := f.call(t, "annotate_entity", args)
	if isErr {
		t.Fatal(txt)
	}
	if m["entity"].(map[string]any)["annotations"].(map[string]any)["owner"] != "ops" || len(f.ann) != 1 {
		t.Fatalf("annotate = %v", m)
	}
	if _, _, isErr := f.call(t, "annotate_entity", map[string]any{"entity_id": f.ids["host"], "annotations": map[string]any{"BAD KEY": "x"}}); !isErr {
		t.Error("invalid annotation key should be an error result")
	}
}

func TestSchemaTypeHistoryDiff(t *testing.T) {
	f := newFixture(t)
	m, _, _ := f.call(t, "describe_schema", nil)
	if len(m["kinds"].([]any)) != len(ident.Kinds()) || len(m["relation_types"].([]any)) == 0 {
		t.Fatalf("schema = %v", m)
	}
	m, _, _ = f.call(t, "describe_type", map[string]any{"kind": "host"})
	if m["count"].(float64) != 2 {
		t.Fatalf("type = %v", m)
	}
	if _, _, isErr := f.call(t, "describe_type", map[string]any{"kind": "nope"}); !isErr {
		t.Error("unknown kind should be an error")
	}
	m, txt, isErr := f.call(t, "entity_history", map[string]any{"entity_id": f.ids["host"]})
	if isErr || len(m["items"].([]any)) == 0 {
		t.Fatalf("history = %v %s", m, txt)
	}
	m, txt, isErr = f.call(t, "graph_diff", map[string]any{"from": "2024-12-31T00:00:00Z", "to": "2025-01-02T00:00:00Z", "verbosity": "brief"})
	if isErr || len(m["added"].([]any)) != 6 {
		t.Fatalf("diff = %v %s", m, txt)
	}
	if _, _, isErr := f.call(t, "graph_diff", map[string]any{"from": "2025-01-02T00:00:00Z", "to": "2024-12-31T00:00:00Z"}); !isErr {
		t.Error("reversed diff should be an error")
	}
}

type roleKey struct{}

// The HTTP handler passes request context values to the tools, so the Facade
// can resolve the caller before the MCP layer.
func TestHandlerPropagatesCallerContext(t *testing.T) {
	f := newFixture(t)
	var seen []string
	srv, err := New(Config{Core: f.core, CallerRole: func(ctx context.Context) string {
		r, _ := ctx.Value(roleKey{}).(string)
		seen = append(seen, r)
		return r
	}, Annotate: func(context.Context, string, map[string]string, []string) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), roleKey{}, "read")))
	}))
	defer ts.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "http"}, nil).Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: ts.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "annotate_entity",
		Arguments: map[string]any{"entity_id": f.ids["host"], "annotations": map[string]any{"a": "b"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || len(seen) != 1 || seen[0] != "read" {
		t.Fatalf("isError=%v seen=%v", res.IsError, seen)
	}
}
