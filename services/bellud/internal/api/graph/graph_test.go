package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/contract"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/tschild"
)

var (
	idA = graph.EntityID("repo:" + strings.Repeat("a", 32))
	idB = graph.EntityID("repo:" + strings.Repeat("b", 32))
	t0  = time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
)

// fakeEngine serves a fixed in-memory graph through the facade interfaces.
type fakeEngine struct {
	state   graph.State
	ents    []graph.Entity
	changes []graph.Change
	lastFQ  graph.FindQuery
}

func (f *fakeEngine) Ingest() graph.Ingest        { return nil }
func (f *fakeEngine) Query() graph.Query          { return f }
func (f *fakeEngine) MCPHandler() http.Handler    { return nil }
func (f *fakeEngine) Close(context.Context) error { return nil }
func (f *fakeEngine) State() graph.State          { return f.state }

func (f *fakeEngine) find(id graph.EntityID) (graph.Entity, bool) {
	for _, e := range f.ents {
		if e.ID == id {
			return e, true
		}
	}
	return graph.Entity{}, false
}

func mkPage[T any](items []T, limit int) graph.Page[T] {
	if limit == 0 {
		limit = graph.DefaultPageSize
	}
	n := min(limit, len(items))
	return graph.Page[T]{Items: append([]T{}, items[:n]...), Total: len(items), Truncated: n < len(items), Limit: limit}
}

func (f *fakeEngine) Entity(_ context.Context, id graph.EntityID, _ *time.Time) (graph.Entity, error) {
	if e, ok := f.find(id); ok {
		return e, nil
	}
	return graph.Entity{}, fmt.Errorf("%w: %s", graph.ErrNotFound, id)
}
func (f *fakeEngine) Find(_ context.Context, q graph.FindQuery) (graph.Page[graph.Entity], error) {
	f.lastFQ = q
	var out []graph.Entity
	for _, e := range f.ents {
		if q.Type == "" || e.Type == q.Type {
			out = append(out, e)
		}
	}
	return mkPage(out, q.PageSize), nil
}
func (f *fakeEngine) Neighbors(_ context.Context, id graph.EntityID, o graph.NeighborOpts) (graph.Page[graph.Edge], error) {
	if _, ok := f.find(id); !ok {
		return graph.Page[graph.Edge]{}, fmt.Errorf("%w: %s", graph.ErrNotFound, id)
	}
	return mkPage([]graph.Edge{{From: idA, To: idB, Type: "depends_on", Direction: "out", Hops: 1}}, o.PageSize), nil
}
func (f *fakeEngine) History(_ context.Context, id graph.EntityID, _ graph.TimeRange, p graph.Paging) (graph.Page[graph.Change], error) {
	if _, ok := f.find(id); !ok {
		return graph.Page[graph.Change]{}, fmt.Errorf("%w: %s", graph.ErrNotFound, id)
	}
	return mkPage(f.changes[:1], p.PageSize), nil
}
func (f *fakeEngine) Changes(_ context.Context, _ graph.TimeRange, flt graph.ChangeFilter) (graph.Page[graph.Change], error) {
	var out []graph.Change
	for _, c := range f.changes {
		if flt.Subject == "" || c.Subject == flt.Subject {
			out = append(out, c)
		}
	}
	return mkPage(out, flt.PageSize), nil
}
func (f *fakeEngine) Diff(_ context.Context, from, to time.Time) (graph.Diff, error) {
	return graph.Diff{From: from, To: to, Added: f.ents, Changed: []graph.Entity{}, Removed: []graph.EntityID{idB}}, nil
}

func newFake() *fakeEngine {
	return &fakeEngine{
		state: graph.State{Kind: graph.StateReady},
		ents: []graph.Entity{
			{ID: idA, Type: "repo", Label: "Alpha", Attributes: map[string]any{"path": "/x/alpha"}, ObservedAt: t0, RecordedAt: t0},
			{ID: idB, Type: "repo", Label: "Beta", Attributes: nil, ObservedAt: t0, RecordedAt: t0},
		},
		changes: []graph.Change{
			{Kind: graph.ChangeAdded, Subject: graph.SubjectEntity, Entity: idA, ObservedAt: t0, RecordedAt: t0},
			{Kind: graph.ChangeAdded, Subject: graph.SubjectRelation, From: idA, To: idB, RelationType: "depends_on", ObservedAt: t0, RecordedAt: t0},
		},
	}
}

func schemas(t *testing.T) *contract.Schemas {
	t.Helper()
	raw, err := os.ReadFile("../../openapi/gocontract.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]any `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return &contract.Schemas{Components: doc.Components.Schemas}
}

func get(t *testing.T, h http.Handler, target string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, Prefix+target, nil))
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("%s: bad json %q", target, rec.Body.String())
	}
	return rec.Code, body
}

func TestSuccessResponsesMatchContract(t *testing.T) {
	s := schemas(t)
	h := New(newFake(), func() ChildState { return ChildReady })
	id := string(idA)
	cases := []struct{ path, schema string }{
		{"/entities", "Graph.EntityPage"},
		{"/entities?match=alpha&type=repo&limit=5", "Graph.EntityPage"},
		{"/entities/" + id, "Graph.Entity"},
		{"/entities/" + string(idB), "Graph.Entity"},
		{"/entities/" + id + "/neighbors?direction=out", "Graph.EdgePage"},
		{"/entities/" + id + "/history?since=2025-01-01T00:00:00Z", "Graph.ChangePage"},
		{"/changes", "Graph.ChangePage"},
		{"/changes?type=depends_on", "Graph.ChangePage"},
		{"/diff?from=2025-01-01T00:00:00Z&to=2025-01-03T00:00:00Z", "Graph.Diff"},
		{"/schema", "Graph.SchemaSummary"},
		{"/status", "Graph.Status"},
	}
	for _, c := range cases {
		code, body := get(t, h, c.path)
		if code != 200 {
			t.Fatalf("%s: status %d %v", c.path, code, body)
		}
		if errs := s.Validate(map[string]any{"$ref": "#/components/schemas/" + c.schema}, body, false); len(errs) > 0 {
			t.Errorf("%s: %v", c.path, errs)
		}
	}
}

func TestErrors(t *testing.T) {
	s := schemas(t)
	h := New(newFake(), nil)
	unknown := "/entities/repo:" + strings.Repeat("c", 32)
	cases := []struct {
		path string
		code int
	}{
		{unknown, 404},
		{unknown + "/neighbors", 404},
		{unknown + "/history", 404},
		{"/entities/not-an-id", 400},
		{"/entities?limit=abc", 400},
		{"/entities?limit=0", 400},
		{"/entities?as_of=yesterday", 400},
		{"/entities/" + string(idA) + "/neighbors?direction=up", 400},
		{"/changes?since=2025-02-01T00:00:00Z&until=2025-01-01T00:00:00Z", 400},
		{"/diff?from=2025-01-01T00:00:00Z", 400},
		{"/diff", 400},
	}
	for _, c := range cases {
		code, body := get(t, h, c.path)
		if code != c.code {
			t.Errorf("%s: got %d want %d (%v)", c.path, code, c.code, body)
		}
		if c.code == 400 {
			if errs := s.Validate(map[string]any{"$ref": "#/components/schemas/InvalidRequestErrorEncoded"}, body, false); len(errs) > 0 {
				t.Errorf("%s: %v", c.path, errs)
			}
		}
	}
}

func TestLimits(t *testing.T) {
	f := newFake()
	h := New(f, nil)
	_, body := get(t, h, "/entities")
	if body["limit"] != float64(100) || f.lastFQ.PageSize != 100 {
		t.Fatalf("default limit: %v / %d", body["limit"], f.lastFQ.PageSize)
	}
	_, body = get(t, h, "/entities?limit=5000")
	if body["limit"] != float64(1000) || f.lastFQ.PageSize != 1000 {
		t.Fatalf("cap: %v / %d", body["limit"], f.lastFQ.PageSize)
	}
	_, body = get(t, h, "/entities?limit=1")
	if body["truncated"] != true || body["total"] != float64(2) || len(body["items"].([]any)) != 1 {
		t.Fatalf("truncation: %v", body)
	}
	_, body = get(t, h, "/entities?match=BETA&limit=5000")
	if body["total"] != float64(1) || body["limit"] != float64(1000) {
		t.Fatalf("match: %v", body)
	}
}

func TestUnavailableWhenNotReady(t *testing.T) {
	for _, st := range []graph.Kind{graph.StateDisabled, graph.StateFailed, graph.StateStarting} {
		f := newFake()
		f.state = graph.State{Kind: st, Reason: "r"}
		h := New(f, nil)
		for _, p := range []string{"/entities", "/entities/" + string(idA), "/changes", "/schema", "/diff?from=2025-01-01T00:00:00Z&to=2025-01-02T00:00:00Z"} {
			code, body := get(t, h, p)
			if code != 503 || body["code"] != "graph_unavailable" || body["_tag"] != "ServiceUnavailableError" {
				t.Errorf("%s/%s: %d %v", st, p, code, body)
			}
		}
		code, body := get(t, h, "/status")
		if code != 200 || body["engine"] != string(st) {
			t.Errorf("status %s: %d %v", st, code, body)
		}
	}
	code, _ := get(t, New(nil, nil), "/entities")
	if code != 503 {
		t.Fatalf("nil engine: %d", code)
	}
}

func TestStatusChildStates(t *testing.T) {
	s := schemas(t)
	for in, want := range map[tschild.State]ChildState{
		tschild.StateStarting: ChildStarting, tschild.StateRunning: ChildReady,
		tschild.StateDegraded: ChildDegraded, tschild.StateStopped: ChildStopped,
	} {
		h := New(nil, func() ChildState { return ChildStateOf(in) })
		start := time.Now()
		code, body := get(t, h, "/status")
		if time.Since(start) > time.Second || code != 200 || body["ts_child"] != string(want) || body["engine"] != "disabled" {
			t.Errorf("%s: %d %v", in, code, body)
		}
		if errs := s.Validate(map[string]any{"$ref": "#/components/schemas/Graph.Status"}, body, false); len(errs) > 0 {
			t.Errorf("%v", errs)
		}
	}
	_, body := get(t, New(nil, nil), "/status")
	if body["ts_child"] != "stopped" {
		t.Fatalf("no child: %v", body)
	}
}

func TestSchemaCounts(t *testing.T) {
	_, body := get(t, New(newFake(), nil), "/schema")
	et := body["entity_types"].([]any)[0].(map[string]any)
	rt := body["relation_types"].([]any)[0].(map[string]any)
	if et["name"] != "repo" || et["count"] != float64(2) || rt["name"] != "depends_on" || rt["count"] != float64(1) {
		t.Fatalf("%v", body)
	}
}
