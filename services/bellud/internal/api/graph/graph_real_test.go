package graph

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/facade"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

// realEngine opens a real facade engine in a temp dir and applies a small batch.
func realEngine(t *testing.T) (hostID, procID string, h func(string) (int, map[string]any)) {
	t.Helper()
	ctx := context.Background()
	en, err := facade.Open(ctx, facade.Config{Enabled: true, Dir: filepath.Join(t.TempDir(), "g")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { en.Close(ctx) })
	hid, err := facade.Hash("host", map[string]string{"hostname": "h1"})
	if err != nil {
		t.Fatal(err)
	}
	pid, err := facade.Hash("process", map[string]string{"host": "h1", "pid": "7", "start_time": "1"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = en.Ingest().Apply(ctx, batch.Batch{
		Collector: "host", ObservedAt: time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC),
		Entities: []batch.Entity{
			{Type: "host", Identity: map[string]string{"hostname": "h1"}, Attributes: map[string]any{"os": "linux"}},
			{Type: "process", Identity: map[string]string{"host": "h1", "pid": "7", "start_time": "1"}, Attributes: map[string]any{"cmd": "sh"}},
		},
		Relations: []batch.Relation{{Type: "runs_on", From: string(pid), To: string(hid)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := New(en, func() ChildState { return ChildReady })
	return string(hid), string(pid), func(p string) (int, map[string]any) { return get(t, handler, p) }
}

func TestRealEngineWireOutput(t *testing.T) {
	s := schemas(t)
	hid, pid, h := realEngine(t)
	cases := []struct{ path, schema string }{
		{"/entities", "Graph.EntityPage"},
		{"/entities?type=host&match=H1", "Graph.EntityPage"},
		{"/entities/" + hid, "Graph.Entity"},
		{"/entities/" + pid + "/neighbors?direction=out", "Graph.EdgePage"},
		{"/entities/" + hid + "/history", "Graph.ChangePage"},
		{"/changes", "Graph.ChangePage"},
		{"/diff?from=2025-01-01T00:00:00Z&to=2030-01-01T00:00:00Z", "Graph.Diff"},
		{"/schema", "Graph.SchemaSummary"},
		{"/status", "Graph.Status"},
	}
	for _, c := range cases {
		code, body := h(c.path)
		if code != 200 {
			t.Fatalf("%s: %d %v", c.path, code, body)
		}
		if errs := s.Validate(map[string]any{"$ref": "#/components/schemas/" + c.schema}, body, false); len(errs) > 0 {
			t.Errorf("%s: %v", c.path, errs)
		}
	}
	_, body := h("/entities")
	if body["total"] != float64(2) {
		t.Fatalf("total: %v", body)
	}
	_, body = h("/entities?type=host&match=H1")
	if body["total"] != float64(1) {
		t.Fatalf("filtered: %v", body)
	}
	_, body = h("/entities/" + pid + "/neighbors?direction=out")
	if body["total"] != float64(1) {
		t.Fatalf("neighbors: %v", body)
	}
	_, body = h("/status")
	if body["engine"] != "ready" || body["ts_child"] != "ready" {
		t.Fatalf("status: %v", body)
	}
}

func TestRealEngineErrorsAndClamping(t *testing.T) {
	_, _, h := realEngine(t)
	for path, want := range map[string]int{
		"/entities/host:" + "00000000000000000000000000000000": 404,
		"/entities/bogus":                 400,
		"/entities?limit=0":               400,
		"/entities?limit=-3":              400,
		"/diff?from=2025-01-01T00:00:00Z": 400,
		"/entities?as_of=notatime":        400,
	} {
		if code, body := h(path); code != want {
			t.Errorf("%s: %d want %d (%v)", path, code, want, body)
		}
	}
	if _, body := h("/entities?limit=999999"); body["limit"] != float64(1000) {
		t.Fatalf("clamp: %v", body["limit"])
	}
	if _, body := h("/entities?limit=1"); body["truncated"] != true || len(body["items"].([]any)) != 1 {
		t.Fatalf("truncate: %v", body)
	}
}
