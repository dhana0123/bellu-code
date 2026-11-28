package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/graph"
)

type fakeQ struct {
	graph.Query
	by map[string][]graph.Entity
}

func (f fakeQ) Find(_ context.Context, q graph.FindQuery) (graph.Page[graph.Entity], error) {
	return graph.Page[graph.Entity]{Items: f.by[q.Type]}, nil
}

func get(t *testing.T, mux *http.ServeMux, path string) (int, map[string]any) {
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	return rec.Code, m
}

func TestSummaryAndEntities(t *testing.T) {
	q := fakeQ{by: map[string][]graph.Entity{
		"ai_model": {{ID: "m1", Type: "ai_model", Label: "gpt"}, {ID: "m2", Type: "ai_model", Label: "llama"}},
		"ai_agent": {{ID: "a1", Type: "ai_agent", Label: "bot"}},
	}}
	mux := http.NewServeMux()
	Mount(mux, q, true)
	code, m := get(t, mux, Prefix+"/summary")
	if code != 200 || m["total"].(float64) != 3 {
		t.Fatalf("summary %d %v", code, m)
	}
	code, m = get(t, mux, Prefix+"/entities")
	if code != 200 || len(m["items"].([]any)) != 3 {
		t.Fatalf("entities %d %v", code, m)
	}
	code, m = get(t, mux, Prefix+"/entities?kind=ai_agent")
	if code != 200 || len(m["items"].([]any)) != 1 {
		t.Fatalf("kind filter %d %v", code, m)
	}
}

func TestDisabled(t *testing.T) {
	mux := http.NewServeMux()
	Mount(mux, fakeQ{}, false)
	if code, _ := get(t, mux, Prefix+"/summary"); code != 404 {
		t.Fatal(code)
	}
}
