package data

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/scanners/dataclass"
)

type fakeGraph struct {
	graph.Query
	ents map[string][]graph.Entity // by resource_type
}

func (f fakeGraph) Find(_ context.Context, q graph.FindQuery) (graph.Page[graph.Entity], error) {
	return graph.Page[graph.Entity]{Items: f.ents[q.Attributes["resource_type"]]}, nil
}

func (f fakeGraph) Entity(_ context.Context, id graph.EntityID, _ *time.Time) (graph.Entity, error) {
	for _, es := range f.ents {
		for _, e := range es {
			if e.ID == id {
				return e, nil
			}
		}
	}
	return graph.Entity{}, graph.ErrNotFound
}

type fakeClasses map[string]dataclass.Row

func (f fakeClasses) Get(_ context.Context, id string) (dataclass.Row, bool, error) {
	r, ok := f[id]
	return r, ok, nil
}

func (f fakeClasses) List(_ context.Context, ids []string) (map[string]dataclass.Row, error) {
	out := map[string]dataclass.Row{}
	for _, id := range ids {
		if r, ok := f[id]; ok {
			out[id] = r
		}
	}
	return out, nil
}

func deps() Deps {
	b := graph.Entity{ID: "aws_resource:b1", Type: "aws_resource", Label: "bkt", Attributes: map[string]any{
		"resource_type": "s3:bucket", "name": "bkt", "encryption_at_rest": true, "public_access": false}}
	return Deps{
		Graph:   fakeGraph{ents: map[string][]graph.Entity{"s3:bucket": {b}}},
		Classes: fakeClasses{"aws_resource:b1": {EntityID: "aws_resource:b1", Classes: []string{"pii"}, MatchCounts: map[string]int{"pii": 3}}},
	}
}

func do(h http.Handler, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	return rec
}

func TestListHasClassesAndAttributes(t *testing.T) {
	rec := do(New(deps(), true), Prefix+"/stores")
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var out struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out.Items) != 1 {
		t.Fatalf("%v %s", err, rec.Body)
	}
	it := out.Items[0]
	if it["encryptionAtRest"] != true || it["publicAccess"] != false || it["name"] != "bkt" ||
		it["classes"].([]any)[0] != "pii" || it["matchCounts"].(map[string]any)["pii"] != float64(3) || it["openExposureCount"] != float64(0) {
		t.Fatalf("unexpected item %v", it)
	}
}

func TestGetUnknownIs404(t *testing.T) {
	if rec := do(New(deps(), true), Prefix+"/stores/nope"); rec.Code != 404 {
		t.Fatalf("status %d", rec.Code)
	}
	if rec := do(New(deps(), true), Prefix+"/stores/aws_resource:b1"); rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
}

func TestFlagOffIs404(t *testing.T) {
	h := New(deps(), false)
	for _, p := range []string{Prefix + "/stores", Prefix + "/stores/aws_resource:b1"} {
		if rec := do(h, p); rec.Code != 404 {
			t.Fatalf("%s: status %d", p, rec.Code)
		}
	}
}
