package identity

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/lens"
)

func do(t *testing.T, r Reacher, enabled bool, url string) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	Mount(mux, r, enabled)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", url, nil))
	return w
}

func TestPaths(t *testing.T) {
	var gotHops int
	ok := func(_ context.Context, a, b string, o lens.ReachOpts) (lens.ReachResult, error) {
		gotHops = o.MaxHops
		return lens.ReachResult{Source: a, Target: b, Path: []lens.ReachHop{{From: a, To: b, Relation: "can_assume"}}}, nil
	}
	w := do(t, ok, true, "/api/experimental/identity/paths?from=a&to=b&max_hops=3")
	if w.Code != 200 || gotHops != 3 || !strings.Contains(w.Body.String(), `"can_assume"`) {
		t.Fatalf("%d %d %s", w.Code, gotHops, w.Body)
	}
	for _, u := range []string{"?from=a", "?from=a&to=b&max_hops=11", "?from=a&to=b&max_hops=x"} {
		if c := do(t, ok, true, "/api/experimental/identity/paths"+u).Code; c != 400 {
			t.Fatalf("%s: %d", u, c)
		}
	}
	if c := do(t, ok, false, "/api/experimental/identity/paths?from=a&to=b").Code; c != 404 {
		t.Fatal(c)
	}
}

func TestDeadlineReturnsNoPartial(t *testing.T) {
	slow := func(_ context.Context, a, b string, _ lens.ReachOpts) (lens.ReachResult, error) {
		return lens.ReachResult{Path: []lens.ReachHop{{From: a, To: b}}}, context.DeadlineExceeded
	}
	w := do(t, slow, true, "/api/experimental/identity/paths?from=a&to=b")
	if w.Code != 504 || strings.Contains(w.Body.String(), `"paths"`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}
