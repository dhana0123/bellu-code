package seek_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/seek"
)

// rsWorld is a generated BSKG state: a CWE hierarchy (child to parent edges,
// possibly cyclic) and the CVEs attached to each CWE.
type rsWorld struct {
	cwes   []string
	edges  [][2]string // child, parent
	attach map[string][]string
}

func (w *rsWorld) children(parent string) []string {
	var out []string
	for _, e := range w.edges {
		if e[1] == parent {
			out = append(out, e[0])
		}
	}
	return out
}

// depths returns the smallest depth of each CWE reachable downward from root
// within maxDepth levels.
func (w *rsWorld) depths(root string, maxDepth int) map[string]int {
	depth := map[string]int{root: 0}
	frontier := []string{root}
	for level := 1; level <= maxDepth; level++ {
		var next []string
		for _, p := range frontier {
			for _, c := range w.children(p) {
				if _, seen := depth[c]; !seen {
					depth[c] = level
					next = append(next, c)
				}
			}
		}
		frontier = next
	}
	return depth
}

// rsServer is a real HTTP fake that serves whatever world is current.
type rsServer struct {
	*httptest.Server
	mu     sync.Mutex
	world  *rsWorld
	depth2 map[string]int // depth=2 neighborhood requests per CWE
}

func rsNewServer(t *testing.T) *rsServer {
	s := &rsServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

func (s *rsServer) reset(w *rsWorld) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.world, s.depth2 = w, map[string]int{}
}

func (s *rsServer) serve(rw http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	w := s.world
	q := r.URL.Query()
	if r.URL.Path == "/v1/graph/neighborhood" && q.Get("depth") == "2" {
		s.depth2[q.Get("id")]++
	}
	s.mu.Unlock()

	known := func(cwe string) bool {
		for _, c := range w.cwes {
			if c == cwe {
				return true
			}
		}
		return false
	}
	reply := func(v any) {
		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(v)
	}
	notFound := func() { http.Error(rw, `{"error":{"code":"not_found"}}`, http.StatusNotFound) }

	p := r.URL.Path
	switch {
	case p == "/v1/graph/neighborhood":
		depth, _ := strconv.Atoi(q.Get("depth"))
		levels := w.depths(q.Get("id"), depth)
		edges := []map[string]string{}
		for _, e := range w.edges {
			// An edge belongs to the neighborhood when its parent is closer than depth.
			if d, ok := levels[e[1]]; ok && d < depth {
				edges = append(edges, map[string]string{"source": "Weakness:" + e[0], "target": "Weakness:" + e[1], "type": "CHILD_OF"})
			}
		}
		reply(map[string]any{"nodes": []any{}, "edges": edges})
	case strings.HasPrefix(p, "/v1/weaknesses/") && strings.HasSuffix(p, "/vulnerabilities"):
		cwe := strings.TrimSuffix(strings.TrimPrefix(p, "/v1/weaknesses/"), "/vulnerabilities")
		items := []map[string]any{}
		for _, id := range w.attach[cwe] {
			items = append(items, map[string]any{"cveID": id, "v3baseScore": 7.5})
		}
		reply(map[string]any{"items": items})
	case strings.HasPrefix(p, "/v1/weaknesses/"):
		cwe := strings.TrimPrefix(p, "/v1/weaknesses/")
		if !known(cwe) {
			notFound()
			return
		}
		reply(map[string]any{"weakness": map[string]string{"cweID": cwe, "name": "Weakness " + cwe}})
	case strings.HasPrefix(p, "/v1/vulnerabilities/"):
		id := strings.TrimPrefix(p, "/v1/vulnerabilities/")
		reply(map[string]any{
			"vulnerability": map[string]any{"cveID": id, "description": rsText, "v3baseScore": 7.5},
			"fixCommits":    []any{},
		})
	default:
		notFound()
	}
}

const rsText = "Heap buffer overflow in the parser when handling record length"

func rsWorldGen() *rapid.Generator[*rsWorld] {
	return rapid.Custom(func(t *rapid.T) *rsWorld {
		n := rapid.IntRange(3, 12).Draw(t, "cwes")
		w := &rsWorld{attach: map[string][]string{}}
		for i := 0; i < n; i++ {
			w.cwes = append(w.cwes, fmt.Sprintf("CWE-%d", 100+i))
		}
		pair := rapid.SliceOfN(rapid.SampledFrom(w.cwes), 2, 2)
		for _, p := range rapid.SliceOfN(pair, 0, 3*n).Draw(t, "edges") {
			w.edges = append(w.edges, [2]string{p[0], p[1]})
		}
		cve := rapid.SampledFrom([]string{
			"CVE-2020-1000", "CVE-2020-1001", "CVE-2020-1002",
			"CVE-2020-1003", "CVE-2020-1004", "CVE-2020-1005",
		})
		for _, c := range w.cwes {
			// Sparse attachments make the no-direct-candidate case frequent.
			if rapid.IntRange(0, 2).Draw(t, "has") == 0 {
				w.attach[c] = rapid.SliceOfNDistinct(cve, 0, 3, func(s string) string { return s }).Draw(t, "cves")
			}
		}
		return w
	})
}

func rsPlan(t *rapid.T, w *rsWorld) seek.Plan {
	preds := rapid.SliceOfNDistinct(rapid.SampledFrom(w.cwes), 1, 4, func(s string) string { return s }).Draw(t, "predicted")
	units := make([]seek.Unit, len(preds))
	for i, id := range preds {
		units[i] = seek.Unit{CWEID: id, RootCause: rsText, Snippet: rsText}
	}
	return seek.Plan{Language: "go", Reasoning: "property test", Weaknesses: units}
}

func rsRetriever(t *testing.T, srv *rsServer) *seek.Retriever {
	cfg := rtConfig(5*time.Second, 20*time.Second)
	cfg.MinRelevance = 0
	r, _ := rtRetriever(t, srv.URL, cfg)
	return r
}

func rsHasAttached(w *rsWorld, levels map[string]int, maxDepth int) bool {
	for cwe, d := range levels {
		if d <= maxDepth && len(w.attach[cwe]) > 0 {
			return true
		}
	}
	return false
}

// Feature: bellu-seek-planner, Property 6: Expansion happens only when the direct scope has no candidates
// **Validates: Requirements 5.2, 5.7, 6.1**
func TestPropExpansionOnlyWhenDirectScopeEmpty(t *testing.T) {
	srv := rsNewServer(t)
	r := rsRetriever(t, srv)
	rapid.Check(t, func(t *rapid.T) {
		w := rsWorldGen().Draw(t, "world")
		plan := rsPlan(t, w)
		srv.reset(w)

		res := r.Run(context.Background(), plan, 10)
		if res.Status != "ok" || len(res.Units) != len(plan.Weaknesses) {
			t.Fatalf("result = %+v", res)
		}
		for i, u := range res.Units {
			levels := w.depths(u.CWEID, 2)
			noDirect := !rsHasAttached(w, levels, 1)
			grandchild := false
			for _, d := range levels {
				grandchild = grandchild || d == 2
			}
			if want := noDirect && grandchild; u.Expanded != want {
				t.Fatalf("unit %d %s: Expanded=%v, want %v (scope %v)", i, u.CWEID, u.Expanded, want, u.Scope)
			}
			// The scope holds depth-2 CWEs exactly when expanded.
			hasDepth2 := false
			for _, id := range u.Scope {
				hasDepth2 = hasDepth2 || levels[id] == 2
			}
			if hasDepth2 != u.Expanded {
				t.Fatalf("unit %d %s: scope %v does not match Expanded=%v", i, u.CWEID, u.Scope, u.Expanded)
			}
			// The grandchild fetch happens once, and only without direct candidates.
			wantCalls := 0
			if noDirect {
				wantCalls = 1
			}
			srv.mu.Lock()
			calls := srv.depth2[u.CWEID]
			srv.mu.Unlock()
			if calls != wantCalls {
				t.Fatalf("unit %d %s: %d depth=2 requests, want %d", i, u.CWEID, calls, wantCalls)
			}
		}
	})
}

// Feature: bellu-seek-planner, Property 10: A CVE is returned at most once, in the earliest unit
// **Validates: Requirements 5.2, 5.7, 6.1**
func TestPropCVEReturnedOnceInEarliestUnit(t *testing.T) {
	srv := rsNewServer(t)
	r := rsRetriever(t, srv)
	rapid.Check(t, func(t *rapid.T) {
		w := rsWorldGen().Draw(t, "world")
		plan := rsPlan(t, w)
		srv.reset(w)

		res := r.Run(context.Background(), plan, 10)
		if res.Status != "ok" || len(res.Units) != len(plan.Weaknesses) {
			t.Fatalf("result = %+v", res)
		}
		reach := func(u seek.UnitResult, cve string) bool {
			for _, cwe := range u.Scope {
				for _, id := range w.attach[cwe] {
					if id == cve {
						return true
					}
				}
			}
			return false
		}
		seen := map[string]int{}
		for i, u := range res.Units {
			for _, c := range u.Candidates {
				if first, dup := seen[c.CVEID]; dup {
					t.Fatalf("%s returned in units %d and %d", c.CVEID, first, i)
				}
				seen[c.CVEID] = i
				for j := 0; j < i; j++ {
					if reach(res.Units[j], c.CVEID) {
						t.Fatalf("%s returned in unit %d but unit %d could reach it", c.CVEID, i, j)
					}
				}
				if !reach(u, c.CVEID) {
					t.Fatalf("%s returned in unit %d outside its scope %v", c.CVEID, i, u.Scope)
				}
			}
		}
		// Nothing reachable is lost to dedupe: with at most 6 CVEs and topK 10,
		// every reachable CVE appears in the earliest unit that reaches it.
		reachable := map[string]int{}
		for i, u := range res.Units {
			for _, cwe := range u.Scope {
				for _, id := range w.attach[cwe] {
					if _, ok := reachable[id]; !ok {
						reachable[id] = i
					}
				}
			}
		}
		var missing []string
		for id, i := range reachable {
			if got, ok := seen[id]; !ok || got != i {
				missing = append(missing, id)
			}
		}
		sort.Strings(missing)
		if len(missing) > 0 {
			t.Fatalf("CVEs not returned in their earliest unit: %v (units %+v)", missing, res.Units)
		}
	})
}
