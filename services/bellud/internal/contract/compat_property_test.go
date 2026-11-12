package contract_test

// Property 13: Contract compatibility.
// Validates: Requirements 22.1, 22.2, 22.3, 22.4, 22.5, 22.9
//
// Today the only go-owned operations are the native Stage 0 graph routes (TS never served them), so TS-vs-Go
// parity is exercised on the operations bellud proxies: routing a recorded fixture through the front door
// (owner ts -> proxy -> backend replaying the recorded TS response) must not change status, content type or
// schema validity compared with replaying it directly. Go-owned graph operations are checked against the
// embedded gocontract.json schemas with generated valid and invalid requests. Finally, the owner gate must
// reject flipping any non-graph operation to go without promotion evidence.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"

	apigraph "github.com/bellu/bellucode/services/bellud/internal/api/graph"
	"github.com/bellu/bellucode/services/bellud/internal/auth"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/facade"
	"github.com/bellu/bellucode/services/bellud/internal/contract"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/server"
	"github.com/bellu/bellucode/services/bellud/internal/server/routes"
)

const ccPassword = "pw"

// ccBackend serves the recorded TS response of fixture f for any request (the "TS server" stand-in).
func ccBackend(f contract.Fixture) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", f.ContentType)
		w.WriteHeader(f.Status)
		if len(f.Events) > 0 {
			for _, e := range f.Events {
				e2 := map[string]any{}
				for k, v := range e {
					e2[k] = v
				}
				e2["id"] = "e1" // concrete value for the "<ID>" placeholder
				b, _ := json.Marshal(e2)
				fmt.Fprintf(w, "event: message\ndata: %s\n\n", b)
			}
			if fl, ok := w.(http.Flusher); ok {
				fl.Flush()
			}
			return
		}
		b, _ := json.Marshal(f.Body)
		_, _ = w.Write(b)
	})
}

// ccFrontDoor is bellud's server.Server with the route table as shipped, proxying ts-owned routes to backend.
func ccFrontDoor(a auth.Authenticator, backend http.Handler) http.Handler {
	return &server.Server{
		Table: routes.MustLoadEmbedded(), Auth: a, Proxy: backend,
		Go: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "go handler", 500) }),
	}
}

// ccOptions resolves the fixture auth placeholders against authenticator a.
func ccOptions(a auth.Authenticator) contract.Options {
	return contract.Options{
		Params:  map[string]string{"<CODE>": "abc"},
		SSEWait: 3 * time.Second,
		Auth: func(f contract.Fixture) string {
			basic := func(u, p string) string { return "Basic " + ccB64(u+":"+p) }
			switch {
			case strings.Contains(f.Name, "password-as-bearer"):
				return "Bearer " + ccPassword
			case strings.Contains(f.Name, "wrong-password"):
				return basic(auth.Username, "nope")
			case strings.Contains(f.Name, "wrong-username"):
				return basic("nobody", ccPassword)
			case strings.Contains(f.Name, "session-token"):
				tok, _ := a.IssueSession(time.Now())
				return basic(auth.Username, tok)
			}
			return basic(auth.Username, ccPassword)
		},
	}
}

func ccB64(s string) string {
	const tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var b strings.Builder
	for i := 0; i < len(s); i += 3 {
		var n, k uint32
		for j := 0; j < 3; j++ {
			n <<= 8
			if i+j < len(s) {
				n |= uint32(s[i+j])
				k++
			}
		}
		for j := uint32(0); j < 4; j++ {
			if j <= k {
				b.WriteByte(tbl[(n>>(18-6*j))&63])
			} else {
				b.WriteByte('=')
			}
		}
	}
	return b.String()
}

type ccResult struct {
	status int
	ct     string
	valid  bool
	detail string
}

// ccReplay replays f against h and validates the body (fixture placeholders tolerated for JSON bodies).
func ccReplay(t *rapid.T, s *contract.Schemas, h http.Handler, f contract.Fixture, opts contract.Options, noise map[string]string) ccResult {
	if len(f.Events) > 0 { // SSE: contract.Check validates status, content type, payloads and event types.
		for k, v := range noise {
			f.Request.Headers[k] = v
		}
		vs := contract.Check(f.OperationID, h, []contract.Fixture{f}, opts)
		return ccResult{status: f.Status, ct: f.ContentType, valid: len(vs) == 0, detail: fmt.Sprint(vs)}
	}
	body := ""
	if f.Request.Body != nil {
		b, _ := json.Marshal(f.Request.Body)
		body = string(b)
	}
	path := f.Path
	for k, v := range opts.Params {
		path = strings.ReplaceAll(path, k, v)
	}
	req := httptest.NewRequest(f.Method, path, strings.NewReader(body))
	for k, v := range f.Request.Headers {
		if strings.HasPrefix(v, "<AUTH:") {
			v = opts.Auth(f)
		}
		req.Header.Set(k, v)
	}
	for k, v := range noise {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	res := rec.Result()
	b, _ := io.ReadAll(res.Body)
	r := ccResult{status: res.StatusCode, ct: strings.Split(res.Header.Get("Content-Type"), ";")[0]}
	sc, ok := s.Response(f.OperationID, res.StatusCode, r.ct)
	if !ok {
		r.detail = "no schema declared"
		return r
	}
	var got any
	if err := json.Unmarshal(b, &got); err != nil {
		r.detail = "not JSON: " + err.Error()
		return r
	}
	msgs := s.Validate(sc, got, true)
	r.valid, r.detail = len(msgs) == 0, strings.Join(msgs, "; ")
	return r
}

func TestCompatFrontDoorTransparent(t *testing.T) {
	s, err := contract.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	fixtures, err := contract.LoadFixtures("testdata")
	if err != nil || len(fixtures) == 0 {
		t.Fatalf("fixtures: %v (%d)", err, len(fixtures))
	}
	a := auth.New(ccPassword)
	opts := ccOptions(a)
	rapid.Check(t, func(t *rapid.T) {
		f := rapid.SampledFrom(fixtures).Draw(t, "fixture")
		noise := map[string]string{}
		if rapid.Bool().Draw(t, "noise") {
			noise["X-Request-Id"] = rapid.StringMatching(`[a-z0-9-]{1,24}`).Draw(t, "rid")
		}
		if f.Request.Headers == nil {
			f.Request.Headers = map[string]string{}
		} else { // do not mutate the shared fixture
			h := map[string]string{}
			for k, v := range f.Request.Headers {
				h[k] = v
			}
			f.Request.Headers = h
		}
		// The recorded TS server auth outcome is the baseline: replay the backend directly with the same request.
		direct := ccReplay(t, s, ccBackend(f), f, opts, noise)
		routed := ccReplay(t, s, ccFrontDoor(a, ccBackend(f)), f, opts, noise)
		if routed.status != direct.status || routed.status != f.Status {
			t.Fatalf("%s/%s: status direct=%d routed=%d recorded=%d", f.OperationID, f.Name, direct.status, routed.status, f.Status)
		}
		if routed.ct != direct.ct {
			t.Fatalf("%s/%s: content type direct=%q routed=%q", f.OperationID, f.Name, direct.ct, routed.ct)
		}
		if !direct.valid {
			t.Fatalf("%s/%s: recorded response schema-invalid: %s", f.OperationID, f.Name, direct.detail)
		}
		if !routed.valid {
			t.Fatalf("%s/%s: routed response schema-invalid: %s", f.OperationID, f.Name, routed.detail)
		}
	})
}

// ---- go-owned graph operations ----

type ccOp struct{ id, path string }

var ccOps = []ccOp{
	{"experimental.graph.find", "/entities"},
	{"experimental.graph.entity", "/entities/{id}"},
	{"experimental.graph.neighbors", "/entities/{id}/neighbors"},
	{"experimental.graph.history", "/entities/{id}/history"},
	{"experimental.graph.changes", "/changes"},
	{"experimental.graph.diff", "/diff"},
	{"experimental.graph.schema", "/schema"},
	{"experimental.graph.status", "/status"},
}

type ccDoc struct {
	Paths map[string]map[string]struct {
		OperationID string `json:"operationId"`
		Responses   map[string]struct {
			Content map[string]struct {
				Schema any `json:"schema"`
			} `json:"content"`
		} `json:"responses"`
	} `json:"paths"`
	Components struct {
		Schemas map[string]any `json:"schemas"`
	} `json:"components"`
}

func ccLoadDoc(t *testing.T) (*ccDoc, *contract.Schemas) {
	t.Helper()
	raw, err := os.ReadFile("../openapi/gocontract.json")
	if err != nil {
		t.Fatal(err)
	}
	var d ccDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	return &d, &contract.Schemas{Components: d.Components.Schemas}
}

func ccOpenEngine(t *testing.T) (apigraph.ChildState, http.Handler, string) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil { // the store requires a private data directory
		t.Fatal(err)
	}
	en, err := facade.Open(ctx, facade.Config{Enabled: true, Dir: dir, MCPToken: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = en.Close(ctx) })
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
	return apigraph.ChildReady, apigraph.New(en, func() apigraph.ChildState { return apigraph.ChildReady }), string(hid)
}

func TestCompatGraphResponsesMatchContract(t *testing.T) {
	doc, schemas := ccLoadDoc(t)
	_, real, hostID := ccOpenEngine(t)
	disabled := apigraph.New(nil, nil)

	declared := map[string]map[string]any{} // op -> status -> schema
	for _, methods := range doc.Paths {
		for _, o := range methods {
			m := map[string]any{}
			for st, r := range o.Responses {
				m[st] = r.Content["application/json"].Schema
			}
			declared[o.OperationID] = m
		}
	}
	for _, op := range ccOps {
		if declared[op.id] == nil {
			t.Fatalf("operation %s missing from gocontract.json", op.id)
		}
	}

	idGen := rapid.OneOf(
		rapid.Just(hostID),
		rapid.StringMatching(`[a-z][a-z0-9_]{0,8}:[0-9a-f]{32}`),
		rapid.StringMatching(`[A-Za-z0-9:_-]{1,40}`),
	)
	limitGen := rapid.OneOf(
		rapid.Just(""),
		rapid.Map(rapid.IntRange(-5, 2000), func(n int) string { return fmt.Sprint(n) }),
		rapid.StringMatching(`[a-z0-9.-]{1,6}`),
	)
	timeGen := rapid.OneOf(
		rapid.Just(""),
		rapid.Map(rapid.Int64Range(0, 4_102_444_800), func(n int64) string {
			return time.Unix(n, 0).UTC().Format(time.RFC3339)
		}),
		rapid.StringMatching(`[a-z0-9:-]{1,12}`),
	)
	wordGen := rapid.OneOf(rapid.Just(""), rapid.StringMatching(`[a-z_]{1,8}`), rapid.SampledFrom([]string{"in", "out", "both", "up"}))

	rapid.Check(t, func(t *rapid.T) {
		op := rapid.SampledFrom(ccOps).Draw(t, "op")
		useReal := rapid.Bool().Draw(t, "engine")
		path := strings.ReplaceAll(op.path, "{id}", url.PathEscape(idGen.Draw(t, "id")))
		q := url.Values{}
		for _, k := range []string{"limit"} {
			if v := limitGen.Draw(t, k); v != "" {
				q.Set(k, v)
			}
		}
		for _, k := range []string{"as_of", "since", "until", "from", "to"} {
			if v := timeGen.Draw(t, k); v != "" {
				q.Set(k, v)
			}
		}
		for _, k := range []string{"type", "match", "direction"} {
			if v := wordGen.Draw(t, k); v != "" {
				q.Set(k, v)
			}
		}
		h := disabled
		if useReal {
			h = real
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, apigraph.Prefix+path+"?"+q.Encode(), nil))
		res := rec.Result()
		if ct := strings.Split(res.Header.Get("Content-Type"), ";")[0]; ct != "application/json" {
			t.Fatalf("%s %s: content type %q", op.id, path, ct)
		}
		var body any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: body not JSON: %v", op.id, err)
		}
		sc, ok := declared[op.id][fmt.Sprint(res.StatusCode)]
		switch {
		case res.StatusCode == 404 && !ok:
			// Not-found on unknown ids is not declared in gocontract.json; it must still be a NotFoundError.
			if m, _ := body.(map[string]any); m["_tag"] != "NotFoundError" {
				t.Fatalf("%s: undeclared 404 with body %v", op.id, body)
			}
			return
		case !ok:
			t.Fatalf("%s %s?%s: status %d not declared", op.id, path, q.Encode(), res.StatusCode)
		}
		if res.StatusCode == 503 { // documented extension: stable `code` marker beyond ServiceUnavailableError
			m, _ := body.(map[string]any)
			if m["code"] != "graph_unavailable" {
				t.Fatalf("%s: 503 without graph_unavailable code: %v", op.id, body)
			}
			cp := map[string]any{}
			for k, v := range m {
				if k != "code" {
					cp[k] = v
				}
			}
			body = cp
		}
		if !useReal && res.StatusCode != 503 && op.id != "experimental.graph.status" {
			t.Fatalf("%s: disabled engine answered %d", op.id, res.StatusCode)
		}
		if msgs := schemas.Validate(sc, body, false); len(msgs) > 0 {
			t.Fatalf("%s %s?%s: status %d body %s invalid: %v", op.id, path, q.Encode(), res.StatusCode, rec.Body.String(), msgs)
		}
	})
}

// ---- owner gate ----

func TestCompatGateRejectsFlippedNonGraphOps(t *testing.T) {
	orig := routes.MustLoadEmbedded()
	all := orig.Routes()
	var cand []int
	for i, r := range all {
		if r.Owner == routes.OwnerTS && !strings.HasPrefix(r.Pattern, apigraph.Prefix) {
			cand = append(cand, i)
		}
	}
	if len(cand) == 0 {
		t.Fatal("no ts-owned routes")
	}
	fixtures, err := contract.LoadFixtures("testdata")
	if err != nil {
		t.Fatal(err)
	}
	if v := contract.GateViolations(orig, fixtures, nil, contract.Options{}); len(v) != 0 {
		t.Fatalf("shipped table violates gate: %v", v)
	}
	rapid.Check(t, func(t *rapid.T) {
		i := rapid.SampledFrom(cand).Draw(t, "route")
		rs := append([]routes.Route(nil), all...)
		rs[i].Owner = routes.OwnerGo
		tbl, err := routes.NewTable(rs)
		if err != nil {
			t.Fatal(err)
		}
		// Neither without a handler nor with one that does not satisfy the fixtures may the flip pass.
		bad := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) })
		for _, hf := range []contract.HandlerFor{nil, func(routes.Route) http.Handler { return bad }} {
			if v := contract.GateViolations(tbl, fixtures, hf, contract.Options{}); len(v) == 0 {
				t.Fatalf("flipping %s %s to go passed the gate", rs[i].Method, rs[i].Pattern)
			}
		}
	})
}
