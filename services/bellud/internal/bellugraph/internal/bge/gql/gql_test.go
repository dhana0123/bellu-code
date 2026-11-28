package gql

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/engine"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

var t0 = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

type fixture struct {
	core *engine.Core
	srv  *httptest.Server
	ids  map[string]string
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
	core, err := engine.Open(t.TempDir(), engine.Options{Clock: func() time.Time { return t0.Add(time.Hour) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = core.Close(context.Background()) })
	f := &fixture{core: core, role: "read", ids: map[string]string{
		"host": hash(t, "host", map[string]string{"hostname": "web-1"}),
		"lp":   hash(t, "listening_port", map[string]string{"host": "web-1", "protocol": "tcp", "address": "0.0.0.0", "port": "80"}),
	}}
	_, err = core.Apply(context.Background(), batch.Batch{Collector: "t", ObservedAt: t0, Entities: []batch.Entity{
		{Type: "host", Identity: map[string]string{"hostname": "web-1"}, Attributes: map[string]any{"os": "linux"}},
		{Type: "listening_port", Identity: map[string]string{"host": "web-1", "protocol": "tcp", "address": "0.0.0.0", "port": "80"}},
	}, Relations: []batch.Relation{
		{Type: "on", From: f.ids["lp"], To: f.ids["host"]},
	}}, engine.ModeFull)
	if err != nil {
		t.Fatal(err)
	}
	h := New(Options{
		Core:       core,
		CallerRole: func(context.Context) string { return f.role },
		Annotate: func(ctx context.Context, id string, set map[string]string, unset []string) error {
			f.ann = append(f.ann, id)
			_, err := core.Annotate(ctx, id, set, unset, "test")
			return err
		},
	})
	f.srv = httptest.NewServer(h)
	t.Cleanup(f.srv.Close)
	return f
}

type gqlResp struct {
	Data   map[string]json.RawMessage `json:"data"`
	Errors []struct {
		Message    string         `json:"message"`
		Extensions map[string]any `json:"extensions"`
	} `json:"errors"`
}

func (f *fixture) do(t *testing.T, query string, vars map[string]any) gqlResp {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"query": query, "variables": vars})
	res, err := http.Post(f.srv.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out gqlResp
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func codes(r gqlResp) []string {
	var out []string
	for _, e := range r.Errors {
		c, _ := e.Extensions["code"].(string)
		out = append(out, c)
	}
	return out
}

func TestEntityQuery(t *testing.T) {
	f := newFixture(t)
	r := f.do(t, `query($id: ID!) { entity(id: $id) { id identityFingerprint localId kind label attributes uri
		neighbors { total items { type direction to { kind } } } dependents { id } } }`, map[string]any{"id": f.ids["host"]})
	if len(r.Errors) > 0 {
		t.Fatalf("errors: %+v", r.Errors)
	}
	var e struct {
		ID, IdentityFingerprint, LocalID, Kind, URI string
		Attributes                                  map[string]any
		Neighbors                                   struct {
			Total int
			Items []struct {
				Type, Direction string
				To              struct{ Kind string }
			}
		}
	}
	if err := json.Unmarshal(r.Data["entity"], &e); err != nil {
		t.Fatal(err)
	}
	if e.ID != f.ids["host"] || e.IdentityFingerprint != e.ID || e.Kind != "host" || !strings.HasPrefix(e.LocalID, "@") ||
		!strings.HasPrefix(e.URI, "bellugraph://host/") || e.Attributes["os"] != "linux" {
		t.Fatalf("entity = %+v", e)
	}
	if e.Neighbors.Total != 1 || e.Neighbors.Items[0].Type != "on" || e.Neighbors.Items[0].Direction != "IN" || e.Neighbors.Items[0].To.Kind != "host" {
		t.Fatalf("neighbors = %+v", e.Neighbors)
	}
	// The local id resolves back to the entity.
	r = f.do(t, `query($id: ID!) { entity(id: $id) { id } }`, map[string]any{"id": e.LocalID})
	if len(r.Errors) > 0 || !strings.Contains(string(r.Data["entity"]), f.ids["host"]) {
		t.Fatalf("by local id: %s %+v", r.Data["entity"], r.Errors)
	}
}

func TestAsOf(t *testing.T) {
	f := newFixture(t)
	before := t0.Add(-time.Minute).Format(time.RFC3339Nano)
	r := f.do(t, `query($id: ID!, $at: Time) { entity(id: $id, asOf: $at) { id } }`, map[string]any{"id": f.ids["host"], "at": before})
	if string(r.Data["entity"]) != "null" || fmt.Sprint(codes(r)) != "[NOT_FOUND]" {
		t.Fatalf("as of before ingest: %s %v", r.Data["entity"], codes(r))
	}
	r = f.do(t, `query($at: Time) { find(kind: "host", asOf: $at) { total } }`, map[string]any{"at": before})
	if !strings.Contains(string(r.Data["find"]), `"total":0`) {
		t.Fatalf("find as of before ingest: %s", r.Data["find"])
	}
	r = f.do(t, `query($a: ID!, $b: ID!, $at: Time) { path(from: $a, to: $b, asOf: $at) { connected path { type } } impact(id: $b, asOf: $at) { hops entity { kind } } }`,
		map[string]any{"a": f.ids["lp"], "b": f.ids["host"], "at": t0.Format(time.RFC3339Nano)})
	if len(r.Errors) > 0 || !strings.Contains(string(r.Data["path"]), `"connected":true`) {
		t.Fatalf("path as of: %s %+v", r.Data["path"], r.Errors)
	}
}

func TestAnnotateMutation(t *testing.T) {
	f := newFixture(t)
	q := `mutation($id: ID!) { annotateEntity(id: $id, set: {owner: "ops"}) { annotations } }`
	r := f.do(t, q, map[string]any{"id": f.ids["host"]})
	if fmt.Sprint(codes(r)) != "[FORBIDDEN]" || len(f.ann) != 0 {
		t.Fatalf("read role: codes %v, annotate calls %v", codes(r), f.ann)
	}
	f.role = "write"
	r = f.do(t, q, map[string]any{"id": f.ids["host"]})
	if len(r.Errors) > 0 || !strings.Contains(string(r.Data["annotateEntity"]), `"owner":"ops"`) || len(f.ann) != 1 {
		t.Fatalf("write role: %s %+v %v", r.Data["annotateEntity"], r.Errors, f.ann)
	}
}

func TestErrorCodes(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct{ name, query, code string }{
		{"not found", `{ neighbors(id: "host:00") { total } }`, CodeNotFound},
		{"bad page size", `{ find(first: 0) { total } }`, CodeValidation},
		{"unknown local id", `{ neighbors(id: "@zzzzzz") { total } }`, CodeNotFound},
		{"bad depth", `{ impact(id: "host:00", depth: 99) { hops } }`, CodeValidation},
		{"bad cursor", `{ find(after: "nope") { total } }`, CodeValidation},
		{"schema validation", `{ nope }`, CodeValidation},
		{"parse", `{`, CodeValidation},
	} {
		r := f.do(t, tc.query, nil)
		if len(r.Errors) == 0 || codes(r)[0] != tc.code {
			t.Errorf("%s: codes %v, errors %+v", tc.name, codes(r), r.Errors)
		}
	}
	// Unknown errors are INTERNAL with a generic message.
	g := presentError(context.Background(), errors.New("disk path /secret leaked"))
	if g.Message != "internal error" || g.Extensions["code"] != CodeInternal {
		t.Fatalf("internal: %+v", g)
	}
	g = presentError(context.Background(), gqlerror.WrapPath(nil, fmt.Errorf("%w: engine closed", errs.Unavailable)))
	if g.Extensions["code"] != CodeUnavailable {
		t.Fatalf("unavailable: %+v", g)
	}
}

func TestDepthLimit(t *testing.T) {
	f := newFixture(t)
	// Each "neighbors { items { to {" level adds 3; entity adds 1.
	nest := func(levels int) string {
		return `{ entity(id: "` + f.ids["host"] + `") { ` + strings.Repeat("neighbors { items { to { ", levels) + "id" +
			strings.Repeat(" } } }", levels) + " } }"
	}
	if r := f.do(t, nest(3), nil); len(r.Errors) > 0 { // depth 1+9+1 = 11
		t.Fatalf("depth 11 rejected: %+v", r.Errors)
	}
	r := f.do(t, nest(4), nil) // depth 14
	if fmt.Sprint(codes(r)) != "[VALIDATION]" || !strings.Contains(r.Errors[0].Message, "depth") || r.Data["entity"] != nil {
		t.Fatalf("depth 14: %s %+v", r.Data, r.Errors)
	}
	// Fragments count toward depth.
	q := `query { entity(id: "x") { ...F } } fragment F on Entity { ` + strings.Repeat("neighbors { items { to { ", 4) + "id" + strings.Repeat(" } } }", 4) + " }"
	if r := f.do(t, q, nil); fmt.Sprint(codes(r)) != "[VALIDATION]" {
		t.Fatalf("fragment depth: %+v", r.Errors)
	}
	// Introspection is allowed.
	intro := "{ __schema { queryType { name } types { name fields { type { " + strings.Repeat("ofType { ", 8) + "name" + strings.Repeat(" }", 8) + " } } } } }"
	if r := f.do(t, intro, nil); len(r.Errors) > 0 {
		t.Fatalf("introspection: %+v", r.Errors)
	}
}

func TestChangesSubscriptionSSE(t *testing.T) {
	f := newFixture(t)
	body, _ := json.Marshal(map[string]any{"query": `subscription { changes(fromSeq: "0", filter: {subject: ENTITY}) { seq kind subject entity } }`})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, f.srv.URL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	sc := bufio.NewScanner(res.Body)
	var got []string
	for sc.Scan() && len(got) < 2 {
		if line, ok := strings.CutPrefix(sc.Text(), "data: "); ok && strings.Contains(line, `"changes"`) {
			got = append(got, line)
		}
	}
	if len(got) != 2 || !strings.Contains(got[0], `"kind":"ADDED"`) || !strings.Contains(got[0], `"subject":"ENTITY"`) {
		t.Fatalf("frames = %v", got)
	}
}

func TestEdgeAttributes(t *testing.T) {
	f := newFixture(t)
	if _, err := f.core.Apply(context.Background(), batch.Batch{Collector: "t2", Entities: []batch.Entity{
		{Type: "host", Identity: map[string]string{"hostname": "db-1"}},
	}, Relations: []batch.Relation{
		{Type: "depends_on", From: f.ids["host"], To: hash(t, "host", map[string]string{"hostname": "db-1"}),
			Attributes: map[string]any{"evidence": "seen", "confidence": "inferred", "observed_at": "2025-01-01T00:00:00Z"}},
	}}, engine.ModeFull); err != nil {
		t.Fatal(err)
	}
	r := f.do(t, `query($id: ID!) { neighbors(id: $id) { items { type evidence confidence observedAt } } }`,
		map[string]any{"id": f.ids["host"]})
	if len(r.Errors) > 0 {
		t.Fatalf("errors: %+v", r.Errors)
	}
	var n struct {
		Items []struct {
			Type                             string
			Evidence, Confidence, ObservedAt *string
		}
	}
	if err := json.Unmarshal(r.Data["neighbors"], &n); err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, e := range n.Items {
		switch e.Type {
		case "depends_on":
			seen++
			if e.Evidence == nil || *e.Evidence != "seen" || e.Confidence == nil || *e.Confidence != "inferred" ||
				e.ObservedAt == nil || *e.ObservedAt != "2025-01-01T00:00:00Z" {
				t.Errorf("depends_on = %+v", e)
			}
		case "on":
			seen++
			if e.Evidence != nil || e.Confidence != nil || e.ObservedAt != nil {
				t.Errorf("on must have null attributes: %+v", e)
			}
		}
	}
	if seen != 2 {
		t.Fatalf("items = %+v", n.Items)
	}
}
