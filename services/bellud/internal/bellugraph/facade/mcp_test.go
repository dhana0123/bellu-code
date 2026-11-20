package facade

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

type bearerRT struct{ tok string }

func (b bearerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	if b.tok != "" {
		r.Header.Set("Authorization", "Bearer "+b.tok)
	}
	return http.DefaultTransport.RoundTrip(r)
}

type failSink struct{}

func (failSink) Write(AuditRecord) error { return errors.New("disk full") }

type memSink struct{ recs []AuditRecord }

func (m *memSink) Write(r AuditRecord) error { m.recs = append(m.recs, r); return nil }

func mcpEngine(t *testing.T, token string) (*engine, *httptest.Server) {
	t.Helper()
	cfg := testCfg(filepath.Join(t.TempDir(), "g"), &bytes.Buffer{})
	cfg.MCPToken = token
	en, err := Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	e := en.(*engine)
	t.Cleanup(func() { e.Close(context.Background()) })
	srv := httptest.NewServer(e.MCPHandler())
	t.Cleanup(srv.Close)
	return e, srv
}

func mcpClient(t *testing.T, url, tok string) *mcpsdk.ClientSession {
	t.Helper()
	c := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "t", Version: "1"}, nil)
	s, err := c.Connect(context.Background(), &mcpsdk.StreamableClientTransport{
		Endpoint: url, HTTPClient: &http.Client{Transport: bearerRT{tok}}, DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestMCPExactlyTwelveToolsAndName(t *testing.T) {
	_, srv := mcpEngine(t, "s3cret")
	s := mcpClient(t, srv.URL, "s3cret")
	init := s.InitializeResult()
	if !strings.Contains(init.ServerInfo.Title, "Bellu Graph Engine") || !strings.Contains(init.Instructions, "Bellu Graph Engine") ||
		strings.Contains(strings.ToLower(init.ServerInfo.Title+init.Instructions), "toi"+"se") {
		t.Fatalf("server info %+v", init.ServerInfo)
	}
	res, err := s.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, tl := range res.Tools {
		got = append(got, tl.Name)
	}
	// The last five MCPTools come from Config.MCPExtras, which this engine does not set.
	want := append([]string(nil), MCPTools[:12]...)
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") || len(got) != 12 {
		t.Fatalf("tools %v", got)
	}
}

func TestMCPBearerRequired(t *testing.T) {
	_, srv := mcpEngine(t, "s3cret")
	for _, h := range []string{"", "Bearer wrong", "Basic s3cret"} {
		req, _ := http.NewRequest("POST", srv.URL, strings.NewReader("{}"))
		if h != "" {
			req.Header.Set("Authorization", h)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%q: got %d", h, resp.StatusCode)
		}
	}
}

func seedHost(t *testing.T, e *engine) string {
	t.Helper()
	if _, err := e.Ingest().Apply(context.Background(), batch.Batch{
		Collector: "host", ObservedAt: t0, Entities: []batch.Entity{hostEnt("h1", map[string]any{"os": "linux"})},
	}); err != nil {
		t.Fatal(err)
	}
	return mustID(t, "host", map[string]string{"hostname": "h1"})
}

func annotate(t *testing.T, s *mcpsdk.ClientSession, id string) *mcpsdk.CallToolResult {
	t.Helper()
	res, err := s.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name: "annotate_entity", Arguments: map[string]any{"entity_id": id, "annotations": map[string]string{"note": "hi"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestMCPAnnotateAuditedBeforeApply(t *testing.T) {
	e, srv := mcpEngine(t, "s3cret")
	id := seedHost(t, e)
	sink := &memSink{}
	e.audit = sink
	res := annotate(t, mcpClient(t, srv.URL, "s3cret"), id)
	if res.IsError {
		t.Fatalf("annotate failed: %+v", res.Content)
	}
	if len(sink.recs) != 1 {
		t.Fatalf("audit %+v", sink.recs)
	}
	r := sink.recs[0]
	if r.Identity != TokenIdentity("s3cret") || strings.Contains(r.Identity, "s3cret") || r.EntityID != id || r.Time.IsZero() || r.Action != "annotate_entity" {
		t.Fatalf("record %+v", r)
	}
	if a, ok, _ := e.stack.Annotations.Get(id); !ok || a.Values["note"] != "hi" {
		t.Fatalf("annotation not applied: %+v %v", a, ok)
	}
}

func TestMCPAnnotateNotAppliedWhenAuditFails(t *testing.T) {
	e, srv := mcpEngine(t, "s3cret")
	id := seedHost(t, e)
	e.audit = failSink{}
	res := annotate(t, mcpClient(t, srv.URL, "s3cret"), id)
	if !res.IsError {
		t.Fatalf("want error result, got %+v", res)
	}
	if n, _ := e.stack.Annotations.Count(); n != 0 {
		t.Fatalf("annotation applied despite audit failure (%d)", n)
	}
}

func TestMCPDefaultAuditFileAndIdempotentClose(t *testing.T) {
	e, srv := mcpEngine(t, "")
	id := seedHost(t, e)
	if res := annotate(t, mcpClient(t, srv.URL, ""), id); res.IsError {
		t.Fatalf("%+v", res.Content)
	}
	b, err := os.ReadFile(filepath.Join(e.cfg.Dir, auditFileName))
	if err != nil || !strings.Contains(string(b), id) || !strings.Contains(string(b), "front-door") {
		t.Fatalf("audit file %q %v", b, err)
	}
	ctx := context.Background()
	if err := e.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(ctx); err != nil {
		t.Fatalf("second close: %v", err)
	}
}
