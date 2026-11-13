package connectors

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/audit"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/manifest"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/policy"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/registry"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/scope"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/vault"
	"github.com/bellu/bellucode/services/bellud/internal/mcptoken"
)

const secret = "ghp_supersecrettoken123456"

type memAudit struct {
	mu sync.Mutex
	es []audit.Entry
}

func (a *memAudit) Append(_ context.Context, e audit.Entry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.es = append(a.es, e)
	return nil
}
func (a *memAudit) List(string, string, int) (audit.Page, error) { return audit.Page{}, nil }
func (a *memAudit) Prune(time.Time, int) error                   { return nil }
func (a *memAudit) entries() []audit.Entry {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]audit.Entry(nil), a.es...)
}

type opener struct{}

func (opener) Use(_ context.Context, _ vault.Ref, fn func([]byte) error) error {
	return fn([]byte(secret))
}

type provider struct {
	n    atomic.Int32
	body string
}

func (p *provider) RoundTrip(r *http.Request) (*http.Response, error) {
	p.n.Add(1)
	return &http.Response{StatusCode: 200, Header: http.Header{}, Request: r,
		Body: io.NopCloser(strings.NewReader(p.body))}, nil
}

type resolver struct {
	refs map[string]broker.ConnectionRef
}

func (r resolver) ResolveConnection(ref string) (broker.ConnectionRef, bool) {
	c, ok := r.refs[ref]
	return c, ok
}

type fixture struct {
	cs      *mcp.ClientSession
	st      *store.Store
	scope   *scope.Service
	audit   *memAudit
	prov    *provider
	token   mcptoken.Token
	enabled atomic.Bool
	url     string
}

func newFixture(t *testing.T, body string) *fixture {
	t.Helper()
	m := manifest.Manifest{
		ID: "github", Version: "1.0.0", Name: "GitHub",
		AuthMethods: []manifest.AuthMethod{{ID: "pat", Name: "PAT", Enabled: true}},
		Entities:    []string{"github_repo"},
		Egress:      []string{"api.github.com"},
		Operations: []manifest.Operation{
			{Name: "GET /repos/{o}/{r}", Class: manifest.ClassRead, Method: "GET", Host: "api.github.com", Path: "/repos/{o}/{r}", StripKeys: []string{"secret"}},
		},
	}
	pol, err := policy.Compile(m, policy.Selection{})
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AddConnection(store.NewConnection("c1", "github", "work", store.Settings{}, time.Now())); err != nil {
		t.Fatal(err)
	}
	reg := registry.New()
	if err := reg.Register(m); err != nil {
		t.Fatal(err)
	}
	f := &fixture{st: st, audit: &memAudit{}, prov: &provider{body: body}}
	f.scope = scope.New(st, reg, nil)
	b := broker.New(broker.Config{Opener: opener{}, Audit: f.audit, Inner: f.prov, RatePerSecond: 1000, AgentGate: f.scope})
	ref := broker.ConnectionRef{ID: "c1", ConnectorID: "github", Manifest: m, Policy: pol, Auth: broker.AuthGitHubToken,
		Credential: vault.Ref{Owner: vault.OwnerConnection, OwnerID: "c1", Slot: "token"}}
	f.token, err = mcptoken.New()
	if err != nil {
		t.Fatal(err)
	}
	f.enabled.Store(true)
	h, err := NewMCP(Config{Token: f.token, Broker: b, Audit: f.audit, Enabled: f.enabled.Load,
		Resolver: resolver{refs: map[string]broker.ConnectionRef{"work": ref, "c1": ref}}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	f.url = srv.URL
	f.cs = f.connect(t, f.token)
	return f
}

type bearer struct {
	tok mcptoken.Token
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", b.tok.Header())
	return http.DefaultTransport.RoundTrip(r)
}

func (f *fixture) connect(t *testing.T, tok mcptoken.Token) *mcp.ClientSession {
	t.Helper()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).Connect(context.Background(),
		&mcp.StreamableClientTransport{Endpoint: f.url, HTTPClient: &http.Client{Transport: bearer{tok}}, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func (f *fixture) call(t *testing.T, conn, op string) (string, bool) {
	t.Helper()
	res, err := f.cs.CallTool(context.Background(), &mcp.CallToolParams{Name: ToolName,
		Arguments: map[string]any{"connection": conn, "operation": op, "params": map[string]any{"o": "a", "r": "b"}}})
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String(), res.IsError
}

func (f *fixture) grant(t *testing.T) {
	t.Helper()
	err := f.scope.Put(scope.Principal, store.Scope{Connectors: []string{"github"}, Connections: []string{"c1"},
		Operations: map[string][]string{"github": {"GET /repos/{o}/{r}"}}})
	if err != nil {
		t.Fatal(err)
	}
}

const readOp = "GET /repos/{o}/{r}"

func TestDefaultScopeDeniesAndAudits(t *testing.T) {
	f := newFixture(t, `{}`)
	text, isErr := f.call(t, "work", readOp)
	if !isErr || !strings.Contains(text, "authorization") || f.prov.n.Load() != 0 {
		t.Fatalf("text=%q isErr=%v sent=%d", text, isErr, f.prov.n.Load())
	}
	es := f.audit.entries()
	if len(es) != 1 || es[0].Event != audit.EventScopeDenied || es[0].ConnectionID != "c1" ||
		es[0].Detail["caller"] != "agent:agent" || es[0].Detail["operation"] != readOp || es[0].Detail["reason"] == "" {
		t.Fatalf("audit: %+v", es)
	}
}

func TestLiveReadsOffByDefaultThenOnAndOffAgain(t *testing.T) {
	f := newFixture(t, `{"name":"r","secret":"s","echo":"`+secret+`"}`)
	f.grant(t)
	if text, isErr := f.call(t, "work", readOp); !isErr || f.prov.n.Load() != 0 {
		t.Fatalf("live reads off must deny: %q sent=%d", text, f.prov.n.Load())
	}
	if es := f.audit.entries(); len(es) != 1 || es[0].Detail["violated"] != "live_reads" {
		t.Fatalf("audit: %+v", es)
	}
	set := func(on bool) {
		err := f.st.UpdateConnection("c1", func(c *store.Connection) error { c.AllowAgentLiveReads = on; return nil })
		if err != nil {
			t.Fatal(err)
		}
		f.scope.Invalidate()
	}
	set(true)
	text, isErr := f.call(t, "c1", readOp)
	if isErr || f.prov.n.Load() != 1 {
		t.Fatalf("want success: %q isErr=%v sent=%d", text, isErr, f.prov.n.Load())
	}
	if strings.Contains(text, secret) || strings.Contains(text, `"secret"`) || !strings.Contains(text, `"name"`) {
		t.Fatalf("response not redacted or projected: %q", text)
	}
	set(false)
	if _, isErr := f.call(t, "work", readOp); !isErr || f.prov.n.Load() != 1 {
		t.Fatalf("disabled live reads must deny: sent=%d", f.prov.n.Load())
	}
}

func TestOutOfScopeAndUnknownConnection(t *testing.T) {
	f := newFixture(t, `{}`)
	f.grant(t)
	_ = f.st.UpdateConnection("c1", func(c *store.Connection) error { c.AllowAgentLiveReads = true; return nil })
	f.scope.Invalidate()
	for _, tc := range []struct{ conn, op string }{{"nope", readOp}, {"work", "GET /other"}, {"work", "DELETE /repos/{o}/{r}"}} {
		text, isErr := f.call(t, tc.conn, tc.op)
		if !isErr || strings.Contains(text, secret) {
			t.Fatalf("%+v: text=%q isErr=%v", tc, text, isErr)
		}
	}
	if f.prov.n.Load() != 0 {
		t.Fatalf("provider contacted: %d", f.prov.n.Load())
	}
	if es := f.audit.entries(); len(es) != 3 {
		t.Fatalf("every denial must be audited: %+v", es)
	}
}

func TestResponseCap(t *testing.T) {
	f := newFixture(t, strings.Repeat("a", MaxResponseBytes+1))
	f.grant(t)
	_ = f.st.UpdateConnection("c1", func(c *store.Connection) error { c.AllowAgentLiveReads = true; return nil })
	f.scope.Invalidate()
	text, isErr := f.call(t, "work", readOp)
	if !isErr || len(text) > MaxResponseBytes {
		t.Fatalf("len=%d isErr=%v", len(text), isErr)
	}
}

func TestAuthAndFlag(t *testing.T) {
	f := newFixture(t, `{}`)
	other, err := mcptoken.New()
	if err != nil {
		t.Fatal(err)
	}
	do := func(h string) int {
		req, _ := http.NewRequest(http.MethodPost, f.url, strings.NewReader(`{}`))
		if h != "" {
			req.Header.Set("Authorization", h)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := do(""); c != http.StatusUnauthorized {
		t.Fatalf("no token: %d", c)
	}
	if c := do(other.Header()); c != http.StatusUnauthorized { // e.g. a graph token
		t.Fatalf("foreign token: %d", c)
	}
	f.enabled.Store(false)
	if c := do(f.token.Header()); c != http.StatusNotFound {
		t.Fatalf("flag off: %d", c)
	}
}

func TestNewMCPRequiresDeps(t *testing.T) {
	if _, err := NewMCP(Config{}); err == nil {
		t.Fatal("want error")
	}
}
