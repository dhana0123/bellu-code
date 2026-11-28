package seek_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bellu/bellucode/services/bellud/internal/seek"
	"github.com/bellu/bellucode/services/bellud/internal/seek/bskg"
	"github.com/bellu/bellucode/services/bellud/internal/seek/seektest"
)

const (
	toolName = "seek_retrieve"
	testKey  = "bskg-test-key-0123456789"
)

// Stand-ins for the other bellu-graph tools. The facade registers its tools
// before MCPExtras runs; what matters here is that their names and schemas do
// not change when seek is registered next to them. (internal/lens cannot be
// imported in every checkout, so real typed tools are registered directly.)
var otherTools = []string{"find_entities", "slice", "blast_radius"}

type otherIn struct {
	Query string `json:"query" jsonschema:"what to look up"`
	Limit int    `json:"limit,omitempty" jsonschema:"maximum items"`
}

type otherOut struct {
	Items []string `json:"items"`
}

func registerOthers(srv *mcp.Server) {
	for _, name := range otherTools {
		mcp.AddTool(srv, &mcp.Tool{
			Name:        name,
			Description: name + " tool",
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
		}, func(context.Context, *mcp.CallToolRequest, otherIn) (*mcp.CallToolResult, otherOut, error) {
			return nil, otherOut{Items: []string{}}, nil
		})
	}
}

func retrieverConfig() seek.Config {
	return seek.Config{
		RequestTimeout: 2 * time.Second,
		TotalTimeout:   5 * time.Second,
		MinRelevance:   seek.DefaultMinRelevance,
		PerCWEFetch:    seek.MaxScope,
		MaxDetailFetch: 120,
		Concurrency:    8,
	}
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// connect serves the bellu-graph tools the way the facade does (other tools,
// then seek extras when bskg.Load says seek is configured) and returns a
// client session over an in-memory transport.
func connect(t *testing.T, env map[string]string, seekCfg bskgBuilder) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	srv := mcp.NewServer(&mcp.Implementation{Name: "bellu-graph"}, nil)
	registerOthers(srv)
	if seekCfg != nil {
		// An invalid pair returns ok=false with an error; the facade logs it and
		// serves no seek tool, so the error is not fatal here.
		cfg, on, _ := bskg.Load(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
		if on {
			seek.Extras(seekCfg(t, cfg))(srv)
		}
	}
	ct, st := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	sess, err := mcp.NewClient(&mcp.Implementation{Name: "c"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return sess
}

type bskgBuilder func(*testing.T, bskg.Config) *seek.Retriever

// liveRetriever builds a Retriever on a real bskg client.
func liveRetriever(t *testing.T, cfg bskg.Config) *seek.Retriever {
	t.Helper()
	cfg.Timeout = 2 * time.Second
	client, err := bskg.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return seek.NewRetriever(client, retrieverConfig(), quietLogger())
}

func envFor(url, key string) map[string]string {
	return map[string]string{
		"BELLUCODE_SEEK_BSKG_URL": url,
		"BELLUCODE_SEEK_BSKG_KEY": key,
	}
}

func listTools(t *testing.T, sess *mcp.ClientSession) map[string]*mcp.Tool {
	t.Helper()
	res, err := sess.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*mcp.Tool{}
	for _, tl := range res.Tools {
		out[tl.Name] = tl
	}
	return out
}

func call(t *testing.T, sess *mcp.ClientSession, args map[string]any) (*mcp.CallToolResult, seek.Result) {
	t.Helper()
	res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{Name: toolName, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool returned a protocol error: %v", err)
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var out seek.Result
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("structuredContent %s: %v", raw, err)
	}
	return res, out
}

func validPlan() map[string]any {
	return map[string]any{
		"language":  "javascript",
		"reasoning": "user input reaches innerHTML",
		"weaknesses": []any{map[string]any{
			"cwe_id":       "CWE-79",
			"root_cause":   "request parameter is written to the page without encoding",
			"code_snippet": "el.innerHTML = req.query.name",
		}},
	}
}

func hasIssue(r seek.Result, path string) bool {
	for _, is := range r.Issues {
		if is.Path == path && is.Reason != "" {
			return true
		}
	}
	return false
}

// Requirements 4.1, 4.7, 11.6: seek_retrieve is listed read-only when the URL
// and key are valid.
func TestSeekRetrieveListedReadOnlyWhenConfigured(t *testing.T) {
	fake := seektest.New(t)
	sess := connect(t, envFor(fake.URL, testKey), liveRetriever)

	tl, ok := listTools(t, sess)[toolName]
	if !ok {
		t.Fatalf("%s not listed", toolName)
	}
	if tl.Annotations == nil || !tl.Annotations.ReadOnlyHint {
		t.Fatalf("annotations = %+v, want ReadOnlyHint true", tl.Annotations)
	}
	// Requirement 4.2: plan is required and nothing but plan and top_k is advertised.
	raw, err := json.Marshal(tl.InputSchema)
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Required   []string       `json:"required"`
		Properties map[string]any `json:"properties"`
		Additional *bool          `json:"additionalProperties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(schema.Required, []string{"plan"}) {
		t.Fatalf("required = %v", schema.Required)
	}
	if _, ok := schema.Properties["plan"]; !ok || len(schema.Properties) != 2 {
		t.Fatalf("properties = %v, want plan and top_k", schema.Properties)
	}
	if _, ok := schema.Properties["top_k"]; !ok {
		t.Fatalf("properties = %v, want top_k", schema.Properties)
	}
	if schema.Additional == nil || *schema.Additional {
		t.Fatalf("additionalProperties = %v, want false", schema.Additional)
	}
}

// Requirements 4.7, 11.6: with a missing or invalid URL or key the tool is
// absent and every other tool is exactly as in a server that never heard of seek.
func TestSeekRetrieveAbsentWhenUnconfigured(t *testing.T) {
	baseline := listTools(t, connect(t, nil, nil))
	if _, ok := baseline[toolName]; ok {
		t.Fatalf("baseline server lists %s", toolName)
	}
	for _, name := range otherTools {
		if _, ok := baseline[name]; !ok {
			t.Fatalf("baseline is missing %s", name)
		}
	}
	cases := map[string]map[string]string{
		"nothing set":    {},
		"missing key":    {"BELLUCODE_SEEK_BSKG_URL": "https://bskg.example.com"},
		"missing url":    {"BELLUCODE_SEEK_BSKG_KEY": testKey},
		"empty key":      envFor("https://bskg.example.com", "  "),
		"invalid url":    envFor("not a url", testKey),
		"url userinfo":   envFor("https://user:pw@bskg.example.com", testKey),
		"plain http":     envFor("http://bskg.example.com", testKey),
		"url with query": envFor("https://bskg.example.com/?x=1", testKey),
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			got := listTools(t, connect(t, env, liveRetriever))
			if _, ok := got[toolName]; ok {
				t.Fatalf("%s listed", toolName)
			}
			if !reflect.DeepEqual(got, baseline) {
				t.Fatalf("tool list differs from the baseline without seek")
			}
		})
	}
}

// Requirement 11.6: adding seek leaves the other tools' names and schemas alone.
func TestOtherToolsUnchangedWhenSeekPresent(t *testing.T) {
	fake := seektest.New(t)
	baseline := listTools(t, connect(t, nil, nil))
	with := listTools(t, connect(t, envFor(fake.URL, testKey), liveRetriever))
	if _, ok := with[toolName]; !ok {
		t.Fatalf("%s not listed", toolName)
	}
	delete(with, toolName)
	if !reflect.DeepEqual(with, baseline) {
		t.Fatalf("other tools changed when seek was registered")
	}
}

// Requirements 4.3, 4.1: a valid call returns structuredContent and the same
// result as text content.
func TestSeekRetrieveValidCall(t *testing.T) {
	fake := seektest.New(t)
	sess := connect(t, envFor(fake.URL, testKey), liveRetriever)

	res, out := call(t, sess, map[string]any{"plan": validPlan(), "top_k": 2})
	if res.IsError {
		t.Fatalf("isError = true: %+v", res)
	}
	if out.Status != "ok" || out.TopK != 2 {
		t.Fatalf("status = %q top_k = %d, want ok and 2", out.Status, out.TopK)
	}
	if len(out.Units) != 1 || out.Units[0].CWEID != "CWE-79" {
		t.Fatalf("units = %+v", out.Units)
	}
	if len(res.Content) != 1 {
		t.Fatalf("content = %+v, want one text block", res.Content)
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content[0] is %T, want *mcp.TextContent", res.Content[0])
	}
	var fromText, fromStructured any
	if err := json.Unmarshal([]byte(text.Text), &fromText); err != nil {
		t.Fatalf("text content is not JSON: %v", err)
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &fromStructured); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fromText, fromStructured) {
		t.Fatalf("text content and structuredContent differ:\n%s\n%s", text.Text, raw)
	}
	if strings.Contains(text.Text, testKey) {
		t.Fatal("result contains the BSKG key")
	}
	for _, r := range fake.Requests() {
		if r.Method != "GET" {
			t.Fatalf("non-read request %s %s", r.Method, r.Path)
		}
	}
}

// Requirement 4.3 (default top_k) and the empty plan case of 4.4: no BSKG call.
func TestSeekRetrieveDefaultTopKAndEmptyPlan(t *testing.T) {
	fake := seektest.New(t)
	sess := connect(t, envFor(fake.URL, testKey), liveRetriever)

	res, out := call(t, sess, map[string]any{"plan": map[string]any{
		"language": "go", "reasoning": "nothing found", "weaknesses": []any{},
	}})
	if res.IsError || out.Status != "ok" || out.TopK != seek.DefaultTopK || len(out.Units) != 0 {
		t.Fatalf("isError = %v result = %+v", res.IsError, out)
	}
	if n := len(fake.Requests()); n != 0 {
		t.Fatalf("%d BSKG requests for an empty plan", n)
	}
}

// Requirements 4.5, 10.1: invalid input is an error result with path-bearing
// issues, not a protocol error, and makes no BSKG call.
func TestSeekRetrieveInvalidInput(t *testing.T) {
	longRoot := validPlan()
	longRoot["weaknesses"].([]any)[0].(map[string]any)["root_cause"] = strings.Repeat("x", seek.MaxRootCause+1)
	noWeaknesses := validPlan()
	delete(noWeaknesses, "weaknesses")

	tests := []struct {
		name string
		args map[string]any
		path string
	}{
		{"missing plan", map[string]any{}, "plan"},
		{"plan is not an object", map[string]any{"plan": "CWE-79"}, "plan"},
		{"missing weaknesses", map[string]any{"plan": noWeaknesses}, "weaknesses"},
		{"root_cause too long", map[string]any{"plan": longRoot}, "weaknesses[0].root_cause"},
		{"top_k too large", map[string]any{"plan": validPlan(), "top_k": 11}, "top_k"},
		{"top_k zero", map[string]any{"plan": validPlan(), "top_k": 0}, "top_k"},
		{"top_k not an integer", map[string]any{"plan": validPlan(), "top_k": 2.5}, "top_k"},
		{"top_k wrong type", map[string]any{"plan": validPlan(), "top_k": "4"}, "top_k"},
		{"unknown top-level argument", map[string]any{"plan": validPlan(), "cwe": "CWE-89"}, "cwe"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := seektest.New(t)
			sess := connect(t, envFor(fake.URL, testKey), liveRetriever)
			res, out := call(t, sess, tt.args)
			if !res.IsError {
				t.Fatalf("isError = false, result = %+v", out)
			}
			if out.Status != "invalid_plan" {
				t.Fatalf("status = %q, want invalid_plan", out.Status)
			}
			if !hasIssue(out, tt.path) {
				t.Fatalf("issues = %+v, want one at %q", out.Issues, tt.path)
			}
			if len(out.Units) != 0 {
				t.Fatalf("units = %+v, want none", out.Units)
			}
			if n := len(fake.Requests()); n != 0 {
				t.Fatalf("%d BSKG requests for invalid input", n)
			}
		})
	}
}

// Requirements 10.1, 4.1: an unreachable BSKG is a normal result, not an error,
// with a failure category, no candidates and no key.
func TestSeekRetrieveCVEUnavailableIsNotAnError(t *testing.T) {
	fake := seektest.New(t)
	sess := connect(t, envFor(fake.URL, testKey), liveRetriever)
	fake.Close() // every request now fails to connect

	res, out := call(t, sess, map[string]any{"plan": validPlan()})
	if res.IsError {
		t.Fatalf("isError = true for cve_unavailable: %+v", res)
	}
	if out.Status != "cve_unavailable" {
		t.Fatalf("status = %q, want cve_unavailable", out.Status)
	}
	if out.Error == nil || out.Error.Category == "" {
		t.Fatalf("error = %+v, want a category", out.Error)
	}
	for _, u := range out.Units {
		if len(u.Candidates) != 0 {
			t.Fatalf("unit %s has candidates", u.CWEID)
		}
	}
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), testKey) || strings.Contains(string(raw), fake.URL) {
		t.Fatalf("result leaks the key or the BSKG URL: %s", raw)
	}
}

// Requirement 10.1: a retriever without a source answers cve_unavailable with
// category unconfigured instead of failing.
func TestSeekRetrieveWithoutSourceIsUnconfigured(t *testing.T) {
	srv := mcp.NewServer(&mcp.Implementation{Name: "bellu-graph"}, nil)
	seek.Register(srv, seek.NewRetriever(nil, retrieverConfig(), quietLogger()))
	ct, st := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(context.Background(), st, nil); err != nil {
		t.Fatal(err)
	}
	sess, err := mcp.NewClient(&mcp.Implementation{Name: "c"}, nil).Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	res, out := call(t, sess, map[string]any{"plan": validPlan()})
	if res.IsError || out.Status != "cve_unavailable" || out.Error == nil || out.Error.Category != "unconfigured" {
		t.Fatalf("isError = %v result = %+v", res.IsError, out)
	}
}
