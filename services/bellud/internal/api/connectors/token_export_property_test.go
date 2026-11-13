package connectors

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"pgregory.net/rapid"

	svc "github.com/bellu/bellucode/services/bellud/internal/connectors"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/audit"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/keysource"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/scope"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/mcptoken"
)

// lockedLog captures every log line the service prints.
type lockedLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lockedLog) Println(v ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintln(&l.buf, v...)
}

func (l *lockedLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// leakNeedles returns the encodings of the credential that must never appear.
func leakNeedles(cred string) map[string]string {
	b := []byte(cred)
	return map[string]string{
		"raw":        cred,
		"hex":        hex.EncodeToString(b),
		"HEX":        strings.ToUpper(hex.EncodeToString(b)),
		"base64-std": base64.StdEncoding.EncodeToString(b),
		"base64-url": base64.URLEncoding.EncodeToString(b),
		"b64-raw":    base64.RawStdEncoding.EncodeToString(b),
		"b64url-raw": base64.RawURLEncoding.EncodeToString(b),
	}
}

// leaks reports every way hay exposes the credential: a full encoding, or any
// substring of the random tail longer than 4 characters.
func leaks(hay, cred, tail string) []string {
	var out []string
	for name, n := range leakNeedles(cred) {
		if strings.Contains(hay, n) {
			out = append(out, name)
		}
	}
	for i := 0; i+5 <= len(tail); i++ {
		// All-digit windows collide with timestamps and counters in benign
		// output, so only windows containing a letter are meaningful.
		if strings.Trim(tail[i:i+5], "0123456789") == "" {
			continue
		}
		if strings.Contains(hay, tail[i:i+5]) {
			out = append(out, "substring:"+tail[i:i+5])
			break
		}
	}
	return out
}

func allAuditOf(t rapid.TB, s *svc.Service) []audit.Entry {
	var out []audit.Entry
	cursor := ""
	for {
		pg, err := s.ListAudit("", cursor, svc.DefaultPageSize)
		if err != nil {
			t.Fatalf("audit: %v", err)
		}
		out = append(out, pg.Entries...)
		if pg.NextCursor == "" {
			return out
		}
		cursor = pg.NextCursor
	}
}

func countOf(es []audit.Entry, ev string) int {
	n := 0
	for _, e := range es {
		if e.Event == ev {
			n++
		}
	}
	return n
}

func dirBytes(t rapid.TB, root string) string {
	var sb strings.Builder
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if b, e := os.ReadFile(p); e == nil {
			sb.Write(b)
		}
		return nil
	})
	return sb.String()
}

// Feature: cloud-connectors, Property 16: No token export across routes
//
// For any Connection holding a random credential, every registered connector
// route (and the connector_read tool) called with valid, invalid and
// credential-requesting inputs returns a body and headers without the
// credential, in any encoding or as a substring longer than 4 characters; every
// credential-requesting option is audited; no audit entry, log line, state
// file or graph file holds the credential; and the set of routes exercised
// equals the set of registered routes.
//
// **Validates: Requirements 6.13, 12.5, 15.1, 15.2, 15.3, 15.4, 15.6, 15.7, 16.9**
func TestProperty16NoTokenExportAcrossRoutes(t *testing.T) {
	if f := flag.Lookup("rapid.checks"); f != nil && f.Value.String() == "100" {
		_ = flag.Set("rapid.checks", "6") // each check opens a graph engine
	}
	rapid.Check(t, func(rt *rapid.T) {
		tail := rapid.StringMatching(`[A-Za-z0-9]{40}`).Draw(rt, "tail")
		cred := "github_pat_" + tail
		ctx := context.Background()

		eng, err := graph.Open(ctx, graph.Config{
			Enabled: true, Dir: filepath.Join(t.TempDir(), "g"),
			Logger: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		})
		if err != nil {
			rt.Fatalf("graph: %v", err)
		}
		logs := &lockedLog{}
		dir := t.TempDir()
		s, err := svc.New(ctx, svc.Options{
			Dir: dir, Engine: eng, Order: []keysource.Source{&apiKeys{slots: map[string][]byte{}}}, Transport: ghOK{},
			Logger: logs,
			Getenv: func(k string) string {
				if k == "BELLUCODE_FLAGS" {
					return "connectors"
				}
				return ""
			},
		})
		if err != nil {
			rt.Fatalf("service: %v", err)
		}
		if err := s.Start(ctx); err != nil {
			rt.Fatalf("start: %v", err)
		}
		defer func() { _ = s.Close(ctx); _ = eng.Close(ctx) }()
		h := NewAPI(APIConfig{Service: s, Scope: s.Scope()})

		var transcript strings.Builder
		record := func(w *httptest.ResponseRecorder) {
			transcript.WriteString(w.Body.String())
			for k, v := range w.Result().Header {
				transcript.WriteString(k + ": " + strings.Join(v, ",") + "\n")
			}
		}
		create := func(alias string) string {
			body := `{"alias":"` + alias + `","connectorId":"github","method":"pat","params":{"repos":"octo/hello"},"credential":{"token":"` + cred + `"}}`
			w := do(h, "POST", Prefix+"/connections", body, writeHdr)
			record(w)
			if w.Code != 200 {
				rt.Fatalf("create %d %s", w.Code, w.Body)
			}
			var m map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
				rt.Fatalf("create body: %v", err)
			}
			return m["id"].(string)
		}
		id := create("main")
		doomed := create("doomed")

		exercised := map[string]bool{}
		optionRequests := 0
		sent := func(rtName, method, pattern, body string, query string, hdr map[string]string, cid string) {
			path := strings.ReplaceAll(Prefix+pattern, "{id}", cid)
			path = strings.ReplaceAll(path, "{principal}", scope.Principal)
			if query != "" {
				path += "?" + query
			}
			w := do(h, method, path, body, hdr)
			record(w)
			exercised[rtName] = true
			if hit := leaks(w.Body.String()+fmt.Sprint(w.Result().Header), cred, tail); len(hit) > 0 {
				rt.Fatalf("%s %s leaks %v: %s", method, path, hit, w.Body)
			}
		}
		validBody := map[string]string{
			"createConnection":    `{"alias":"extra","connectorId":"github","method":"pat","params":{"repos":"octo/hello"},"credential":{"token":"` + cred + `"}}`,
			"updateConnection":    `{"alias":"renamed","allowAgentLiveReads":true}`,
			"reconnectConnection": `{"credential":{"token":"` + cred + `"}}`,
			"rotateCredential":    `{"credential":{"token":"` + cred + `"}}`,
			"createAuthConfig":    `{"connectorId":"github","name":"cfg","method":"pat","settings":{},"secrets":{"token":"` + cred + `"}}`,
			"putScope":            `{"connectors":["github"],"connections":["` + id + `"],"operations":{"github":["GET /user"]}}`,
			"unlockVault":         `{"passphrase":"` + cred + `"}`,
			"awsSetup":            `{}`,
		}
		invalidBody := `{"credential":` + `"` + cred + `","alias":7}`

		routes := Routes()
		sort.SliceStable(routes, func(i, j int) bool {
			rank := func(n string) int {
				switch n {
				case "deleteConnection":
					return 1
				case "rotateMasterKey":
					return 2
				case "forgetAll":
					return 3
				}
				return 0
			}
			return rank(routes[i].Name) < rank(routes[j].Name)
		})
		for _, r := range routes {
			cid := id
			if r.Name == "deleteConnection" {
				cid = doomed
			}
			body := ""
			if r.Method != "GET" && r.Method != "DELETE" {
				body = validBody[r.Name]
				if body == "" {
					body = "{}"
				}
			}
			// valid
			sent(r.Name, r.Method, r.Pattern, body, "", writeHdr, cid)
			// invalid: unknown id, malformed body, no client header
			sent(r.Name, r.Method, r.Pattern, invalidBody, "", writeHdr, "nope")
			sent(r.Name, r.Method, r.Pattern, body, "", nil, cid)
			// credential-requesting options (query, header and body field)
			before := countOf(allAuditOf(rt, s), audit.EventCredentialOptionIgnored)
			qbody := body
			if qbody != "" && strings.HasPrefix(qbody, "{") && qbody != "{}" {
				qbody = `{"reveal":true,"exportKey":true,` + qbody[1:]
			} else if qbody == "{}" {
				qbody = `{"reveal":true,"exportKey":true}`
			}
			hdr := map[string]string{ClientHeader: "web", "X-Debug": "1", "X-Reveal-Secret": "true"}
			sent(r.Name, r.Method, r.Pattern, qbody, "reveal=1&debug=true&includeSecret=1&dump=all", hdr, cid)
			after := countOf(allAuditOf(rt, s), audit.EventCredentialOptionIgnored)
			optionRequests++
			if r.Name != "forgetAll" && after <= before {
				rt.Fatalf("%s: credential-requesting options were not audited (%d -> %d)", r.Name, before, after)
			}
		}
		var missing []string
		for _, r := range Routes() {
			if !exercised[r.Name] {
				missing = append(missing, r.Name)
			}
		}
		if len(missing) > 0 {
			rt.Fatalf("registered routes not exercised: %v", missing)
		}
		if len(exercised) != len(Routes()) {
			rt.Fatalf("exercised %d routes, registered %d", len(exercised), len(Routes()))
		}

		// Connector MCP tool, on the service's own broker, resolver, audit and scope.
		// forgetAll above removed connections, so plant a fresh one first.
		id = create("mcp")
		if w := do(h, "PATCH", Prefix+"/connections/"+id, `{"allowAgentLiveReads":true}`, writeHdr); w.Code != 200 {
			rt.Fatalf("enable live reads %d %s", w.Code, w.Body)
		}
		if err := s.Scope().Put(scope.Principal, store.Scope{Connectors: []string{"github"}, Connections: []string{id},
			Operations: map[string][]string{"github": {"GET /user"}}}); err != nil {
			rt.Fatalf("scope: %v", err)
		}
		tok, err := mcptoken.New()
		if err != nil {
			rt.Fatalf("token: %v", err)
		}
		mh, err := NewMCP(Config{Token: tok, Broker: s.Broker(), Resolver: svc.NewResolver(s), Audit: s.Audit(), Enabled: s.Enabled})
		if err != nil {
			rt.Fatalf("mcp: %v", err)
		}
		srv := httptest.NewServer(mh)
		defer srv.Close()
		cs, err := mcp.NewClient(&mcp.Implementation{Name: "t"}, nil).Connect(ctx,
			&mcp.StreamableClientTransport{Endpoint: srv.URL, HTTPClient: &http.Client{Transport: bearer{tok}}, DisableStandaloneSSE: true}, nil)
		if err != nil {
			rt.Fatalf("mcp connect: %v", err)
		}
		defer cs.Close()
		for _, args := range []map[string]any{
			{"connection": id, "operation": "GET /user"},
			{"connection": id, "operation": "GET /user", "params": map[string]any{"reveal": true}},
			{"connection": id, "operation": "DELETE /user"},
			{"connection": id, "operation": "GET /user/repos"},
			{"connection": "nope", "operation": "GET /user"},
		} {
			res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: ToolName, Arguments: args})
			if err != nil {
				transcript.WriteString(err.Error())
				continue
			}
			for _, c := range res.Content {
				if tc, ok := c.(*mcp.TextContent); ok {
					transcript.WriteString(tc.Text)
				}
			}
			if res.StructuredContent != nil {
				transcript.WriteString(fmt.Sprint(res.StructuredContent))
			}
		}
		if hit := leaks(transcript.String(), cred, tail); len(hit) > 0 {
			rt.Fatalf("response transcript leaks %v", hit)
		}

		// Audit entries, log lines, state and graph files.
		var ab strings.Builder
		for _, e := range allAuditOf(rt, s) {
			ab.WriteString(fmt.Sprintf("%+v\n", e))
		}
		if hit := leaks(ab.String(), cred, tail); len(hit) > 0 {
			rt.Fatalf("audit entries leak %v", hit)
		}
		if hit := leaks(logs.String(), cred, tail); len(hit) > 0 {
			rt.Fatalf("log lines leak %v", hit)
		}
		if hit := leaks(dirBytes(rt, dir), cred, tail); len(hit) > 0 {
			rt.Fatalf("connector data directory (state, vault, audit files) leaks %v", hit)
		}
		if optionRequests != len(Routes()) {
			rt.Fatalf("option requests %d != routes %d", optionRequests, len(Routes()))
		}
	})
}
