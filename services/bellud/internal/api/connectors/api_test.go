package connectors

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	svc "github.com/bellu/bellucode/services/bellud/internal/connectors"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/keysource"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
)

type apiKeys struct {
	mu    sync.Mutex
	slots map[string][]byte
}

func (m *apiKeys) Name() string                   { return "mem" }
func (m *apiKeys) Available(context.Context) bool { return true }
func (m *apiKeys) Load(ctx context.Context) ([]byte, error) {
	return m.LoadSlot(ctx, keysource.SlotCurrent)
}
func (m *apiKeys) LoadSlot(_ context.Context, slot string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.slots[slot]
	if !ok {
		return nil, keysource.ErrNoKey
	}
	return append([]byte(nil), k...), nil
}
func (m *apiKeys) Store(_ context.Context, key []byte, slot string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.slots[slot] = append([]byte(nil), key...)
	return nil
}
func (m *apiKeys) Promote(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.slots[keysource.SlotCurrent] = m.slots[keysource.SlotNext]
	delete(m.slots, keysource.SlotNext)
	return nil
}

type ghOK struct{}

func (ghOK) RoundTrip(r *http.Request) (*http.Response, error) {
	body := `[]`
	if r.URL.Path == "/user" {
		body = `{"login":"octo"}`
	}
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
}

func newService(t *testing.T, flags string) *svc.Service {
	t.Helper()
	ctx := context.Background()
	eng, err := graph.Open(ctx, graph.Config{
		Enabled: true, Dir: filepath.Join(t.TempDir(), "g"),
		Logger: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { eng.Close(ctx) })
	s, err := svc.New(ctx, svc.Options{
		Dir: t.TempDir(), Engine: eng, Order: []keysource.Source{&apiKeys{slots: map[string][]byte{}}}, Transport: ghOK{},
		Getenv: func(k string) string {
			if k == "BELLUCODE_FLAGS" {
				return flags
			}
			return ""
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close(ctx) })
	return s
}

const apiToken = "github_pat_" + "abcdefghijklmnopqrstuvwxyz0123456789"

func do(h http.Handler, method, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:5555"
	r.Host = "localhost:4096"
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

var writeHdr = map[string]string{ClientHeader: "web"}

func createBody(extra string) string {
	return `{"alias":"main","connectorId":"github","method":"pat","params":{"repos":"octo/hello"},"credential":{"token":"` + apiToken + `"}` + extra + `}`
}

func decode(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("body %q: %v", w.Body.String(), err)
	}
	return m
}

func TestCRUDAndMasking(t *testing.T) {
	s := newService(t, "connectors")
	h := NewAPI(APIConfig{Service: s})
	if w := do(h, "GET", Prefix+"/status", "", nil); w.Code != 200 || decode(t, w)["enabled"] != true {
		t.Fatalf("status %d %s", w.Code, w.Body)
	}
	if w := do(h, "GET", Prefix+"/catalog", "", nil); w.Code != 200 || len(decode(t, w)["items"].([]any)) != 8 {
		t.Fatalf("catalog %d %s", w.Code, w.Body)
	}
	w := do(h, "POST", Prefix+"/connections", createBody(""), writeHdr)
	if w.Code != 200 {
		t.Fatalf("create %d %s", w.Code, w.Body)
	}
	conn := decode(t, w)
	id := conn["id"].(string)
	if conn["status"] != "ACTIVE" || conn["accountLabel"] != "octo" {
		t.Fatalf("conn %v", conn)
	}
	if w := do(h, "GET", Prefix+"/connections", "", nil); len(decode(t, w)["items"].([]any)) != 1 {
		t.Fatalf("list %s", w.Body)
	}
	w = do(h, "PATCH", Prefix+"/connections/"+id, `{"alias":"renamed","intervalSec":120,"allowAgentLiveReads":true}`, writeHdr)
	if w.Code != 200 || decode(t, w)["alias"] != "renamed" {
		t.Fatalf("update %d %s", w.Code, w.Body)
	}
	for _, p := range []string{"/connections", "/connections/" + id} {
		if b := do(h, "GET", Prefix+p, "", nil).Body.String(); strings.Contains(b, "abcdefgh") {
			t.Fatalf("token leaked in %s", b)
		}
	}
	if w := do(h, "DELETE", Prefix+"/connections/"+id, "", writeHdr); w.Code != 200 {
		t.Fatalf("delete %d %s", w.Code, w.Body)
	}
	if w := do(h, "GET", Prefix+"/connections/"+id, "", nil); w.Code != 404 {
		t.Fatalf("get after delete %d", w.Code)
	}
	if w := do(h, "PATCH", Prefix+"/connections/nope", `{}`, writeHdr); w.Code != 404 {
		t.Fatalf("patch unknown %d", w.Code)
	}
}

func TestDisabledAnswers404(t *testing.T) {
	s := newService(t, "-connectors")
	h := NewAPI(APIConfig{Service: s})
	for _, rt := range Routes() {
		path := strings.ReplaceAll(Prefix+rt.Pattern, "{id}", "x")
		if w := do(h, rt.Method, path, "{}", writeHdr); w.Code != 404 {
			t.Fatalf("%s: %d", rt.Name, w.Code)
		}
	}
}

func TestEveryRouteHasHandler(t *testing.T) {
	// NewAPI panics on a route without a handler.
	NewAPI(APIConfig{Service: newService(t, "connectors")})
}

func auditEvents(t *testing.T, s *svc.Service, event string) int {
	t.Helper()
	pg, err := s.ListAudit("", "", 50)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range pg.Entries {
		if e.Event == event {
			n++
			for _, v := range e.Detail {
				if strings.Contains(v, "abcdefgh") {
					t.Fatalf("audit leaks token: %v", e)
				}
			}
		}
	}
	return n
}

func TestCredentialWriteGuards(t *testing.T) {
	s := newService(t, "connectors")
	role := "user"
	h := NewAPI(APIConfig{Service: s, Role: func(*http.Request) string { return role }})
	post := func(mut func(*http.Request)) int {
		r := httptest.NewRequest("POST", Prefix+"/connections", strings.NewReader(createBody("")))
		r.RemoteAddr, r.Host = "127.0.0.1:1", "localhost:4096"
		r.Header.Set(ClientHeader, "web")
		mut(r)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code == 403 && decode(t, w)["code"] != "forbidden" {
			t.Fatalf("body %s", w.Body)
		}
		return w.Code
	}
	cases := map[string]func(*http.Request){
		"not local":     func(r *http.Request) { r.RemoteAddr = "192.168.1.5:4000" },
		"bad host":      func(r *http.Request) { r.Host = "evil.example:4096" },
		"no client":     func(r *http.Request) { r.Header.Del(ClientHeader) },
		"cross site":    func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") },
		"no remoteaddr": func(r *http.Request) { r.RemoteAddr = "" },
	}
	for name, mut := range cases {
		if c := post(mut); c != 403 {
			t.Fatalf("%s: %d", name, c)
		}
	}
	role = "agent"
	if c := post(func(*http.Request) {}); c != 403 {
		t.Fatalf("agent role: %d", c)
	}
	role = ""
	if c := post(func(*http.Request) {}); c != 403 {
		t.Fatalf("unauthenticated: %d", c)
	}
	if len(s.Connections()) != 0 {
		t.Fatal("rejected write stored a connection")
	}
	if n := auditEvents(t, s, "blocked_operation"); n != 7 {
		t.Fatalf("rejection audits = %d", n)
	}
	role = "user"
	if c := post(func(r *http.Request) { r.Host = "[::1]:4096" }); c != 200 {
		t.Fatalf("ipv6 loopback host: %d", c)
	}
}

func TestBodyLimitAndValidation(t *testing.T) {
	s := newService(t, "connectors")
	h := NewAPI(APIConfig{Service: s})
	big := `{"alias":"` + strings.Repeat("a", 1<<20) + `"}`
	if w := do(h, "POST", Prefix+"/connections", big, writeHdr); w.Code != 413 || decode(t, w)["code"] != "payload_too_large" {
		t.Fatalf("big %d %s", w.Code, w.Body)
	}
	// Chunked body (unknown length) is limited too.
	r := httptest.NewRequest("POST", Prefix+"/connections", io.NopCloser(strings.NewReader(big)))
	r.ContentLength = -1
	r.RemoteAddr, r.Host = "127.0.0.1:1", "localhost"
	r.Header.Set(ClientHeader, "web")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 413 {
		t.Fatalf("chunked %d", w.Code)
	}
	const planted = "PLANTEDVALUE-9f8e7d6c"
	bad := `{"alias":"","connectorId":7,"method":"pat","credential":{"token":5,"` + planted + `":"x"},"intervalSec":"` + planted + `"}`
	w = do(h, "POST", Prefix+"/connections", bad, writeHdr)
	if w.Code != 400 || strings.Contains(w.Body.String(), planted) {
		t.Fatalf("validation %d %s", w.Code, w.Body)
	}
	m := decode(t, w)
	if m["_tag"] != "ConnectorError" || m["code"] != "validation_failed" {
		t.Fatalf("%v", m)
	}
	got := map[string]bool{}
	for _, o := range m["offenders"].([]any) {
		got[o.(string)] = true
	}
	for _, f := range []string{"alias", "connectorId", "credential", "intervalSec"} {
		if !got[f] {
			t.Fatalf("offender %s missing: %v", f, m)
		}
	}
	for _, body := range []string{`not json`, `[]`, `null`, `{"alias":"a"} {}`, ``} {
		if w := do(h, "POST", Prefix+"/connections", body, writeHdr); w.Code != 400 {
			t.Fatalf("%q: %d", body, w.Code)
		}
	}
	for _, body := range []string{`{"intervalSec":59}`, `{"intervalSec":1.5}`, `{"rotationIntervalDays":0}`, `{"alias":"` + strings.Repeat("a", 41) + `"}`, `{"selection":{"regions":"us-east-1"}}`, `{"allowAgentLiveReads":"yes"}`} {
		if w := do(h, "PATCH", Prefix+"/connections/x", body, writeHdr); w.Code != 400 {
			t.Fatalf("%s: %d", body, w.Code)
		}
	}
	if len(s.Connections()) != 0 {
		t.Fatal("invalid request changed state")
	}
}

func TestCredentialOptionsIgnoredAndAudited(t *testing.T) {
	s := newService(t, "connectors")
	h := NewAPI(APIConfig{Service: s})
	w := do(h, "POST", Prefix+"/connections", createBody(`,"debug":true,"reveal_token":1`), writeHdr)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	id := decode(t, w)["id"].(string)
	// The first sync runs in the background and moves lastSync; compare the
	// rest of the representation.
	stable := func(b string) string {
		var m map[string]any
		_ = json.Unmarshal([]byte(b), &m)
		delete(m, "lastSync")
		out, _ := json.Marshal(m)
		return string(out)
	}
	base := stable(do(h, "GET", Prefix+"/connections/"+id, "", nil).Body.String())
	for _, c := range []struct {
		path string
		hdr  map[string]string
	}{
		{"?debug=1", nil}, {"?includeCredential=true", nil}, {"?secret=1", nil},
		{"", map[string]string{"X-Reveal-Credential": "1"}}, {"", map[string]string{"X-Debug": "1"}},
	} {
		got := do(h, "GET", Prefix+"/connections/"+id+c.path, "", c.hdr)
		if stable(got.Body.String()) != base {
			t.Fatalf("%v changed the response: %s", c, got.Body)
		}
	}
	// 2 body options + 5 read options.
	if n := auditEvents(t, s, "credential_option_ignored"); n != 7 {
		t.Fatalf("option audits = %d", n)
	}
	pg, _ := s.ListAudit(id, "", 50)
	found := false
	for _, e := range pg.Entries {
		if e.Event == "credential_option_ignored" && e.ConnectionID == id && e.Detail["role"] == "user" && !e.TS.IsZero() {
			found = true
		}
	}
	if !found {
		t.Fatal("no audit entry with connection, role and timestamp")
	}
}

func TestErrorMapping(t *testing.T) {
	s := newService(t, "connectors")
	h := NewAPI(APIConfig{Service: s})
	w := do(h, "POST", Prefix+"/connections", `{"alias":"a","connectorId":"nope","method":"pat","credential":{"token":"x"}}`, writeHdr)
	m := decode(t, w)
	if w.Code != 400 || m["_tag"] != "ConnectorError" || m["code"] != "validation_failed" {
		t.Fatalf("%d %v", w.Code, m)
	}
	do(h, "POST", Prefix+"/connections", createBody(""), writeHdr)
	w = do(h, "POST", Prefix+"/connections", createBody(""), writeHdr)
	if m := decode(t, w); w.Code != 400 || m["code"] != "alias_taken" {
		t.Fatalf("dup alias %d %v", w.Code, m)
	}
}

func TestHostMatching(t *testing.T) {
	for host, want := range map[string]bool{
		"localhost": true, "LOCALHOST:80": true, "127.0.0.1:1": true, "[::1]:9": true, "::1": true,
		"example.com": false, "localhost.evil.com": false, "127.0.0.1.evil.com:80": false, "": false, "my.box": true,
	} {
		if got := hostAllowed(host, []string{"my.box"}); got != want {
			t.Errorf("%q: %v", host, got)
		}
	}
}

func TestOptionNames(t *testing.T) {
	for n, want := range map[string]bool{
		"debug": true, "X-Debug": true, "show_credential": true, "includeSecret": true, "reveal": true,
		"export": true, "secret": true, "cursor": false, "alias": false, "auth_token": false, "Authorization": false,
		"X-Bellucode-Client": false, "intervalSec": false, "Content-Type": false,
	} {
		if got := isCredentialOption(n, true); got != want {
			t.Errorf("%q: %v", n, got)
		}
	}
	if isCredentialOption("credential", false) {
		t.Error("own body field flagged")
	}
}
