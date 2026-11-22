package bskg_test

// Tests for the BSKG client (tasks 5.2, requirements 9.1-9.6, 9.8, 12.2, 12.4).
// They are written before the client exists and stay red until task 5.3.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/seek/bskg"
	"github.com/bellu/bellucode/services/bellud/internal/seek/seektest"
)

const testKey = "bskg-key-7f3a9c1e-SECRET"

func newClient(t *testing.T, srv *seektest.Server, timeout time.Duration) *bskg.Client {
	t.Helper()
	c, err := bskg.New(bskg.Config{BaseURL: srv.URL, Key: bskg.Secret(testKey), Timeout: timeout})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// assertClean fails when an error string exposes the key, a URL or a body.
func assertClean(t *testing.T, err error, srv *seektest.Server) {
	t.Helper()
	if err == nil {
		return
	}
	msg := err.Error()
	for _, bad := range []string{testKey, srv.URL, srv.Listener.Addr().String(), "/v1/", "fake bskg", "http://", "https://"} {
		if strings.Contains(msg, bad) {
			t.Errorf("error %q contains %q", msg, bad)
		}
	}
}

// calls runs every client method with a valid id.
func calls(c *bskg.Client) map[string]func(context.Context) error {
	return map[string]func(context.Context) error{
		"Weakness":      func(ctx context.Context) error { _, err := c.Weakness(ctx, "CWE-79"); return err },
		"Children":      func(ctx context.Context) error { _, err := c.Children(ctx, "CWE-79", 1); return err },
		"WeaknessVulns": func(ctx context.Context) error { _, err := c.WeaknessVulns(ctx, "CWE-79", 50); return err },
		"Vulnerability": func(ctx context.Context) error { _, err := c.Vulnerability(ctx, "CVE-2021-0001"); return err },
		"Status":        func(ctx context.Context) error { return c.Status(ctx) },
	}
}

func TestContractFixturesDecode(t *testing.T) {
	srv := seektest.New(t)
	c := newClient(t, srv, 5*time.Second)
	ctx := context.Background()

	w, err := c.Weakness(ctx, "CWE-79")
	if err != nil {
		t.Fatalf("Weakness: %v", err)
	}
	if w.CWEID != "CWE-79" || !strings.HasPrefix(w.Name, "Improper Neutralization of Input During Web Page") {
		t.Errorf("Weakness = %+v", w)
	}

	edges, err := c.Children(ctx, "CWE-79", 1)
	if err != nil {
		t.Fatalf("Children d1: %v", err)
	}
	if len(edges) != 1 || edges[0].Child != "CWE-80" || edges[0].Parent != "CWE-79" {
		t.Errorf("Children d1 = %+v, want CWE-80 child of CWE-79", edges)
	}
	edges, err = c.Children(ctx, "CWE-79", 2)
	if err != nil {
		t.Fatalf("Children d2: %v", err)
	}
	if len(edges) != 2 || edges[1].Child != "CWE-81" || edges[1].Parent != "CWE-80" {
		t.Errorf("Children d2 = %+v", edges)
	}

	refs, err := c.WeaknessVulns(ctx, "CWE-79", 50)
	if err != nil {
		t.Fatalf("WeaknessVulns: %v", err)
	}
	if len(refs) != 2 || refs[0].CVEID != "CVE-2021-0001" || refs[1].CVEID != "CVE-2021-0002" {
		t.Fatalf("WeaknessVulns = %+v", refs)
	}
	if refs[0].CVSS == nil || *refs[0].CVSS != 6.1 || refs[1].CVSS == nil || *refs[1].CVSS != 9.8 {
		t.Errorf("WeaknessVulns CVSS = %+v", refs)
	}

	v, err := c.Vulnerability(ctx, "CVE-2021-0001")
	if err != nil {
		t.Fatalf("Vulnerability: %v", err)
	}
	if v.CVEID != "CVE-2021-0001" || v.KEV || v.CVSS == nil || *v.CVSS != 6.1 || v.EPSS == nil || *v.EPSS != 0.02 ||
		!strings.HasPrefix(v.Description, "Cross-site scripting") || v.FixCommit != "" || v.Repository != "" {
		t.Errorf("Vulnerability 0001 = %+v", v)
	}
	v, err = c.Vulnerability(ctx, "CVE-2021-0002")
	if err != nil {
		t.Fatalf("Vulnerability 0002: %v", err)
	}
	if !v.KEV || v.FixCommit != "0123456789abcdef0123456789abcdef01234567" || v.Repository != "https://github.com/acme/widget" {
		t.Errorf("Vulnerability 0002 = %+v", v)
	}
	v, err = c.Vulnerability(ctx, "CVE-2020-0004")
	if err != nil {
		t.Fatalf("Vulnerability 0004: %v", err)
	}
	if v.CVSS != nil || v.EPSS != nil {
		t.Errorf("absent scores must be nil: %+v", v)
	}

	if err := c.Status(ctx); err != nil {
		t.Fatalf("Status: %v", err)
	}

	// Every other fixture decodes too.
	for _, id := range []string{"CWE-80", "CWE-81", "CWE-89"} {
		if _, err := c.Weakness(ctx, id); err != nil {
			t.Errorf("Weakness %s: %v", id, err)
		}
		if _, err := c.WeaknessVulns(ctx, id, 50); err != nil {
			t.Errorf("WeaknessVulns %s: %v", id, err)
		}
	}
	if _, err := c.Children(ctx, "CWE-89", 2); err != nil {
		t.Errorf("Children CWE-89: %v", err)
	}
	if _, err := c.Vulnerability(ctx, "CVE-2022-0003"); err != nil {
		t.Errorf("Vulnerability 2022-0003: %v", err)
	}

	allowed := func(p string) bool {
		segs := strings.Split(strings.TrimPrefix(p, "/"), "/")
		switch {
		case p == "/v1/status", p == "/v1/graph/neighborhood":
			return true
		case len(segs) == 3 && segs[0] == "v1" && (segs[1] == "weaknesses" || segs[1] == "vulnerabilities"):
			return true
		case len(segs) == 4 && segs[0] == "v1" && segs[1] == "weaknesses" && segs[3] == "vulnerabilities":
			return true
		}
		return false
	}
	reqs := srv.Requests()
	if len(reqs) == 0 {
		t.Fatal("no requests recorded")
	}
	for _, r := range reqs {
		if r.Method != http.MethodGet {
			t.Errorf("method %s on %s", r.Method, r.Path)
		}
		if !allowed(r.Path) {
			t.Errorf("disallowed path %q", r.Path)
		}
		if r.Path != "/v1/graph/neighborhood" && r.RawQuery != "" && !strings.HasSuffix(r.Path, "/vulnerabilities") {
			t.Errorf("unexpected query %q on %s", r.RawQuery, r.Path)
		}
		if r.Body != "" {
			t.Errorf("request body on %s", r.Path)
		}
	}
}

func TestChildrenUsesChildOfNeighborhood(t *testing.T) {
	srv := seektest.New(t)
	c := newClient(t, srv, 5*time.Second)
	if _, err := c.Children(context.Background(), "CWE-79", 2); err != nil {
		t.Fatal(err)
	}
	r := srv.Requests()[0]
	if r.Path != "/v1/graph/neighborhood" {
		t.Fatalf("path = %q", r.Path)
	}
	for _, want := range []string{"type=Weakness", "id=CWE-79", "depth=2", "relTypes=CHILD_OF"} {
		if !strings.Contains(r.RawQuery, want) {
			t.Errorf("query %q lacks %s", r.RawQuery, want)
		}
	}
}

func TestKeySentOnlyAsBearerToConfiguredHost(t *testing.T) {
	srv := seektest.New(t)
	c := newClient(t, srv, 5*time.Second)
	for name, call := range calls(c) {
		if err := call(context.Background()); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	reqs := srv.Requests()
	if len(reqs) != 5 {
		t.Fatalf("requests = %d, want 5", len(reqs))
	}
	for _, r := range reqs {
		if got := r.Header.Get("Authorization"); got != "Bearer "+testKey {
			t.Errorf("%s Authorization = %q", r.Path, got)
		}
		if strings.Contains(r.Path+r.RawPath+r.RawQuery+r.Body, testKey) {
			t.Errorf("%s: key in path, query or body", r.Path)
		}
		for name, vals := range r.Header {
			if name == "Authorization" {
				continue
			}
			for _, v := range vals {
				if strings.Contains(v, testKey) {
					t.Errorf("%s: key in header %s", r.Path, name)
				}
			}
		}
	}
	if n := len(srv.ForeignRequests()); n != 0 {
		t.Errorf("foreign server got %d requests", n)
	}
}

func TestRedirectNotFollowed(t *testing.T) {
	for name, call := range func() map[string]func(*bskg.Client) error {
		return map[string]func(*bskg.Client) error{
			"Weakness": func(c *bskg.Client) error { _, err := c.Weakness(context.Background(), "CWE-79"); return err },
			"Status":   func(c *bskg.Client) error { return c.Status(context.Background()) },
		}
	}() {
		t.Run(name, func(t *testing.T) {
			srv := seektest.New(t)
			srv.Inject("/v1/weaknesses/CWE-79", seektest.Rule{RedirectTo: srv.Foreign().URL})
			srv.Inject("/v1/status", seektest.Rule{RedirectTo: srv.Foreign().URL})
			err := call(newClient(t, srv, 5*time.Second))
			if !errors.Is(err, bskg.ErrUnreachable) {
				t.Fatalf("err = %v, want ErrUnreachable", err)
			}
			assertClean(t, err, srv)
			if n := len(srv.ForeignRequests()); n != 0 {
				t.Fatalf("redirect was followed: foreign server got %d requests", n)
			}
			if got := len(srv.Requests()); got != 1 {
				t.Fatalf("configured host got %d requests, want 1", got)
			}
		})
	}
}

func TestStatusCodesMapToCategories(t *testing.T) {
	cases := []struct {
		status int
		want   error
	}{
		{http.StatusUnauthorized, bskg.ErrAuth},
		{http.StatusNotFound, bskg.ErrNotFound},
		{http.StatusTooManyRequests, bskg.ErrUnreachable},
		{http.StatusInternalServerError, bskg.ErrUnreachable},
		{http.StatusServiceUnavailable, bskg.ErrUnreachable},
		{http.StatusGatewayTimeout, bskg.ErrUnreachable},
	}
	paths := map[string]string{
		"Weakness":      "/v1/weaknesses/CWE-79",
		"Children":      "/v1/graph/neighborhood",
		"WeaknessVulns": "/v1/weaknesses/CWE-79/vulnerabilities",
		"Vulnerability": "/v1/vulnerabilities/CVE-2021-0001",
		"Status":        "/v1/status",
	}
	for _, tc := range cases {
		for name, path := range paths {
			t.Run(fmt.Sprintf("%d/%s", tc.status, name), func(t *testing.T) {
				srv := seektest.New(t)
				srv.Inject(path, seektest.Rule{Status: tc.status})
				err := calls(newClient(t, srv, 5*time.Second))[name](context.Background())
				if !errors.Is(err, tc.want) {
					t.Fatalf("err = %v, want %v", err, tc.want)
				}
				for _, other := range []error{bskg.ErrAuth, bskg.ErrNotFound, bskg.ErrUnreachable, bskg.ErrTimeout, bskg.ErrUnconfigured} {
					if other != tc.want && errors.Is(err, other) {
						t.Errorf("err also matches %v", other)
					}
				}
				assertClean(t, err, srv)
			})
		}
	}
}

func TestUnknownIDOnServerIsNotFound(t *testing.T) {
	srv := seektest.New(t)
	c := newClient(t, srv, 5*time.Second)
	if _, err := c.Weakness(context.Background(), "CWE-99999"); !errors.Is(err, bskg.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestNetworkErrorIsUnreachable(t *testing.T) {
	srv := seektest.New(t)
	c := newClient(t, srv, 5*time.Second)
	srv.Close()
	for name, call := range calls(c) {
		err := call(context.Background())
		if !errors.Is(err, bskg.ErrUnreachable) {
			t.Errorf("%s: err = %v, want ErrUnreachable", name, err)
		}
		assertClean(t, err, srv)
	}
}

func TestDeadlineIsTimeout(t *testing.T) {
	t.Run("client Timeout", func(t *testing.T) {
		srv := seektest.New(t)
		srv.Inject("/v1/weaknesses/CWE-79", seektest.Rule{Delay: 2 * time.Second})
		c := newClient(t, srv, 50*time.Millisecond)
		start := time.Now()
		_, err := c.Weakness(context.Background(), "CWE-79")
		if !errors.Is(err, bskg.ErrTimeout) {
			t.Fatalf("err = %v, want ErrTimeout", err)
		}
		if errors.Is(err, bskg.ErrUnreachable) {
			t.Error("timeout must not match ErrUnreachable")
		}
		if time.Since(start) > time.Second {
			t.Errorf("took %v", time.Since(start))
		}
		assertClean(t, err, srv)
	})
	t.Run("context deadline", func(t *testing.T) {
		srv := seektest.New(t)
		srv.Inject("/v1/status", seektest.Rule{Delay: 2 * time.Second})
		c := newClient(t, srv, 5*time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		err := c.Status(ctx)
		if !errors.Is(err, bskg.ErrTimeout) {
			t.Fatalf("err = %v, want ErrTimeout", err)
		}
		assertClean(t, err, srv)
	})
}

func TestInvalidIDsRejectedBeforeAnyRequest(t *testing.T) {
	bad := []string{
		"", " ", "CWE-79 ", " CWE-79", "cwe-79", "CWE-", "CWE-123456", "CWE-7/9", "CWE-79/vulnerabilities",
		"CWE-79?x=1", "CWE-79#f", "CWE-79%2F", "%43WE-79", "..", "../status", "CWE-79/../../status",
		"CWE-79\n", "CWE-\u0661\u0662", "CVE-2021-0001", "CWE-79\x00",
	}
	badCVE := []string{
		"", "CVE-2021-1", "CVE-21-0001", "CVE-2021-0001/../x", "CVE-2021-0001?a=b", "CVE-2021-0001#x",
		"CVE-2021-0001%2F", "CVE 2021-0001", "CVE-2021-0001 ", "..", "CWE-79", "cve-2021-0001", "CVE-2021-0001\n",
	}
	srv := seektest.New(t)
	c := newClient(t, srv, 5*time.Second)
	ctx := context.Background()
	for _, id := range bad {
		if _, err := c.Weakness(ctx, id); err == nil {
			t.Errorf("Weakness(%q) succeeded", id)
		}
		if _, err := c.Children(ctx, id, 1); err == nil {
			t.Errorf("Children(%q) succeeded", id)
		}
		if _, err := c.WeaknessVulns(ctx, id, 50); err == nil {
			t.Errorf("WeaknessVulns(%q) succeeded", id)
		}
	}
	for _, id := range badCVE {
		if _, err := c.Vulnerability(ctx, id); err == nil {
			t.Errorf("Vulnerability(%q) succeeded", id)
		}
	}
	if got := srv.Requests(); len(got) != 0 {
		t.Fatalf("invalid ids reached the network: %+v", got)
	}
}

func TestValidRequestsHaveExpectedShape(t *testing.T) {
	srv := seektest.New(t)
	c := newClient(t, srv, 5*time.Second)
	ctx := context.Background()
	_, _ = c.Weakness(ctx, "CWE-79")
	_, _ = c.WeaknessVulns(ctx, "CWE-79", 50)
	_, _ = c.Vulnerability(ctx, "CVE-2021-0001")
	reqs := srv.Requests()
	want := []struct {
		path  string
		query string
	}{
		{"/v1/weaknesses/CWE-79", ""},
		{"/v1/weaknesses/CWE-79/vulnerabilities", "limit=50"},
		{"/v1/vulnerabilities/CVE-2021-0001", ""},
	}
	if len(reqs) != len(want) {
		t.Fatalf("requests = %d", len(reqs))
	}
	for i, w := range want {
		if reqs[i].Path != w.path || reqs[i].RawQuery != w.query {
			t.Errorf("request %d = %s?%s, want %s?%s", i, reqs[i].Path, reqs[i].RawQuery, w.path, w.query)
		}
		if reqs[i].RawPath != "" {
			t.Errorf("request %d RawPath = %q, want plain", i, reqs[i].RawPath)
		}
	}
}

// rawServer is a real HTTP server with a fixed handler, for responses the
// fixture server cannot produce (oversized and malformed bodies).
func rawServer(t *testing.T, h http.HandlerFunc) *bskg.Client {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	c, err := bskg.New(bskg.Config{BaseURL: s.URL, Key: bskg.Secret(testKey), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestOversizedAndMalformedBodiesAreUnreachable(t *testing.T) {
	const secretText = "leaky-body-text"
	bodies := map[string]func(w http.ResponseWriter){
		"oversized": func(w http.ResponseWriter) {
			// Valid JSON prefix, then padding well past 2 MiB.
			_, _ = w.Write([]byte(`{"weakness":{"cweID":"CWE-79","name":"` + secretText))
			chunk := []byte(strings.Repeat("a", 64*1024))
			for i := 0; i < 48; i++ { // 3 MiB
				if _, err := w.Write(chunk); err != nil {
					return
				}
			}
			_, _ = w.Write([]byte(`"}}`))
		},
		"truncated":  func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{"weakness":{"cweID":"CWE-79",` + secretText)) },
		"not json":   func(w http.ResponseWriter) { _, _ = w.Write([]byte("<html>" + secretText + "</html>")) },
		"empty":      func(w http.ResponseWriter) {},
		"wrong type": func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{"weakness":"` + secretText + `"}`)) },
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			c := rawServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				body(w)
			})
			for mname, call := range calls(c) {
				err := call(context.Background())
				if !errors.Is(err, bskg.ErrUnreachable) {
					t.Errorf("%s: err = %v, want ErrUnreachable", mname, err)
					continue
				}
				if strings.Contains(err.Error(), secretText) || strings.Contains(err.Error(), testKey) {
					t.Errorf("%s: error leaks body: %v", mname, err)
				}
			}
		})
	}
}

func TestErrorBodiesNeverSurface(t *testing.T) {
	const echo = "ERRBODY-should-not-appear"
	for _, status := range []int{401, 404, 429, 500, 502, 503} {
		c := rawServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":{"code":"x","message":"` + echo + " " + r.Header.Get("Authorization") + `"}}`))
		})
		for name, call := range calls(c) {
			err := call(context.Background())
			if err == nil {
				t.Fatalf("%d %s: no error", status, name)
			}
			if strings.Contains(err.Error(), echo) || strings.Contains(err.Error(), testKey) {
				t.Errorf("%d %s: error leaks body: %v", status, name, err)
			}
		}
	}
}

func TestEchoedKeyBodyNeverSurfaces(t *testing.T) {
	srv := seektest.New(t)
	srv.Inject("/v1/weaknesses/CWE-79", seektest.Rule{EchoKey: true})
	srv.Inject("/v1/vulnerabilities/CVE-2021-0001", seektest.Rule{EchoKey: true})
	c := newClient(t, srv, 5*time.Second)
	w, err := c.Weakness(context.Background(), "CWE-79")
	if err == nil && (w.CWEID != "" || w.Name != "") {
		t.Errorf("unexpected data decoded from echo body: %+v", w)
	}
	if err != nil {
		assertClean(t, err, srv)
	}
	v, err := c.Vulnerability(context.Background(), "CVE-2021-0001")
	if strings.Contains(fmt.Sprintf("%+v", v), testKey) {
		t.Error("key reached Vulnerability result")
	}
	if err != nil {
		assertClean(t, err, srv)
	}
}

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

const (
	urlVar = "BELLUCODE_SEEK_BSKG_URL"
	keyVar = "BELLUCODE_SEEK_BSKG_KEY"
)

func TestConfigured(t *testing.T) {
	k := bskg.Secret("k")
	cases := []struct {
		name string
		cfg  bskg.Config
		want bool
	}{
		{"https", bskg.Config{BaseURL: "https://bskg.example.com", Key: k}, true},
		{"https port and path", bskg.Config{BaseURL: "https://bskg.example.com:8443/api", Key: k}, true},
		{"http localhost", bskg.Config{BaseURL: "http://localhost:8080", Key: k}, true},
		{"http 127.0.0.1", bskg.Config{BaseURL: "http://127.0.0.1:9", Key: k}, true},
		{"http 127.0.0.2", bskg.Config{BaseURL: "http://127.0.0.2", Key: k}, true},
		{"http ipv6 loopback", bskg.Config{BaseURL: "http://[::1]:8080", Key: k}, true},
		{"https loopback", bskg.Config{BaseURL: "https://127.0.0.1", Key: k}, true},
		{"empty url", bskg.Config{BaseURL: "", Key: k}, false},
		{"blank url", bskg.Config{BaseURL: "   ", Key: k}, false},
		{"empty key", bskg.Config{BaseURL: "https://bskg.example.com"}, false},
		{"blank key", bskg.Config{BaseURL: "https://bskg.example.com", Key: " \t\n"}, false},
		{"http remote", bskg.Config{BaseURL: "http://bskg.example.com", Key: k}, false},
		{"http private", bskg.Config{BaseURL: "http://10.0.0.5", Key: k}, false},
		{"http localhost lookalike", bskg.Config{BaseURL: "http://localhost.example.com", Key: k}, false},
		{"http 0.0.0.0", bskg.Config{BaseURL: "http://0.0.0.0", Key: k}, false},
		{"ftp", bskg.Config{BaseURL: "ftp://bskg.example.com", Key: k}, false},
		{"file", bskg.Config{BaseURL: "file:///etc/passwd", Key: k}, false},
		{"no scheme", bskg.Config{BaseURL: "bskg.example.com", Key: k}, false},
		{"relative", bskg.Config{BaseURL: "/v1/status", Key: k}, false},
		{"no host", bskg.Config{BaseURL: "https://", Key: k}, false},
		{"userinfo", bskg.Config{BaseURL: "https://user:pw@bskg.example.com", Key: k}, false},
		{"user only", bskg.Config{BaseURL: "https://user@bskg.example.com", Key: k}, false},
		{"query", bskg.Config{BaseURL: "https://bskg.example.com?a=b", Key: k}, false},
		{"empty query marker", bskg.Config{BaseURL: "https://bskg.example.com/?", Key: k}, false},
		{"fragment", bskg.Config{BaseURL: "https://bskg.example.com#x", Key: k}, false},
		{"empty fragment marker", bskg.Config{BaseURL: "https://bskg.example.com/#", Key: k}, false},
		{"garbage", bskg.Config{BaseURL: "https://[bad", Key: k}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.Configured(); got != tc.want {
				t.Errorf("Configured() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		cfg, ok, err := bskg.Load(env(map[string]string{urlVar: "https://bskg.example.com", keyVar: "abc"}))
		if err != nil || !ok {
			t.Fatalf("ok=%v err=%v", ok, err)
		}
		if cfg.BaseURL != "https://bskg.example.com" || string(cfg.Key) != "abc" || !cfg.Configured() {
			t.Errorf("cfg = %#v", cfg)
		}
	})
	t.Run("values are trimmed", func(t *testing.T) {
		cfg, ok, _ := bskg.Load(env(map[string]string{urlVar: "  https://bskg.example.com\n", keyVar: " abc \n"}))
		if !ok || cfg.BaseURL != "https://bskg.example.com" || string(cfg.Key) != "abc" {
			t.Errorf("ok=%v cfg=%#v", ok, cfg)
		}
	})
	t.Run("http loopback", func(t *testing.T) {
		_, ok, err := bskg.Load(env(map[string]string{urlVar: "http://127.0.0.1:8080", keyVar: "abc"}))
		if err != nil || !ok {
			t.Errorf("ok=%v err=%v", ok, err)
		}
	})
	t.Run("env takes precedence", func(t *testing.T) {
		// Load reads only the environment, so a value set there is the value used.
		cfg, ok, _ := bskg.Load(env(map[string]string{urlVar: "https://from-env.example.com", keyVar: "env-key"}))
		if !ok || cfg.BaseURL != "https://from-env.example.com" || string(cfg.Key) != "env-key" {
			t.Errorf("ok=%v cfg=%#v", ok, cfg)
		}
	})
	invalid := map[string]map[string]string{
		"missing both":    {},
		"missing url":     {keyVar: "abc"},
		"missing key":     {urlVar: "https://bskg.example.com"},
		"blank url":       {urlVar: "", keyVar: "abc"},
		"whitespace url":  {urlVar: "  \t", keyVar: "abc"},
		"blank key":       {urlVar: "https://bskg.example.com", keyVar: ""},
		"whitespace key":  {urlVar: "https://bskg.example.com", keyVar: " \n\t"},
		"http remote":     {urlVar: "http://bskg.example.com", keyVar: "abc"},
		"userinfo":        {urlVar: "https://u:p@bskg.example.com", keyVar: "abc"},
		"query":           {urlVar: "https://bskg.example.com/?x=1", keyVar: "abc"},
		"fragment":        {urlVar: "https://bskg.example.com/#x", keyVar: "abc"},
		"unsupported url": {urlVar: "ftp://bskg.example.com", keyVar: "abc"},
	}
	for name, vars := range invalid {
		t.Run("unconfigured/"+name, func(t *testing.T) {
			cfg, ok, err := bskg.Load(env(vars))
			if ok {
				t.Fatalf("ok = true, cfg = %#v", cfg)
			}
			if cfg.Configured() {
				t.Error("returned config reports Configured()")
			}
			if err != nil {
				for _, v := range vars {
					if v != "" && strings.Contains(err.Error(), v) {
						t.Errorf("error %q contains a configured value", err)
					}
				}
			}
		})
	}
}

func TestUnconfiguredClientMakesNoRequests(t *testing.T) {
	srv := seektest.New(t)
	cfgs := map[string]bskg.Config{
		"blank key":      {BaseURL: srv.URL, Key: "  "},
		"empty key":      {BaseURL: srv.URL},
		"blank url":      {BaseURL: " ", Key: bskg.Secret(testKey)},
		"empty config":   {},
		"remote http":    {BaseURL: "http://bskg.example.invalid", Key: bskg.Secret(testKey)},
		"userinfo":       {BaseURL: strings.Replace(srv.URL, "http://", "http://u:p@", 1), Key: bskg.Secret(testKey)},
		"query":          {BaseURL: srv.URL + "/?a=b", Key: bskg.Secret(testKey)},
		"fragment":       {BaseURL: srv.URL + "/#f", Key: bskg.Secret(testKey)},
		"unsupported":    {BaseURL: "gopher://" + srv.Listener.Addr().String(), Key: bskg.Secret(testKey)},
		"timeout unused": {Timeout: time.Second},
	}
	for name, cfg := range cfgs {
		t.Run(name, func(t *testing.T) {
			if cfg.Configured() {
				t.Fatal("test config is unexpectedly configured")
			}
			c, err := bskg.New(cfg)
			if err != nil {
				if !errors.Is(err, bskg.ErrUnconfigured) {
					t.Errorf("New err = %v, want ErrUnconfigured", err)
				}
				if strings.Contains(err.Error(), testKey) {
					t.Error("New error leaks key")
				}
			} else {
				for mname, call := range calls(c) {
					if err := call(context.Background()); !errors.Is(err, bskg.ErrUnconfigured) {
						t.Errorf("%s: err = %v, want ErrUnconfigured", mname, err)
					}
				}
			}
			if got := srv.Requests(); len(got) != 0 {
				t.Fatalf("unconfigured client made %d requests: %+v", len(got), got)
			}
		})
	}
}

func TestSecretIsRedacted(t *testing.T) {
	s := bskg.Secret(testKey)
	cfg := bskg.Config{BaseURL: "https://bskg.example.com", Key: s, Timeout: time.Second}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
		for name, arg := range map[string]any{"Secret": s, "*Secret": &s, "Config": cfg, "*Config": &cfg, "slice": []bskg.Secret{s}, "map": map[string]bskg.Secret{"k": s}} {
			out := fmt.Sprintf(verb, arg)
			if strings.Contains(out, testKey) {
				t.Errorf("Sprintf(%s, %s) leaks key: %s", verb, name, out)
			}
		}
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if out := fmt.Sprintf(verb, s); !strings.Contains(out, "[REDACTED]") {
			t.Errorf("Sprintf(%s, Secret) = %q, want [REDACTED]", verb, out)
		}
	}
	if got := s.String(); got != "[REDACTED]" {
		t.Errorf("String() = %q", got)
	}
	if got := s.GoString(); got != "[REDACTED]" && got != `"[REDACTED]"` {
		t.Errorf("GoString() = %q", got)
	}
	for name, v := range map[string]any{"Secret": s, "Config": cfg, "*Config": &cfg} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.Contains(string(b), testKey) {
			t.Errorf("%s JSON leaks key: %s", name, b)
		}
		if !strings.Contains(string(b), "[REDACTED]") {
			t.Errorf("%s JSON = %s, want [REDACTED]", name, b)
		}
	}
}
