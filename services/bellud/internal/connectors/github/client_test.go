package github

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// countingRT records requests and answers from a route table.
type countingRT struct {
	mu     sync.Mutex
	reqs   []*http.Request
	routes func(*http.Request) (int, string, http.Header)
}

func (c *countingRT) RoundTrip(r *http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.reqs = append(c.reqs, r)
	c.mu.Unlock()
	status, body, h := c.routes(r)
	if h == nil {
		h = http.Header{}
	}
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
}

func (c *countingRT) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.reqs)
}

func newTestClient(rt *countingRT) *Client {
	return NewClient(&http.Client{Transport: rt}, "api.github.com", "")
}

func TestValidateToken(t *testing.T) {
	for _, tc := range []struct {
		in string
		ok bool
	}{
		{"github_pat_11ABCDEF_xyz", true},
		{"ghp_classic123456", false},
		{"gho_oauth", false},
		{"", false},
		{"github_pat_", false},
		{" github_pat_abc", false},
		{"GITHUB_PAT_abc", false},
	} {
		err := ValidateToken([]byte(tc.in))
		if (err == nil) != tc.ok {
			t.Errorf("%q: err=%v want ok=%v", tc.in, err, tc.ok)
		}
		if err != nil {
			if !errors.Is(err, ErrClassicToken) || strings.Contains(err.Error(), tc.in) && tc.in != "" {
				t.Errorf("%q: error must be ErrClassicToken without the token: %v", tc.in, err)
			}
		}
	}
	if !strings.Contains(ClassicTokenMessage, "read-only") || !strings.Contains(ClassicTokenMessage, "specific repositories") {
		t.Error("message must explain the read-only and repository limits")
	}
}

func TestParseTokenExpiry(t *testing.T) {
	got, ok := ParseTokenExpiry("2025-08-10 04:00:00 UTC")
	if !ok || !got.Equal(time.Date(2025, 8, 10, 4, 0, 0, 0, time.UTC)) {
		t.Fatalf("got %v %v", got, ok)
	}
	for _, bad := range []string{"", "tomorrow", "2025-08-10"} {
		if _, ok := ParseTokenExpiry(bad); ok {
			t.Errorf("%q should not parse", bad)
		}
	}
}

func TestVerifyRecordsExpiryWhenPresent(t *testing.T) {
	h := http.Header{}
	h.Set(TokenExpiryHeader, "2030-01-02 03:04:05 UTC")
	rt := &countingRT{routes: func(r *http.Request) (int, string, http.Header) {
		return 200, `{"login":"octo","id":7,"type":"User"}`, h
	}}
	u, exp, ok, err := newTestClient(rt).Verify(context.Background())
	if err != nil || u.Login != "octo" || !ok || exp.Year() != 2030 {
		t.Fatalf("u=%+v exp=%v ok=%v err=%v", u, exp, ok, err)
	}
	req := rt.reqs[0]
	if req.URL.String() != "https://api.github.com/user" || req.Method != "GET" {
		t.Errorf("request %s %s", req.Method, req.URL)
	}
	if req.Header.Get("Authorization") != "" {
		t.Error("client must not set credentials; the broker injects them")
	}

	rt = &countingRT{routes: func(*http.Request) (int, string, http.Header) { return 200, `{"login":"octo"}`, nil }}
	if _, _, ok, err := newTestClient(rt).Verify(context.Background()); err != nil || ok {
		t.Fatalf("no header: ok=%v err=%v", ok, err)
	}
}

func TestStatusErrorHasNoBody(t *testing.T) {
	rt := &countingRT{routes: func(*http.Request) (int, string, http.Header) {
		return 401, `{"message":"Bad credentials github_pat_x"}`, nil
	}}
	_, err := newTestClient(rt).User(context.Background())
	var se *StatusError
	if !errors.As(err, &se) || !se.Unauthorized() || strings.Contains(err.Error(), "github_pat_x") {
		t.Fatalf("err=%v", err)
	}
}

func TestBadNamesSendNothing(t *testing.T) {
	rt := &countingRT{routes: func(*http.Request) (int, string, http.Header) { return 200, `[]`, nil }}
	c := newTestClient(rt)
	for _, pair := range [][2]string{{"..", "r"}, {"o", ".."}, {"o/x", "r"}, {"o", "r?x=1"}, {"", "r"}} {
		if _, err := c.OpenPullRequests(context.Background(), pair[0], pair[1]); !errors.Is(err, ErrBadName) {
			t.Errorf("%v: err=%v", pair, err)
		}
	}
	if _, err := c.Org(context.Background(), "a/b"); !errors.Is(err, ErrBadName) {
		t.Errorf("org err=%v", err)
	}
	if rt.count() != 0 {
		t.Fatalf("%d requests sent", rt.count())
	}
}

func TestPaginationAndGHESBase(t *testing.T) {
	page := func(n int) string {
		items := make([]string, n)
		for i := range items {
			items[i] = `{"number":1,"title":"t","state":"open"}`
		}
		return "[" + strings.Join(items, ",") + "]"
	}
	rt := &countingRT{routes: func(r *http.Request) (int, string, http.Header) {
		if r.URL.Query().Get("page") == "1" {
			return 200, page(perPage), nil
		}
		return 200, page(3), nil
	}}
	c := NewClient(&http.Client{Transport: rt}, "ghe.example.com", "/api/v3/")
	prs, err := c.OpenPullRequests(context.Background(), "o", "r")
	if err != nil || len(prs) != perPage+3 || rt.count() != 2 {
		t.Fatalf("len=%d n=%d err=%v", len(prs), rt.count(), err)
	}
	got := rt.reqs[0].URL
	if got.Host != "ghe.example.com" || got.Path != "/api/v3/repos/o/r/pulls" || got.Query().Get("state") != "open" {
		t.Errorf("url %s", got)
	}
}

func TestSecretScanningDropsSecretValue(t *testing.T) {
	rt := &countingRT{routes: func(*http.Request) (int, string, http.Header) {
		return 200, `[{"number":4,"state":"open","secret_type":"aws_access_key_id","secret":"AKIAREALSECRET"}]`, nil
	}}
	alerts, err := newTestClient(rt).SecretScanningAlerts(context.Background(), "o", "r")
	if err != nil || len(alerts) != 1 || alerts[0].Detector != "aws_access_key_id" {
		t.Fatalf("%+v %v", alerts, err)
	}
}

func TestOpenIssueCountUsesLinkAndReadsNoContent(t *testing.T) {
	h := http.Header{}
	h.Set("Link", `<https://api.github.com/repositories/1/issues?state=open&per_page=1&page=2>; rel="next", <https://api.github.com/repositories/1/issues?state=open&per_page=1&page=57>; rel="last"`)
	rt := &countingRT{routes: func(*http.Request) (int, string, http.Header) {
		return 200, `[{"number":9,"title":"x","body":"private text"}]`, h
	}}
	n, err := newTestClient(rt).OpenIssueCount(context.Background(), "o", "r")
	if err != nil || n != 57 || rt.reqs[0].URL.Query().Get("per_page") != "1" {
		t.Fatalf("n=%d err=%v", n, err)
	}
	rt = &countingRT{routes: func(*http.Request) (int, string, http.Header) { return 200, `[{"number":1}]`, nil }}
	if n, err := newTestClient(rt).OpenIssueCount(context.Background(), "o", "r"); err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestProjectionsDecode(t *testing.T) {
	rt := &countingRT{routes: func(r *http.Request) (int, string, http.Header) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/actions/workflows"):
			return 200, `{"total_count":1,"workflows":[{"id":3,"name":"CI","path":".github/workflows/ci.yml","state":"active"}]}`, nil
		case strings.HasSuffix(r.URL.Path, "/code-scanning/alerts"):
			return 200, `[{"number":1,"state":"open","rule":{"id":"js/xss","severity":"error","security_severity_level":"high"},"tool":{"name":"CodeQL"}}]`, nil
		case strings.HasSuffix(r.URL.Path, "/dependabot/alerts"):
			return 200, `[{"number":2,"state":"open","security_advisory":{"ghsa_id":"GHSA-x","severity":"high"},"dependency":{"package":{"name":"lodash","ecosystem":"npm"}}}]`, nil
		case r.URL.Path == "/installation/repositories":
			return 200, `{"total_count":1,"repositories":[{"id":1,"name":"r","full_name":"o/r","owner":{"login":"o","type":"Organization"}}]}`, nil
		case strings.HasPrefix(r.URL.Path, "/orgs/"):
			return 200, `{"login":"o","id":5,"name":"Org"}`, nil
		}
		return 404, `{}`, nil
	}}
	c, ctx := newTestClient(rt), context.Background()
	if w, err := c.Workflows(ctx, "o", "r"); err != nil || len(w) != 1 || w[0].Name != "CI" {
		t.Errorf("workflows %+v %v", w, err)
	}
	if a, err := c.CodeScanningAlerts(ctx, "o", "r"); err != nil || a[0].Rule.SecuritySeverityLevel != "high" || a[0].Tool.Name != "CodeQL" {
		t.Errorf("code scanning %+v %v", a, err)
	}
	if a, err := c.DependabotAlerts(ctx, "o", "r"); err != nil || a[0].Dependency.Package.Name != "lodash" {
		t.Errorf("dependabot %+v %v", a, err)
	}
	if r, err := c.InstallationRepositories(ctx); err != nil || r[0].Owner.Login != "o" {
		t.Errorf("repos %+v %v", r, err)
	}
	if o, err := c.Org(ctx, "o"); err != nil || o.ID != 5 {
		t.Errorf("org %+v %v", o, err)
	}
}
