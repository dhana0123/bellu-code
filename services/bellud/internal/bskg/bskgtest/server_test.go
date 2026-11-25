package bskgtest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func get(t *testing.T, s *Server, path, mode string) (*http.Response, []byte, error) {
	t.Helper()
	req, _ := http.NewRequest("GET", s.URL+path, nil)
	req.Header.Set("Authorization", "Bearer bskg_secret")
	if mode != "" {
		req.Header.Set(ModeHeader, mode)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp, b, err
}

func graphOf(t *testing.T, b []byte) Graph {
	t.Helper()
	var e struct{ Graph Graph }
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	return e.Graph
}

func TestEndpointsOK(t *testing.T) {
	s := New(Options{})
	defer s.Close()
	for _, p := range []string{
		"/v1/vulnerabilities/CVE-2021-44228", "/v1/vulnerabilities?q=lodash", "/v1/weaknesses/CWE-502",
		"/v1/graph/neighborhood?id=CVE-2021-44228&type=Vulnerability&nodeTypes=Exploit",
	} {
		resp, b, err := get(t, s, p, "")
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("%s: %v %v", p, resp, err)
		}
		g := graphOf(t, b)
		if g.Version != "rev-test-1" || g.Stale || g.BuildMode != "full" {
			t.Fatalf("%s: envelope %+v", p, g)
		}
	}
	if resp, _, _ := get(t, s, "/v1/vulnerabilities/CVE-1999-0001", ""); resp.StatusCode != 404 {
		t.Fatalf("want 404, got %d", resp.StatusCode)
	}
}

func TestFailureModes(t *testing.T) {
	s := New(Options{RetryAfter: 7})
	defer s.Close()
	const p = "/v1/vulnerabilities/CVE-2021-44228"
	for mode, want := range map[string]int{"401": 401, "503": 503, "504": 504, "429:always": 429} {
		resp, _, err := get(t, s, p, mode)
		if err != nil || resp.StatusCode != want {
			t.Fatalf("%s: got %v %v", mode, resp, err)
		}
		if want == 429 && resp.Header.Get("Retry-After") != "7" {
			t.Fatalf("Retry-After = %q", resp.Header.Get("Retry-After"))
		}
	}
	_, b, _ := get(t, s, p, "stale")
	if !graphOf(t, b).Stale {
		t.Fatal("want stale")
	}
	_, b, _ = get(t, s, p, "sample")
	if graphOf(t, b).BuildMode != "sample" {
		t.Fatal("want sample")
	}
	if _, b, err := get(t, s, p, "truncated"); err == nil || json.Valid(b) {
		t.Fatalf("want truncated body error, got err=%v len=%d", err, len(b))
	}
}

func TestRateLimitThenSuccess(t *testing.T) {
	s := New(Options{Mode: Mode429, RateLimitTimes: 2})
	defer s.Close()
	var codes []int
	for i := 0; i < 3; i++ {
		resp, _, _ := get(t, s, "/v1/weaknesses/CWE-94", "")
		codes = append(codes, resp.StatusCode)
	}
	if codes[0] != 429 || codes[1] != 429 || codes[2] != 200 || s.Calls429() != 2 {
		t.Fatalf("codes %v", codes)
	}
}

func TestSlowTimesOut(t *testing.T) {
	s := New(Options{Mode: ModeSlow, Delay: 5 * time.Second})
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", s.URL+"/v1/weaknesses/CWE-94", nil)
	if _, err := http.DefaultClient.Do(req); err == nil {
		t.Fatal("want timeout")
	}
}

func TestRecorderAndAllowList(t *testing.T) {
	s := New(Options{})
	defer s.Close()
	get(t, s, "/v1/vulnerabilities/CVE-2021-44228", "")
	reqs := s.Recorder.Requests()
	if len(reqs) != 1 || !reqs[0].AuthPresent || reqs[0].Header.Get("Authorization") != "" {
		t.Fatalf("recording: %+v", reqs)
	}
	allow := AllowList{Rules: []Rule{{Method: "GET", Path: "/v1/vulnerabilities/{id}"}}}
	s.Recorder.AssertAllowed(t, allow)

	get(t, s, "/v1/vulnerabilities/CVE-2021-44228?debug=1", "")
	get(t, s, "/v1/stats", "")
	v := allow.Violations(s.Recorder.Requests())
	if len(v) != 2 || !strings.Contains(v[0], "GET /v1/vulnerabilities/CVE-2021-44228") || !strings.Contains(v[0], "param debug") ||
		!strings.Contains(v[1], "GET /v1/stats") {
		t.Fatalf("violations: %q", v)
	}
	req, _ := http.NewRequest("GET", s.URL+"/v1/vulnerabilities/CVE-2021-44228", nil)
	req.Header.Set("X-Evil", "1")
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
	}
	last := allow.Violations(s.Recorder.Requests()[3:])
	if len(last) != 1 || !strings.Contains(last[0], "header X-Evil") {
		t.Fatalf("header violation: %q", last)
	}
}
