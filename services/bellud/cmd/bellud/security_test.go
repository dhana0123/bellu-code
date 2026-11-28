package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func runSec(t *testing.T, env map[string]string, args ...string) (int, string, string) {
	t.Helper()
	var o, e bytes.Buffer
	code := runSecurity(args, securityEnv{getenv: func(k string) string { return env[k] }, stdout: &o, stderr: &e})
	return code, o.String(), e.String()
}

func TestSecurityArgumentErrors(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"bogus"},
		{"scan", "--kind", "nope", "--target-type", "repository", "--target", "x"},
		{"scan", "--kind", "sbom", "--target-type", "repository"},
		{"findings", "--limit", "0"},
		{"findings", "--output", "xml"},
		{"sbom", "--format", "pdf"},
		{"sbom", "--out", "f.json"},
		{"cve"},
		{"cve", "lookup"},
		{"cve", "lookup", "--purl", "pkg:npm/a"},
		{"cve", "status", "--output", "xml"},
	} {
		code, out, errOut := runSec(t, nil, args...)
		if code != 2 || out != "" || !strings.Contains(errOut, "error:") {
			t.Errorf("%v: code=%d stdout=%q stderr=%q", args, code, out, errOut)
		}
	}
}

func TestSecurityServerDownExitsNonZeroWithEmptyStdout(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	code, out, errOut := runSec(t, nil, "findings", "--server", url)
	if code != 1 || out != "" || !strings.Contains(errOut, "running server") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errOut)
	}
}

func TestSecurityServerErrorIsReportedOnStderr(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"message":"findings are not enabled"}`))
	}))
	defer srv.Close()
	code, out, errOut := runSec(t, nil, "findings", "--server", srv.URL)
	if code != 1 || out != "" || !strings.Contains(errOut, "findings are not enabled") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errOut)
	}
}

func TestSecurityScanWaitAndFindingsHappyPath(t *testing.T) {
	securityPoll = time.Millisecond
	var polls atomic.Int32
	mux := http.NewServeMux()
	authed := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if _, p, ok := r.BasicAuth(); !ok || p != "secret" {
				w.WriteHeader(401)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("POST /api/experimental/scans", authed(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(202)
		_, _ = w.Write([]byte(`{"id":"j1","status":"queued"}`))
	}))
	mux.HandleFunc("GET /api/experimental/scans/j1", authed(func(w http.ResponseWriter, _ *http.Request) {
		st := "running"
		if polls.Add(1) >= 2 {
			st = "succeeded"
		}
		_, _ = w.Write([]byte(`{"id":"j1","status":"` + st + `","created":3}`))
	}))
	mux.HandleFunc("GET /api/experimental/findings", authed(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("severity") != "high" || r.URL.Query().Get("limit") != "5" {
			w.WriteHeader(400)
			return
		}
		_, _ = w.Write([]byte(`{"items":[{"id":"f1","severity":"high","status":"open","category":"vulnerability","assetId":"a1","title":"CVE-1"}]}`))
	}))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	env := map[string]string{"BELLUCODE_PASSWORD": "secret"}

	code, out, errOut := runSec(t, env, "scan", "--server", srv.URL, "--kind", "sbom", "--target-type", "repository", "--target", "r1", "--wait")
	if code != 0 || !strings.Contains(out, "job j1 succeeded (created 3") || errOut != "" {
		t.Fatalf("scan: code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	code, out, errOut = runSec(t, env, "findings", "--server", srv.URL, "--severity", "high", "--limit", "5")
	if code != 0 || !strings.Contains(out, "CVE-1") || !strings.Contains(out, "SEVERITY") || errOut != "" {
		t.Fatalf("findings: code=%d stdout=%q stderr=%q", code, out, errOut)
	}
}

func TestSecurityCVEStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, p, ok := r.BasicAuth(); r.URL.Path != "/api/experimental/cve/status" || !ok || p != "secret" {
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write([]byte(`{"mode":"hybrid","dbInstalled":true,"dataAge":"3d","stale":false,"bskgReachable":true,"lastGap":null}`))
	}))
	defer srv.Close()
	env := map[string]string{"BELLUCODE_PASSWORD": "secret"}
	code, out, errOut := runSec(t, env, "cve", "status", "--server", srv.URL)
	if code != 0 || errOut != "" || !strings.Contains(out, "Mode") || !strings.Contains(out, "hybrid") || !strings.Contains(out, "BskgReachable") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	if strings.Contains(out, "secret") {
		t.Fatalf("key leaked: %q", out)
	}
	code, out, _ = runSec(t, env, "cve", "status", "--server", srv.URL, "--output", "json")
	if code != 0 || !strings.Contains(out, `"dbInstalled":true`) {
		t.Fatalf("json: code=%d stdout=%q", code, out)
	}
}
