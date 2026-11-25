package bskg

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const secret = "bskg_0123456789abcdef_SECRETSECRETSECRET"

const okBody = `{"graph":{"version":"rev-7","buildState":"ready","buildMode":"full","stale":false},"x":1}`

func newTest(t *testing.T, h http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	c := New(Config{URL: s.URL, Key: secret})
	c.sleep = func(context.Context, time.Duration) error { return nil }
	return c, s
}

func TestAuthHeaderNotURL(t *testing.T) {
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+secret || strings.Contains(r.URL.String(), secret) {
			t.Errorf("bad auth: %q %q", r.Header.Get("Authorization"), r.URL)
		}
		w.Write([]byte(okBody))
	})
	res, err := c.Vulnerability(context.Background(), "CVE-2024-12345")
	if err != nil || res.Revision != "rev-7" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestErrorMapping(t *testing.T) {
	for status, want := range map[int]string{401: CauseUnauthorized, 403: CauseUnauthorized, 503: CauseUnreachable} {
		c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) })
		_, err := c.Search(context.Background(), "x", 0, "")
		if Cause(err) != want {
			t.Errorf("%d: cause %q want %q", status, Cause(err), want)
		}
	}
}

func TestRateLimitedAfterThreeRetries(t *testing.T) {
	var n atomic.Int32
	var waits []time.Duration
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.Header().Set("Retry-After", "2")
		w.WriteHeader(429)
	})
	c.sleep = func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil }
	_, err := c.Search(context.Background(), "x", 0, "")
	if Cause(err) != CauseRateLimited || n.Load() != 4 || len(waits) != 3 || waits[0] != 2*time.Second {
		t.Fatalf("cause=%q calls=%d waits=%v", Cause(err), n.Load(), waits)
	}
}

func TestRateLimitThenSuccess(t *testing.T) {
	var n atomic.Int32
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			w.WriteHeader(429)
			return
		}
		w.Write([]byte(okBody))
	})
	if _, err := c.Search(context.Background(), "x", 0, ""); err != nil {
		t.Fatal(err)
	}
}

func TestTimeout(t *testing.T) {
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) { time.Sleep(300 * time.Millisecond) })
	c.http.Timeout = 50 * time.Millisecond
	_, err := c.Search(context.Background(), "x", 0, "")
	if Cause(err) != CauseTimeout {
		t.Fatalf("cause %q", Cause(err))
	}
}

func TestUnreachableAndTruncated(t *testing.T) {
	c, s := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.Write([]byte(`{"graph":`))
	})
	if _, err := c.Search(context.Background(), "x", 0, ""); Cause(err) != CauseUnreachable {
		t.Fatalf("truncated: %v", err)
	}
	s.Close()
	if _, err := c.Search(context.Background(), "x", 0, ""); Cause(err) != CauseUnreachable || strings.Contains(err.Error(), secret) {
		t.Fatalf("closed: %v", err)
	}
}

func TestWarnings(t *testing.T) {
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"graph":{"version":3,"buildMode":"sample","stale":true}}`))
	})
	res, err := c.Vulnerability(context.Background(), "CVE-2024-12345")
	if err != nil || len(res.Warnings) != 2 || !strings.Contains(res.Warnings[0], "stale=true") || !strings.Contains(res.Warnings[1], "buildMode=sample") || res.Revision != "3" {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestPurlVersionStripped(t *testing.T) {
	var got string
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.RequestURI()
		w.Write([]byte(okBody))
	})
	if _, err := c.AffectedPackages(context.Background(), "pkg:npm/%40scope/lodash@4.17.20?arch=x#sub"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "4.17") || strings.Contains(got, "arch") || !strings.Contains(got, "lodash") {
		t.Fatalf("path %q", got)
	}
	if StripPurlVersion("pkg:golang/github.com/a/b@v1.2.3") != "pkg:golang/github.com/a/b" {
		t.Fatal("strip")
	}
}

func TestDisallowedParamRejected(t *testing.T) {
	for _, k := range []string{"version", "path", "accountId", "key"} {
		if _, err := buildRequest("/v1/x", map[string]string{k: "v"}); err == nil || !strings.Contains(err.Error(), k) {
			t.Errorf("%s accepted", k)
		}
	}
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) { t.Error("request sent") })
	for _, l := range []int{-1, 101} {
		if _, err := c.Search(context.Background(), "x", l, ""); err == nil || !strings.Contains(err.Error(), "limit") {
			t.Errorf("limit %d: %v", l, err)
		}
	}
}

func TestKeyScrubbedFromErrors(t *testing.T) {
	c := New(Config{URL: "https://example.invalid", Key: secret})
	if got := c.scrub("Get https://h/?k=" + secret); strings.Contains(got, secret) || !strings.Contains(got, "[REDACTED:bskg_key]") {
		t.Fatal(got)
	}
	_, err := c.Search(context.Background(), "x", 0, "")
	if strings.Contains(err.Error(), secret) {
		t.Fatal(err)
	}
}

func TestNonLoopbackHTTPSendsNothing(t *testing.T) {
	var hits atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer s.Close()
	// Same server reached through a non-loopback host name.
	u := strings.Replace(s.URL, "127.0.0.1", "example.com", 1)
	c := New(Config{URL: u, Key: secret, HTTP: &http.Client{Transport: &http.Transport{}}})
	_, err := c.Vulnerability(context.Background(), "CVE-2024-12345")
	if Cause(err) != CauseNotConfigured || hits.Load() != 0 {
		t.Fatalf("cause=%q hits=%d", Cause(err), hits.Load())
	}
}
