package cveupdate

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type seen struct {
	method, path, rawQuery string
	header                 http.Header
	bodyLen                int64
}

func recorder(t *testing.T, status func(n int) int) (*httptest.Server, *[]seen) {
	t.Helper()
	var mu sync.Mutex
	var log []seen
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		log = append(log, seen{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Clone(), r.ContentLength})
		n := len(log)
		mu.Unlock()
		code := status(n)
		if code == 200 {
			w.Header().Set("ETag", `"abc"`)
		}
		w.WriteHeader(code)
		if code == 200 && r.Method == http.MethodGet {
			_, _ = w.Write([]byte("data"))
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &log
}

func noSleep(context.Context, time.Duration) error { return nil }

func TestFetchIndexSendsOnlyAllowedHeaders(t *testing.T) {
	srv, log := recorder(t, func(int) int { return 200 })
	c, err := New(Config{MirrorURL: srv.URL, Version: "1.2.3", Sleep: noSleep})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.FetchIndex(context.Background(), `"old"`)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "data" || resp.ETag != `"abc"` {
		t.Fatalf("unexpected response %q %q", b, resp.ETag)
	}
	got := (*log)[0]
	if got.method != "GET" || got.path != "/cve/v1/index.json" || got.rawQuery != "" || got.bodyLen > 0 {
		t.Fatalf("bad request %+v", got)
	}
	if got.header.Get("User-Agent") != "bellu-cve-update/1.2.3" || got.header.Get("If-None-Match") != `"old"` {
		t.Fatalf("bad headers %v", got.header)
	}
	for k := range got.header {
		switch k {
		case "User-Agent", "If-None-Match", "Accept":
		default:
			t.Errorf("unexpected header %s", k)
		}
	}
}

func TestEmptyUserAgentAndNotModified(t *testing.T) {
	srv, log := recorder(t, func(int) int { return 304 })
	c, _ := New(Config{MirrorURL: srv.URL, UserAgentSet: true, Sleep: noSleep})
	if _, err := c.FetchIndex(context.Background(), `"x"`); !errors.Is(err, ErrNotModified) {
		t.Fatalf("want ErrNotModified, got %v", err)
	}
	// Go omits an empty User-Agent instead of sending its default.
	if ua := (*log)[0].header["User-Agent"]; len(ua) != 0 && ua[0] != "" {
		t.Fatalf("want empty User-Agent, got %v", ua)
	}
	if len(*log) != 1 {
		t.Fatalf("304 must not retry")
	}
}

func TestRetriesThenSucceeds(t *testing.T) {
	srv, log := recorder(t, func(n int) int {
		if n < 3 {
			return 503
		}
		return 200
	})
	var waits []time.Duration
	c, _ := New(Config{MirrorURL: srv.URL, Sleep: func(_ context.Context, d time.Duration) error {
		waits = append(waits, d)
		return nil
	}})
	resp, err := c.FetchPack(context.Background(), "packs/a.tar")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(*log) != 3 || len(waits) != 2 || waits[0] != 5*time.Second {
		t.Fatalf("attempts=%d waits=%v", len(*log), waits)
	}
}

func TestMirrorFailureNamesMirrorAndStopsAfterThreeAttempts(t *testing.T) {
	srv, log := recorder(t, func(int) int { return 500 })
	c, _ := New(Config{MirrorURL: srv.URL, Sleep: noSleep})
	_, err := c.FetchIndex(context.Background(), "")
	if !errors.Is(err, ErrMirror) || len(*log) != 3 {
		t.Fatalf("err=%v attempts=%d", err, len(*log))
	}
}

func TestResolvePackURL(t *testing.T) {
	c, _ := New(Config{MirrorURL: "https://mirror.example/base/"})
	for in, want := range map[string]string{
		"packs/a.tar":                      "https://mirror.example/base/cve/v1/packs/a.tar",
		"https://cve.bellu.dev/cve/v1/b.x": "https://mirror.example/base/cve/v1/b.x",
	} {
		if got, err := c.ResolvePackURL(in); err != nil || got != want {
			t.Errorf("%s: got %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"a?x=1", "../x", "ftp://h/x", ""} {
		if _, err := c.ResolvePackURL(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
	d, _ := New(Config{})
	if _, err := d.ResolvePackURL("https://evil.example/cve/v1/a"); err == nil {
		t.Error("foreign host must be rejected without a mirror")
	}
}
