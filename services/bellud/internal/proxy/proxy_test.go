package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/tschild"
)

func childFor(t *testing.T, h http.Handler) (*tschild.Child, *httptest.Server) {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	u, _ := url.Parse(s.URL)
	return &tschild.Child{URL: u, Password: "internal-pw"}, s
}

func TestForwardsAndIsolatesCredentials(t *testing.T) {
	var got *http.Request
	c, _ := childFor(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		w.Header().Set("X-Up", "1")
		w.WriteHeader(201)
		io.WriteString(w, "hello")
	}))
	h := New(func() *tschild.Child { return c })
	req := httptest.NewRequest("POST", "http://client.example:4096/a/b?x=1", strings.NewReader("body"))
	req.RemoteAddr = "10.1.2.3:555"
	req.Header.Set("Authorization", "Basic ZXh0ZXJuYWw6c2VjcmV0")
	req.Header.Set("Cookie", "opencode_session=zzz")
	req.Header.Set("X-Forwarded-For", "6.6.6.6")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != 201 || rec.Body.String() != "hello" || rec.Header().Get("X-Up") != "1" {
		t.Fatalf("bad response %d %q", rec.Code, rec.Body.String())
	}
	if got.URL.Path != "/a/b" || got.URL.RawQuery != "x=1" || got.Host != "client.example:4096" {
		t.Fatalf("bad request %v host=%s", got.URL, got.Host)
	}
	if v := got.Header.Values("Authorization"); len(v) != 1 {
		t.Fatalf("auth headers %v", v)
	}
	if u, p, _ := got.BasicAuth(); u != "opencode" || p != "internal-pw" {
		t.Fatalf("basic %s %s", u, p)
	}
	if got.Header.Get("Cookie") != "" {
		t.Fatal("cookie leaked")
	}
	if got.Header.Get("X-Forwarded-For") != "10.1.2.3" ||
		got.Header.Get("X-Forwarded-Host") != "client.example:4096" ||
		got.Header.Get("X-Forwarded-Proto") != "http" {
		t.Fatalf("xff %v", got.Header)
	}
}

func TestNoChild503(t *testing.T) {
	h := New(func() *tschild.Child { return nil })
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
	if rec.Code != 503 || rec.Header().Get("Retry-After") != "2" {
		t.Fatalf("got %d %v", rec.Code, rec.Header())
	}
	var b map[string]string
	if json.Unmarshal(rec.Body.Bytes(), &b) != nil || b["_tag"] != "ServiceUnavailableError" {
		t.Fatalf("body %s", rec.Body.String())
	}
}

func TestRefusedConnection502(t *testing.T) {
	c, s := childFor(t, http.NotFoundHandler())
	s.Close()
	h := New(func() *tschild.Child { return c })
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
	if rec.Code != 502 || !strings.Contains(rec.Body.String(), "upstream unavailable") {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
}

func TestSSEStreamsUnbuffered(t *testing.T) {
	release := make(chan struct{})
	c, _ := childFor(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: 1\n\n")
		w.(http.Flusher).Flush()
		<-release
	}))
	front := httptest.NewServer(New(func() *tschild.Child { return c }))
	defer front.Close()
	res, err := http.Get(front.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	line := make(chan string, 1)
	go func() { l, _ := bufio.NewReader(res.Body).ReadString('\n'); line <- l }()
	select {
	case l := <-line:
		if l != "data: 1\n" {
			t.Fatalf("line %q", l)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("chunk not delivered before stream end")
	}
	close(release)
}

func TestSSECleanCloseWhenChildDies(t *testing.T) {
	c, s := childFor(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: 1\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	front := httptest.NewServer(New(func() *tschild.Child { return c }))
	defer front.Close()
	res, err := http.Get(front.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	buf := make([]byte, 9)
	if _, err := io.ReadFull(res.Body, buf); err != nil {
		t.Fatal(err)
	}
	go s.CloseClientConnections()
	rest, err := io.ReadAll(res.Body)
	if err != nil || len(rest) != 0 {
		t.Fatalf("want clean EOF, got %q %v", rest, err)
	}
}

func TestClientDisconnectCancelsUpstream(t *testing.T) {
	cancelled := make(chan struct{})
	started := make(chan struct{})
	c, _ := childFor(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(cancelled)
	}))
	front := httptest.NewServer(New(func() *tschild.Child { return c }))
	defer front.Close()
	rctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(rctx, "GET", front.URL, nil)
	go http.DefaultClient.Do(req)
	<-started
	cancel()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("upstream not cancelled within 1s")
	}
}

func TestUpgradeHook(t *testing.T) {
	c, _ := childFor(t, http.NotFoundHandler())
	called := false
	h := New(func() *tschild.Child { return c }, Options{Upgrade: func(w http.ResponseWriter, r *http.Request, _ *tschild.Child) {
		called = true
		w.WriteHeader(204)
	}})
	req := httptest.NewRequest("GET", "/ws", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !called || rec.Code != 204 {
		t.Fatal("upgrade hook not used")
	}
}
