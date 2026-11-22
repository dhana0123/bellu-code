// Package seektest provides a fake BSKG HTTP server for seek tests. It is a
// real httptest.Server that serves the JSON fixtures in internal/seek/testdata
// for the five endpoints the seek client may call, and records every request.
package seektest

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// Request is one recorded request.
type Request struct {
	Method   string
	Path     string // decoded path
	RawPath  string // escaped path as sent, when it differs from Path
	RawQuery string
	Header   http.Header
	Body     string
}

// Rule overrides the normal fixture response for one URL path. Fields are
// applied in this order: Delay, then Redirect, then EchoKey, then Status.
type Rule struct {
	Delay time.Duration
	// Status is returned with an error envelope body (401, 404, 429, 5xx ...).
	Status int
	// RedirectTo answers 302 with this Location (for example Foreign().URL).
	RedirectTo string
	// EchoKey answers 200 with a body that contains the bearer key, to test
	// that response bodies never reach results or logs.
	EchoKey bool
}

// Server is the fake BSKG.
type Server struct {
	*httptest.Server
	foreign *httptest.Server

	mu       sync.Mutex
	requests []Request
	foreignR []Request
	rules    map[string]Rule
	dir      string
}

// New starts the server and the foreign (redirect target) server. Both are
// closed when t finishes.
func New(t testing.TB) *Server {
	t.Helper()
	s := &Server{rules: map[string]Rule{}, dir: testdataDir()}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	s.foreign = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.foreignR = append(s.foreignR, record(r))
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"foreign":true}`))
	}))
	t.Cleanup(s.Server.Close)
	t.Cleanup(s.foreign.Close)
	return s
}

// Foreign returns the second server used as a redirect target. Its requests
// are listed by ForeignRequests.
func (s *Server) Foreign() *httptest.Server { return s.foreign }

// Inject sets a rule for an exact URL path such as "/v1/weaknesses/CWE-79".
func (s *Server) Inject(path string, r Rule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules[path] = r
}

// Clear removes every injected rule.
func (s *Server) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules = map[string]Rule{}
}

// Requests returns a copy of the recorded requests, oldest first.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}

// ForeignRequests returns the requests the foreign server received.
func (s *Server) ForeignRequests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.foreignR...)
}

var (
	reCWE = regexp.MustCompile(`^CWE-[0-9]{1,5}$`)
	reCVE = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
)

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.requests = append(s.requests, record(r))
	rule, ok := s.rules[r.URL.Path]
	s.mu.Unlock()

	if ok {
		if rule.Delay > 0 {
			select {
			case <-time.After(rule.Delay):
			case <-r.Context().Done():
				return
			}
		}
		switch {
		case rule.RedirectTo != "":
			http.Redirect(w, r, rule.RedirectTo+r.URL.Path, http.StatusFound)
			return
		case rule.EchoKey:
			writeJSON(w, http.StatusOK, `{"echo":"`+strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")+`"}`)
			return
		case rule.Status != 0:
			writeJSON(w, rule.Status, errorBody(rule.Status))
			return
		}
	}

	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusNotFound, errorBody(http.StatusNotFound))
		return
	}
	file := s.fixture(r)
	if file == "" {
		writeJSON(w, http.StatusNotFound, errorBody(http.StatusNotFound))
		return
	}
	body, err := os.ReadFile(filepath.Join(s.dir, file))
	if err != nil {
		writeJSON(w, http.StatusNotFound, errorBody(http.StatusNotFound))
		return
	}
	writeJSON(w, http.StatusOK, string(body))
}

// fixture maps a request to a file name in testdata, or "" for no route.
func (s *Server) fixture(r *http.Request) string {
	p := r.URL.Path
	switch {
	case p == "/v1/status":
		return "status.json"
	case p == "/v1/graph/neighborhood":
		q := r.URL.Query()
		depth := q.Get("depth")
		if depth == "" {
			depth = "1"
		}
		if q.Get("type") != "Weakness" || !reCWE.MatchString(q.Get("id")) {
			return ""
		}
		return "neighborhood_" + q.Get("id") + "_d" + depth + ".json"
	case strings.HasPrefix(p, "/v1/weaknesses/"):
		rest := strings.Split(strings.TrimPrefix(p, "/v1/weaknesses/"), "/")
		if !reCWE.MatchString(rest[0]) {
			return ""
		}
		if len(rest) == 1 {
			return "weakness_" + rest[0] + ".json"
		}
		if len(rest) == 2 && rest[1] == "vulnerabilities" {
			return "weakness_vulns_" + rest[0] + ".json"
		}
	case strings.HasPrefix(p, "/v1/vulnerabilities/"):
		id := strings.TrimPrefix(p, "/v1/vulnerabilities/")
		if reCVE.MatchString(id) {
			return "vulnerability_" + id + ".json"
		}
	}
	return ""
}

func record(r *http.Request) Request {
	req := Request{
		Method:   r.Method,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
		Header:   r.Header.Clone(),
	}
	if r.URL.RawPath != "" {
		req.RawPath = r.URL.RawPath
	}
	if r.Body != nil {
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		req.Body = string(buf[:n])
	}
	return req
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// errorBody follows the BSKG error envelope: {"error":{"code","message"},"graph":{...}}.
func errorBody(status int) string {
	code := map[int]string{
		http.StatusUnauthorized:        "unauthorized",
		http.StatusNotFound:            "not_found",
		http.StatusTooManyRequests:     "rate_limited",
		http.StatusInternalServerError: "internal",
		http.StatusServiceUnavailable:  "unavailable",
		http.StatusGatewayTimeout:      "timeout",
	}[status]
	if code == "" {
		code = "internal"
	}
	return `{"error":{"code":"` + code + `","message":"fake bskg ` + code + `"},"graph":{"version":"dev","buildState":"ready","buildMode":"sample","stale":false,"sources":{}}}`
}

func testdataDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "testdata")
}
