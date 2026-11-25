// Package bskgtest provides a fake BSKG REST server for tests. It binds to
// loopback through httptest, can fail in chosen ways, and can record every
// request so a test can assert that the client stays inside an allow-list.
package bskgtest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Mode selects how the fake server answers.
type Mode string

const (
	ModeOK        Mode = "ok"
	Mode401       Mode = "401"
	Mode429       Mode = "429" // Retry-After; see Options.RateLimitTimes
	Mode503       Mode = "503"
	Mode504       Mode = "504"
	ModeTruncated Mode = "truncated" // declared length longer than the body sent
	ModeStale     Mode = "stale"     // success with graph.stale = true
	ModeSample    Mode = "sample"    // success with graph.buildMode = "sample"
	ModeSlow      Mode = "slow"      // success after Options.Delay
)

// ModeHeader selects the mode for one request. Value is a Mode, and for 429
// it may be "429:N" (N rate-limited responses, then success) or "429:always".
const ModeHeader = "X-Fake-Mode"

// Options configures a Server.
type Options struct {
	// Mode is the default mode when a request has no ModeHeader.
	Mode Mode
	// RateLimitTimes is how many 429 responses to send before succeeding.
	// A negative value means always. Zero with Mode429 means always.
	RateLimitTimes int
	// RetryAfter is the Retry-After value in seconds for 429. Default 1.
	RetryAfter int
	// Delay is the slow-mode delay. Default 2s.
	Delay time.Duration
	// Revision is the graph version in the envelope. Default "rev-test-1".
	Revision string
}

// Server is a fake BSKG server.
type Server struct {
	*httptest.Server
	Recorder *Recorder

	opts Options
	mu   sync.Mutex
	n429 int
}

// New starts a fake server on loopback. The caller must call Close.
func New(opts Options) *Server {
	if opts.Mode == "" {
		opts.Mode = ModeOK
	}
	if opts.RetryAfter <= 0 {
		opts.RetryAfter = 1
	}
	if opts.Delay <= 0 {
		opts.Delay = 2 * time.Second
	}
	if opts.Revision == "" {
		opts.Revision = "rev-test-1"
	}
	s := &Server{Recorder: &Recorder{}, opts: opts}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

// Calls429 returns how many 429 responses were sent.
func (s *Server) Calls429() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n429
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.Recorder.record(r)
	mode, times := s.opts.Mode, s.opts.RateLimitTimes
	if h := r.Header.Get(ModeHeader); h != "" {
		name, arg, _ := strings.Cut(h, ":")
		mode = Mode(name)
		if arg == "always" {
			times = -1
		} else if n, err := strconv.Atoi(arg); err == nil {
			times = n
		}
	}
	if mode == Mode429 && times == 0 {
		times = -1
	}
	graph := Graph{Version: s.opts.Revision, BuildState: "ready", BuildMode: "full"}
	switch mode {
	case Mode401:
		writeErr(w, 401, "unauthorized", graph)
		return
	case Mode503:
		writeErr(w, 503, "migrating", graph)
		return
	case Mode504:
		writeErr(w, 504, "query_timeout", graph)
		return
	case Mode429:
		s.mu.Lock()
		limited := times < 0 || s.n429 < times
		if limited {
			s.n429++
		}
		s.mu.Unlock()
		if limited {
			w.Header().Set("Retry-After", strconv.Itoa(s.opts.RetryAfter))
			writeErr(w, 429, "rate_limited", graph)
			return
		}
	case ModeStale:
		graph.Stale = true
	case ModeSample:
		graph.BuildMode = "sample"
	case ModeSlow:
		select {
		case <-time.After(s.opts.Delay):
		case <-r.Context().Done():
			return
		}
	}
	status, payload := route(r)
	body := envelope(payload, graph)
	if mode == ModeTruncated && status == 200 {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(200)
		_, _ = w.Write(body[:len(body)/2])
		return // short of Content-Length, so the server closes the connection
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// Graph is the envelope metadata present in every body.
type Graph struct {
	Version    string                       `json:"version"`
	BuildState string                       `json:"buildState"`
	BuildMode  string                       `json:"buildMode"`
	Stale      bool                         `json:"stale"`
	Sources    map[string]map[string]string `json:"sources"`
}

func envelope(payload map[string]any, g Graph) []byte {
	if g.Sources == nil {
		g.Sources = map[string]map[string]string{
			"cwe":       {"lastSuccess": "2025-01-01T03:00:00Z"},
			"nvd":       {"lastSuccess": "2025-01-01T03:00:00Z"},
			"exploitdb": {"lastSuccess": "2025-01-01T03:00:00Z"},
		}
	}
	out := map[string]any{}
	for k, v := range payload {
		out[k] = v
	}
	out["graph"] = g
	b, _ := json.Marshal(out)
	return b
}

func writeErr(w http.ResponseWriter, status int, code string, g Graph) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(envelope(map[string]any{"error": map[string]any{"code": code, "message": code}}, g))
}
