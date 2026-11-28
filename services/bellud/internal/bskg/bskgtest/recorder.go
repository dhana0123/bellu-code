package bskgtest

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// RecordedRequest is one request seen by the server. The Authorization value
// is never kept, only whether it was present.
type RecordedRequest struct {
	Method      string
	Path        string
	Query       url.Values
	Header      http.Header // Authorization removed
	AuthPresent bool
}

// Recorder keeps every request.
type Recorder struct {
	mu   sync.Mutex
	reqs []RecordedRequest
}

func (rc *Recorder) record(r *http.Request) {
	h := r.Header.Clone()
	_, auth := h["Authorization"]
	h.Del("Authorization")
	q := r.URL.Query()
	rc.mu.Lock()
	rc.reqs = append(rc.reqs, RecordedRequest{Method: r.Method, Path: r.URL.Path, Query: q, Header: h, AuthPresent: auth})
	rc.mu.Unlock()
}

// Requests returns a copy of the recorded requests in arrival order.
func (rc *Recorder) Requests() []RecordedRequest {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return append([]RecordedRequest(nil), rc.reqs...)
}

// Reset clears the recording.
func (rc *Recorder) Reset() {
	rc.mu.Lock()
	rc.reqs = nil
	rc.mu.Unlock()
}

// Rule allows one method and path. Path segments written as "{name}" match
// any single non-empty segment.
type Rule struct {
	Method string
	Path   string
	Params []string // allowed query parameter names; nil means none
}

// AllowList is the set of requests a client may make.
type AllowList struct {
	Rules []Rule
	// Headers are allowed request header names. Authorization is always
	// allowed. Defaults to Accept, Accept-Encoding, User-Agent and ModeHeader.
	Headers []string
}

var defaultHeaders = []string{"Accept", "Accept-Encoding", "User-Agent", ModeHeader}

func pathMatch(pattern, path string) bool {
	ps, as := strings.Split(strings.Trim(pattern, "/"), "/"), strings.Split(strings.Trim(path, "/"), "/")
	if len(ps) != len(as) {
		return false
	}
	for i := range ps {
		if strings.HasPrefix(ps[i], "{") && strings.HasSuffix(ps[i], "}") {
			if as[i] == "" {
				return false
			}
			continue
		}
		if ps[i] != as[i] {
			return false
		}
	}
	return true
}

// Violations returns one message per offending request. Each names the method
// and path.
func (a AllowList) Violations(reqs []RecordedRequest) []string {
	hdrs := map[string]bool{"Authorization": true}
	list := a.Headers
	if list == nil {
		list = defaultHeaders
	}
	for _, h := range list {
		hdrs[http.CanonicalHeaderKey(h)] = true
	}
	var out []string
	for _, r := range reqs {
		var rule *Rule
		for i := range a.Rules {
			if a.Rules[i].Method == r.Method && pathMatch(a.Rules[i].Path, r.Path) {
				rule = &a.Rules[i]
				break
			}
		}
		if rule == nil {
			out = append(out, fmt.Sprintf("%s %s: method or path not allowed", r.Method, r.Path))
			continue
		}
		okParam := map[string]bool{}
		for _, p := range rule.Params {
			okParam[p] = true
		}
		var bad []string
		for p := range r.Query {
			if !okParam[p] {
				bad = append(bad, "param "+p)
			}
		}
		for h := range r.Header {
			if !hdrs[http.CanonicalHeaderKey(h)] {
				bad = append(bad, "header "+h)
			}
		}
		if len(bad) > 0 {
			sort.Strings(bad)
			out = append(out, fmt.Sprintf("%s %s: not allowed: %s", r.Method, r.Path, strings.Join(bad, ", ")))
		}
	}
	return out
}

// TB is the part of testing.TB the assertion needs.
type TB interface {
	Helper()
	Errorf(format string, args ...any)
}

// AssertAllowed fails t once per request outside the allow-list.
func (rc *Recorder) AssertAllowed(t TB, a AllowList) {
	t.Helper()
	for _, v := range a.Violations(rc.Requests()) {
		t.Errorf("BSKG request outside allow-list: %s", v)
	}
}
