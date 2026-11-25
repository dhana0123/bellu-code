// Package bskg is the Graph_Mode client for the BSKG REST API (Requirement 17).
// It sends only allow-listed request data, keeps the API key in the
// Authorization header, and maps every failure to a gap cause.
package bskg

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Gap causes of a cve_graph_unavailable gap (Requirement 17.6).
const (
	CauseNotConfigured = "not_configured"
	CauseUnreachable   = "unreachable"
	CauseUnauthorized  = "unauthorized"
	CauseRateLimited   = "rate_limited"
	CauseTimeout       = "timeout"
)

const (
	redactedKey    = "[REDACTED:bskg_key]"
	maxBody        = 8 << 20
	maxRetries     = 3
	maxRetryAfter  = 300 * time.Second
	defaultTimeout = 10 * time.Second
	DefaultLimit   = 25
)

// ErrNotFound is returned for an HTTP 404. It is not a gap.
var ErrNotFound = errors.New("bskg: not found")

// GapError carries the gap cause. Its text never contains the key.
type GapError struct{ Cause string }

func (e *GapError) Error() string { return "bskg: graph unavailable: " + e.Cause }

// Cause returns the gap cause of err, or "" when err is not a gap.
func Cause(err error) string {
	var g *GapError
	if errors.As(err, &g) {
		return g.Cause
	}
	return ""
}

// ValidationError names the offending parameter (Requirement 17.2).
type ValidationError struct{ Param, Reason string }

func (e *ValidationError) Error() string {
	return "bskg: invalid parameter " + e.Param + ": " + e.Reason
}

// Config is the client configuration.
type Config struct {
	URL     string
	Key     string
	Timeout time.Duration
	HTTP    *http.Client
}

// Result is a successful response.
type Result struct {
	Revision string          // graph revision, the cache key in task 33.1
	Warnings []string        // stale and sample conditions (Requirement 17.16)
	Body     json.RawMessage // the response body, including the envelope
}

// Client reads from BSKG.
type Client struct {
	base  *url.URL // nil when not usable
	key   string
	http  *http.Client
	sleep func(context.Context, time.Duration) error
}

// New returns a client. A client whose URL is empty, not https (and not
// loopback), or whose key is empty sends nothing and returns not_configured.
func New(cfg Config) *Client {
	c := &Client{key: strings.TrimSpace(cfg.Key), sleep: sleepCtx}
	c.base = usableURL(cfg.URL)
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	hc := &http.Client{}
	if cfg.HTTP != nil {
		cp := *cfg.HTTP
		hc = &cp
	}
	hc.Timeout = timeout
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	c.http = hc
	return c
}

func usableURL(raw string) *url.URL {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if raw == "" || err != nil || u.User != nil || u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" {
		return nil
	}
	switch u.Scheme {
	case "https":
		return u
	case "http":
		if h := u.Hostname(); h == "localhost" || (net.ParseIP(h) != nil && net.ParseIP(h).IsLoopback()) {
			return u
		}
	}
	return nil
}

var (
	cveRe  = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
	cweRe  = regexp.MustCompile(`^CWE-[0-9]{1,5}$`)
	purlRe = regexp.MustCompile(`^pkg:[a-z0-9.+-]+/[^\s?#]+$`)
	nameRe = regexp.MustCompile(`^[A-Za-z]{1,32}(,[A-Za-z_]{1,32}){0,9}$`)
)

// allowedParams is the complete set of query parameters the client may send.
// id, type, depth, relTypes and nodeTypes select a CVE or CWE id and the graph
// shape for neighbourhood expansion; they carry no local data.
var allowedParams = map[string]bool{
	"q": true, "limit": true, "cursor": true,
	"id": true, "type": true, "depth": true, "relTypes": true, "nodeTypes": true,
}

// StripPurlVersion removes the version, qualifiers and subpath from a purl.
func StripPurlVersion(purl string) string {
	if i := strings.IndexAny(purl, "?#"); i >= 0 {
		purl = purl[:i]
	}
	if at := strings.LastIndex(purl, "@"); at > strings.LastIndex(purl, "/") {
		purl = purl[:at]
	}
	return purl
}

// request is a validated outbound request. Only buildRequest creates one.
type request struct {
	path  string
	query url.Values
}

// buildRequest is the only way to form an outbound request. It rejects any
// parameter outside the allow-list and validates the limit.
func buildRequest(path string, params map[string]string) (request, error) {
	q := url.Values{}
	for k, v := range params {
		if !allowedParams[k] {
			return request{}, &ValidationError{Param: k, Reason: "not an allowed parameter"}
		}
		if k == "limit" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 100 {
				return request{}, &ValidationError{Param: "limit", Reason: "must be an integer from 1 to 100"}
			}
		}
		q.Set(k, v)
	}
	return request{path: path, query: q}, nil
}

func limitParam(limit int) string {
	if limit == 0 {
		limit = DefaultLimit
	}
	return strconv.Itoa(limit)
}

// Vulnerability returns one vulnerability by CVE id (or alias).
func (c *Client) Vulnerability(ctx context.Context, cve string) (Result, error) {
	if !cveRe.MatchString(cve) {
		return Result{}, &ValidationError{Param: "id", Reason: "not a CVE id"}
	}
	r, _ := buildRequest("/v1/vulnerabilities/"+cve, nil)
	return c.do(ctx, r)
}

// Search searches vulnerabilities. limit 0 means the default of 25.
func (c *Client) Search(ctx context.Context, text string, limit int, cursor string) (Result, error) {
	p := map[string]string{"q": text, "limit": limitParam(limit)}
	if cursor != "" {
		p["cursor"] = cursor
	}
	r, err := buildRequest("/v1/vulnerabilities", p)
	if err != nil {
		return Result{}, err
	}
	return c.do(ctx, r)
}

// Weakness returns a CWE with its parents and children (CHILD_OF edges).
func (c *Client) Weakness(ctx context.Context, cwe string) (Result, error) {
	if !cweRe.MatchString(cwe) {
		return Result{}, &ValidationError{Param: "id", Reason: "not a CWE id"}
	}
	r, _ := buildRequest("/v1/weaknesses/"+cwe, nil)
	w, err := c.do(ctx, r)
	if err != nil {
		return Result{}, err
	}
	n, err := c.Neighbourhood(ctx, "Weakness", cwe, 1, []string{"CHILD_OF"}, nil)
	if err != nil {
		return Result{}, err
	}
	out, _ := json.Marshal(map[string]json.RawMessage{"weakness": w.Body, "relations": n.Body})
	w.Body = out
	w.Warnings = merge(w.Warnings, n.Warnings)
	return w, nil
}

// Exploits returns the exploits linked to a CVE.
func (c *Client) Exploits(ctx context.Context, cve string) (Result, error) {
	return c.Neighbourhood(ctx, "Vulnerability", cve, 1, nil, []string{"Exploit"})
}

// AffectedProducts returns the products and vendors affected by a CVE.
func (c *Client) AffectedProducts(ctx context.Context, cve string) (Result, error) {
	return c.Neighbourhood(ctx, "Vulnerability", cve, 1, nil, []string{"Product", "Vendor"})
}

// AffectedPackages returns the vulnerabilities for a package. The version is
// stripped from the purl before it is sent.
func (c *Client) AffectedPackages(ctx context.Context, purl string) (Result, error) {
	purl = StripPurlVersion(purl)
	if !purlRe.MatchString(purl) {
		return Result{}, &ValidationError{Param: "purl", Reason: "not a purl"}
	}
	r, _ := buildRequest("/v1/packages/"+url.PathEscape(purl), nil)
	return c.do(ctx, r)
}

// Neighbourhood expands the graph around a node of type Vulnerability or
// Weakness. depth is 1 or 2.
func (c *Client) Neighbourhood(ctx context.Context, nodeType, id string, depth int, relTypes, nodeTypes []string) (Result, error) {
	switch {
	case nodeType == "Vulnerability" && cveRe.MatchString(id), nodeType == "Weakness" && cweRe.MatchString(id):
	default:
		return Result{}, &ValidationError{Param: "id", Reason: "not a CVE or CWE id for type " + nodeType}
	}
	if depth == 0 {
		depth = 1
	}
	if depth < 1 || depth > 2 {
		return Result{}, &ValidationError{Param: "depth", Reason: "must be 1 or 2"}
	}
	p := map[string]string{"type": nodeType, "id": id, "depth": strconv.Itoa(depth)}
	for k, list := range map[string][]string{"relTypes": relTypes, "nodeTypes": nodeTypes} {
		if len(list) == 0 {
			continue
		}
		v := strings.Join(list, ",")
		if !nameRe.MatchString(v) && !strings.Contains(v, "_") {
			return Result{}, &ValidationError{Param: k, Reason: "invalid list"}
		}
		p[k] = v
	}
	r, err := buildRequest("/v1/graph/neighborhood", p)
	if err != nil {
		return Result{}, err
	}
	return c.do(ctx, r)
}

func merge(a, b []string) []string {
	for _, w := range b {
		dup := false
		for _, x := range a {
			dup = dup || x == w
		}
		if !dup {
			a = append(a, w)
		}
	}
	return a
}

func (c *Client) scrub(s string) string {
	if c.key != "" {
		s = strings.ReplaceAll(s, c.key, redactedKey)
	}
	return s
}

func (c *Client) do(ctx context.Context, r request) (Result, error) {
	if c.base == nil || c.key == "" {
		return Result{}, &GapError{Cause: CauseNotConfigured}
	}
	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/") + r.path
	u.RawPath = ""
	if strings.Contains(r.path, "%") {
		if p, err := url.PathUnescape(r.path); err == nil {
			u.Path = strings.TrimRight(c.base.Path, "/") + p
			u.RawPath = strings.TrimRight(c.base.EscapedPath(), "/") + r.path
		}
	}
	u.RawQuery = r.query.Encode()
	for attempt := 0; ; attempt++ {
		res, retryAfter, err := c.once(ctx, u.String())
		if retryAfter < 0 {
			return res, err
		}
		if attempt >= maxRetries {
			return Result{}, &GapError{Cause: CauseRateLimited}
		}
		if err := c.sleep(ctx, retryAfter); err != nil {
			return Result{}, c.classify(err)
		}
	}
}

// once sends one request. retryAfter >= 0 asks the caller to retry after that wait.
func (c *Client) once(ctx context.Context, target string) (Result, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return Result{}, -1, &GapError{Cause: CauseUnreachable}
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return Result{}, -1, c.classify(err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return Result{}, -1, &GapError{Cause: CauseUnauthorized}
	case resp.StatusCode == http.StatusTooManyRequests:
		return Result{}, parseRetryAfter(resp.Header.Get("Retry-After")), nil
	case resp.StatusCode == http.StatusNotFound:
		return Result{}, -1, ErrNotFound
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return Result{}, -1, &GapError{Cause: CauseUnreachable}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return Result{}, -1, c.classify(err)
	}
	var env struct {
		Graph *struct {
			Version   json.RawMessage `json:"version"`
			BuildMode string          `json:"buildMode"`
			Stale     bool            `json:"stale"`
		} `json:"graph"`
	}
	if len(data) > maxBody || json.Unmarshal(data, &env) != nil || env.Graph == nil {
		return Result{}, -1, &GapError{Cause: CauseUnreachable}
	}
	res := Result{Body: data, Revision: strings.Trim(string(env.Graph.Version), `"`)}
	if env.Graph.Stale {
		res.Warnings = append(res.Warnings, "BSKG reports stale=true: the graph data is out of date")
	}
	if env.Graph.BuildMode == "sample" {
		res.Warnings = append(res.Warnings, "BSKG reports buildMode=sample: the graph holds only a sample of the data")
	}
	return res, -1, nil
}

func (c *Client) classify(err error) error {
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return &GapError{Cause: CauseTimeout}
	}
	return &GapError{Cause: CauseUnreachable}
}

func parseRetryAfter(h string) time.Duration {
	d := time.Second
	if n, err := strconv.Atoi(strings.TrimSpace(h)); err == nil && n >= 0 {
		d = time.Duration(n) * time.Second
	} else if t, err := http.ParseTime(h); err == nil {
		d = max(time.Until(t), 0)
	}
	return min(d, maxRetryAfter)
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
