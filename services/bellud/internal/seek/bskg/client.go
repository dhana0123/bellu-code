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

	"github.com/bellu/bellucode/services/bellud/internal/seek"
)

// Error categories. They carry no URL, key or response body. They are the
// seek package's sentinels so the Retriever can classify them without
// importing this package.
var (
	ErrNotFound     = seek.ErrNotFound
	ErrUnconfigured = seek.ErrUnconfigured
	ErrUnreachable  = seek.ErrUnreachable
	ErrTimeout      = seek.ErrTimeout
	ErrAuth         = seek.ErrAuth
)

const (
	maxBody        = 2 << 20
	defaultTimeout = 10 * time.Second
)

var (
	cweRe = regexp.MustCompile(`^CWE-[0-9]{1,5}$`)
	cveRe = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
)

// Client reads from BSKG. It only issues GET requests to the five endpoints
// the seek tool needs and implements seek.Source.
type Client struct {
	base *url.URL
	key  string
	http *http.Client
}

var _ seek.Source = (*Client)(nil)

// New returns a client, or ErrUnconfigured when cfg is not usable.
func New(cfg Config) (*Client, error) {
	base, ok := cfg.baseURL()
	if !ok || strings.TrimSpace(string(cfg.Key)) == "" {
		return nil, ErrUnconfigured
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Proxies only see https traffic; the key must not cross one in clear text.
	transport.Proxy = func(r *http.Request) (*url.URL, error) {
		if r.URL.Scheme != "https" {
			return nil, nil
		}
		return http.ProxyFromEnvironment(r)
	}
	return &Client{
		base: base,
		key:  strings.TrimSpace(string(cfg.Key)),
		http: &http.Client{
			Timeout:       timeout,
			Transport:     transport,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func (c *Client) Weakness(ctx context.Context, cwe string) (seek.WeaknessInfo, error) {
	if !cweRe.MatchString(cwe) {
		return seek.WeaknessInfo{}, ErrNotFound
	}
	var body struct {
		Weakness *struct {
			CWEID string `json:"cweID"`
			Name  string `json:"name"`
		} `json:"weakness"`
	}
	if err := c.get(ctx, "/v1/weaknesses/"+cwe, nil, &body); err != nil {
		return seek.WeaknessInfo{}, err
	}
	if body.Weakness == nil || body.Weakness.CWEID == "" {
		return seek.WeaknessInfo{}, ErrUnreachable
	}
	return seek.WeaknessInfo{CWEID: body.Weakness.CWEID, Name: body.Weakness.Name}, nil
}

// Children returns the CHILD_OF edges (child to parent) within depth of cwe.
func (c *Client) Children(ctx context.Context, cwe string, depth int) ([]seek.Edge, error) {
	if !cweRe.MatchString(cwe) {
		return nil, ErrNotFound
	}
	q := url.Values{"type": {"Weakness"}, "id": {cwe}, "depth": {strconv.Itoa(max(depth, 1))}, "relTypes": {"CHILD_OF"}}
	var body struct {
		Edges *[]struct {
			Source string `json:"source"`
			Target string `json:"target"`
			Type   string `json:"type"`
		} `json:"edges"`
	}
	if err := c.get(ctx, "/v1/graph/neighborhood", q, &body); err != nil {
		return nil, err
	}
	if body.Edges == nil {
		return nil, ErrUnreachable
	}
	edges := []seek.Edge{}
	for _, e := range *body.Edges {
		child, parent := strings.TrimPrefix(e.Source, "Weakness:"), strings.TrimPrefix(e.Target, "Weakness:")
		if e.Type == "CHILD_OF" && cweRe.MatchString(child) && cweRe.MatchString(parent) {
			edges = append(edges, seek.Edge{Child: child, Parent: parent})
		}
	}
	return edges, nil
}

func (c *Client) WeaknessVulns(ctx context.Context, cwe string, limit int) ([]seek.VulnRef, error) {
	if !cweRe.MatchString(cwe) {
		return nil, ErrNotFound
	}
	q := url.Values{"limit": {strconv.Itoa(max(limit, 1))}}
	var body struct {
		Items *[]struct {
			CVEID string   `json:"cveID"`
			CVSS  *float64 `json:"v3baseScore"`
		} `json:"items"`
	}
	if err := c.get(ctx, "/v1/weaknesses/"+cwe+"/vulnerabilities", q, &body); err != nil {
		return nil, err
	}
	if body.Items == nil {
		return nil, ErrUnreachable
	}
	refs := []seek.VulnRef{}
	for _, it := range *body.Items {
		if cveRe.MatchString(it.CVEID) {
			refs = append(refs, seek.VulnRef{CVEID: it.CVEID, CVSS: it.CVSS, CWEID: cwe})
		}
	}
	return refs, nil
}

func (c *Client) Vulnerability(ctx context.Context, id string) (seek.VulnDetail, error) {
	if !cveRe.MatchString(id) {
		return seek.VulnDetail{}, ErrNotFound
	}
	var body struct {
		Vulnerability *struct {
			CVEID       string   `json:"cveID"`
			Description string   `json:"description"`
			CVSS        *float64 `json:"v3baseScore"`
			KEV         bool     `json:"kev"`
			EPSS        *float64 `json:"epssScore"`
		} `json:"vulnerability"`
		FixCommits []struct {
			SHA     string `json:"sha"`
			RepoURL string `json:"repoUrl"`
		} `json:"fixCommits"`
	}
	if err := c.get(ctx, "/v1/vulnerabilities/"+id, nil, &body); err != nil {
		return seek.VulnDetail{}, err
	}
	v := body.Vulnerability
	if v == nil || v.CVEID == "" {
		return seek.VulnDetail{}, ErrUnreachable
	}
	d := seek.VulnDetail{CVEID: v.CVEID, Description: v.Description, CVSS: v.CVSS, KEV: v.KEV, EPSS: v.EPSS}
	if len(body.FixCommits) > 0 {
		d.FixCommit, d.Repository = body.FixCommits[0].SHA, body.FixCommits[0].RepoURL
	}
	return d, nil
}

// Status checks that BSKG answers on /v1/status.
func (c *Client) Status(ctx context.Context) error {
	var body struct {
		BuildState string `json:"buildState"`
	}
	if err := c.get(ctx, "/v1/status", nil, &body); err != nil {
		return err
	}
	if body.BuildState == "" {
		return ErrUnreachable
	}
	return nil
}

// get issues one GET and decodes the JSON body into out. Every failure is
// mapped to a category error so nothing from the request or response leaks.
func (c *Client) get(ctx context.Context, path string, query url.Values, out any) error {
	if c == nil || c.http == nil {
		return ErrUnconfigured
	}
	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/") + path
	u.RawPath = ""
	u.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return ErrUnreachable
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return classify(err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return ErrAuth
	case resp.StatusCode == http.StatusNotFound:
		return ErrNotFound
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return ErrUnreachable
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return classify(err)
	}
	if len(data) > maxBody || json.Unmarshal(data, out) != nil {
		return ErrUnreachable
	}
	return nil
}

func classify(err error) error {
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return ErrTimeout
	}
	return ErrUnreachable
}
