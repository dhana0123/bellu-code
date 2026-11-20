// Package cveupdate fetches the signed CVE snapshot index and packs.
//
// It is the only package allowed to make outbound requests to a CVE host
// (Requirement 19.15). Requests are GET or HEAD only, carry no query string,
// cookie, authorization header or body, and send only Host, If-None-Match,
// Accept and a fixed User-Agent.
package cveupdate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultHost is the default CVE host. The index lives at <host>/cve/v1/index.json.
const DefaultHost = "https://cve.bellu.dev"

const (
	indexPath      = "/cve/v1/index.json"
	pathPrefix     = "/cve/v1/"
	connectTimeout = 10 * time.Second
	totalTimeout   = 300 * time.Second
	extraRetries   = 2
	retryWait      = 5 * time.Second
	acceptIndex    = "application/json"
	acceptPack     = "application/octet-stream"
)

// ErrMirror is wrapped by every error caused by a configured mirror.
var ErrMirror = errors.New("cve mirror failed")

// ErrNotModified is returned by FetchIndex when the host answered 304.
var ErrNotModified = errors.New("index not modified")

// Config configures a Client.
type Config struct {
	// Host overrides DefaultHost. Ignored when MirrorURL is set.
	Host string
	// MirrorURL, when set, receives every request. There is no fallback.
	MirrorURL string
	// Version is the bellucode version used in the User-Agent.
	Version string
	// UserAgent is cve.user_agent. When UserAgentSet is true and UserAgent is
	// empty, the User-Agent header is sent empty.
	UserAgent    string
	UserAgentSet bool

	// Test hooks. Zero values use the fixed production values.
	Transport http.RoundTripper
	Sleep     func(context.Context, time.Duration) error
}

// Client is the HTTP client for the CVE host or mirror.
type Client struct {
	base      *url.URL
	mirror    bool
	userAgent string
	http      *http.Client
	sleep     func(context.Context, time.Duration) error
}

// Response is a fetched object. Body must be closed by the caller.
type Response struct {
	Body   io.ReadCloser
	ETag   string
	Length int64
}

// New validates cfg and builds a Client.
func New(cfg Config) (*Client, error) {
	raw, mirror := cfg.Host, false
	if raw == "" {
		raw = DefaultHost
	}
	if cfg.MirrorURL != "" {
		raw, mirror = cfg.MirrorURL, true
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" ||
		u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, fmt.Errorf("invalid CVE host URL %q", raw)
	}
	u.Path = strings.TrimRight(u.Path, "/")

	ua := cfg.UserAgent
	if !cfg.UserAgentSet && ua == "" {
		ua = "bellu-cve-update/" + cfg.Version
	}

	rt := cfg.Transport
	if rt == nil {
		rt = &http.Transport{
			DialContext:         (&net.Dialer{Timeout: connectTimeout}).DialContext,
			TLSHandshakeTimeout: connectTimeout,
			DisableCompression:  true, // no Accept-Encoding header
			Proxy:               http.ProxyFromEnvironment,
		}
	}
	sleep := cfg.Sleep
	if sleep == nil {
		sleep = sleepCtx
	}
	return &Client{
		base: u, mirror: mirror, userAgent: ua, sleep: sleep,
		http: &http.Client{
			Transport: rt,
			Timeout:   totalTimeout,
			// A redirect could leave the chosen host, so none is followed.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Jar:           nil,
		},
	}, nil
}

// IndexURL returns the fixed index URL.
func (c *Client) IndexURL() string { return c.base.String() + indexPath }

// ResolvePackURL maps a pack reference from the index to a request URL. With a
// mirror configured, the result always points at the mirror.
func (c *Client) ResolvePackURL(ref string) (string, error) {
	r, err := url.Parse(ref)
	if err != nil || ref == "" {
		return "", fmt.Errorf("invalid pack URL %q", ref)
	}
	if r.RawQuery != "" || r.ForceQuery || r.Fragment != "" || r.User != nil {
		return "", fmt.Errorf("pack URL %q must not carry a query, fragment or credentials", ref)
	}
	var path string
	switch {
	case r.Host == "" && r.Scheme == "":
		if strings.HasPrefix(r.Path, "/") {
			path = r.Path
		} else {
			path = pathPrefix + r.Path
		}
	case r.Scheme == "https" || r.Scheme == "http":
		if !c.mirror && !sameHost(r, c.base) {
			return "", fmt.Errorf("pack URL %q is not on host %s", ref, c.base.Host)
		}
		path = r.Path
	default:
		return "", fmt.Errorf("unsupported pack URL scheme in %q", ref)
	}
	if strings.Contains(path, "..") {
		return "", fmt.Errorf("pack URL %q contains a path traversal", ref)
	}
	return c.base.String() + path, nil
}

func sameHost(a, b *url.URL) bool {
	return strings.EqualFold(a.Host, b.Host) && a.Scheme == b.Scheme
}

// FetchIndex requests index.json with If-None-Match set to etag (when
// non-empty). On 304 it returns ErrNotModified.
func (c *Client) FetchIndex(ctx context.Context, etag string) (*Response, error) {
	return c.do(ctx, http.MethodGet, c.IndexURL(), etag, acceptIndex)
}

// FetchPack downloads the pack or signature named by ref.
func (c *Client) FetchPack(ctx context.Context, ref string) (*Response, error) {
	u, err := c.ResolvePackURL(ref)
	if err != nil {
		return nil, err
	}
	return c.do(ctx, http.MethodGet, u, "", acceptPack)
}

// HeadPack issues a HEAD for the pack named by ref.
func (c *Client) HeadPack(ctx context.Context, ref string) (*Response, error) {
	u, err := c.ResolvePackURL(ref)
	if err != nil {
		return nil, err
	}
	return c.do(ctx, http.MethodHead, u, "", acceptPack)
}

func (c *Client) do(ctx context.Context, method, target, etag, accept string) (*Response, error) {
	var last error
	for attempt := 0; attempt <= extraRetries; attempt++ {
		if attempt > 0 {
			if err := c.sleep(ctx, retryWait); err != nil {
				return nil, c.wrap(err)
			}
		}
		resp, retry, err := c.once(ctx, method, target, etag, accept)
		if err == nil {
			return resp, nil
		}
		if errors.Is(err, ErrNotModified) {
			return nil, err
		}
		last = err
		if !retry || ctx.Err() != nil {
			break
		}
	}
	return nil, c.wrap(last)
}

// once performs a single attempt. retry reports whether the failure is a
// timeout, connection error, or 5xx.
func (c *Client) once(ctx context.Context, method, target, etag, accept string) (*Response, bool, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return nil, false, err
	}
	// Set User-Agent explicitly (even empty) so Go does not add its default.
	req.Header["User-Agent"] = []string{c.userAgent}
	req.Header.Set("Accept", accept)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, true, err
	}
	switch {
	case resp.StatusCode == http.StatusNotModified && etag != "":
		resp.Body.Close()
		return nil, false, ErrNotModified
	case resp.StatusCode == http.StatusOK:
		return &Response{Body: resp.Body, ETag: resp.Header.Get("ETag"), Length: resp.ContentLength}, false, nil
	default:
		resp.Body.Close()
		return nil, resp.StatusCode >= 500, fmt.Errorf("%s %s: unexpected status %d", method, target, resp.StatusCode)
	}
}

func (c *Client) wrap(err error) error {
	if err == nil || !c.mirror {
		return err
	}
	return fmt.Errorf("%w: mirror %s: %v", ErrMirror, c.base.String(), err)
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
