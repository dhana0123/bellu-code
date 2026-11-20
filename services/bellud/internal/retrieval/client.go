// Package retrieval is the Go client for the local Python retrieval service
// (services/retrieval). The service listens on a Unix domain socket, or on
// loopback with a random per-run token where no socket exists. This package
// does not import any outbound HTTP target: it dials only that local endpoint.
package retrieval

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// TokenHeader carries the per-run token.
const TokenHeader = "X-Bellu-Retrieval-Token"

// Stage names map to the service routes.
const (
	StagePlan     = "plan"
	StageRetrieve = "retrieve"
	StageRank     = "rank"
	StageSelect   = "select"
	StageCompile  = "compile"
)

var stages = map[string]bool{StagePlan: true, StageRetrieve: true, StageRank: true, StageSelect: true, StageCompile: true}

// CodeUnavailable is the error code returned to API callers when the service is down.
const CodeUnavailable = "retrieval_unavailable"

// ErrUnavailable means the retrieval service is down, unreachable or failing.
var ErrUnavailable = errors.New("retrieval_unavailable")

var errTransport = errors.New("transport failure")

// ErrAuth means the service rejected the per-run token.
var ErrAuth = errors.New("retrieval: authentication failed")

// NewToken returns a random per-run token.
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Client calls the retrieval service.
type Client struct {
	hc    *http.Client
	token string
	base  string
}

// NewUnix returns a client for a service on a Unix domain socket.
func NewUnix(socketPath, token string) *Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
		DisableKeepAlives: true,
	}
	return &Client{hc: &http.Client{Transport: tr}, token: token, base: "http://retrieval.local"}
}

// NewLoopback returns a client for a service on a loopback address. A
// non-loopback address is refused.
func NewLoopback(addr, token string) (*Client, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("retrieval: bad address %q: %w", addr, err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("retrieval: %q is not a loopback address", addr)
	}
	return &Client{
		hc:    &http.Client{Transport: &http.Transport{DisableKeepAlives: true}},
		token: token,
		base:  "http://" + addr,
	}, nil
}

// Call posts req to the stage and decodes the JSON response into resp (may be nil).
// A transport failure, a 5xx response or a 503 returns an error wrapping ErrUnavailable.
func (c *Client) Call(ctx context.Context, stage string, req, resp any) error {
	if !stages[stage] {
		return fmt.Errorf("retrieval: unknown stage %q", stage)
	}
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/v1/"+stage, bytes.NewReader(body))
	if err != nil {
		return err
	}
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set(TokenHeader, c.token)
	out, err := c.hc.Do(hr)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("%w: %w", ErrUnavailable, errTransport)
	}
	defer out.Body.Close()
	data, err := io.ReadAll(io.LimitReader(out.Body, 16<<20))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	switch {
	case out.StatusCode == http.StatusUnauthorized:
		return ErrAuth
	case out.StatusCode >= 500 && out.StatusCode != http.StatusNotImplemented:
		return fmt.Errorf("%w: status %d", ErrUnavailable, out.StatusCode)
	case out.StatusCode != http.StatusOK:
		return fmt.Errorf("retrieval: %s: status %d: %s", stage, out.StatusCode, strings.TrimSpace(string(data)))
	}
	if resp == nil {
		return nil
	}
	return json.Unmarshal(data, resp)
}

// Plan, Retrieve, Rank, Select and Compile are typed-by-caller wrappers.
func (c *Client) Plan(ctx context.Context, req, resp any) error {
	return c.Call(ctx, StagePlan, req, resp)
}
func (c *Client) Retrieve(ctx context.Context, req, resp any) error {
	return c.Call(ctx, StageRetrieve, req, resp)
}
func (c *Client) Rank(ctx context.Context, req, resp any) error {
	return c.Call(ctx, StageRank, req, resp)
}
func (c *Client) Select(ctx context.Context, req, resp any) error {
	return c.Call(ctx, StageSelect, req, resp)
}
func (c *Client) Compile(ctx context.Context, req, resp any) error {
	return c.Call(ctx, StageCompile, req, resp)
}

// UnavailableBody is the JSON body of a 503 retrieval_unavailable response.
type UnavailableBody struct {
	Error string `json:"error"`
}

// WriteUnavailable writes `503 retrieval_unavailable`.
func WriteUnavailable(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(UnavailableBody{Error: CodeUnavailable})
}

// ExactLookup answers an exact-identifier lookup (CVE id, purl, ARN, ...)
// from Go, without the retrieval service.
type ExactLookup func(ctx context.Context, identifier string) (any, error)

// Gateway fronts the service. Staged retrieval needs the service; exact
// lookups never do (Requirement 9.9).
type Gateway struct {
	Client *Client
	Exact  ExactLookup
}

// Lookup answers an exact identifier from Go, whether or not the service is up.
func (g *Gateway) Lookup(ctx context.Context, identifier string) (any, error) {
	if g.Exact == nil {
		return nil, errors.New("retrieval: no exact lookup configured")
	}
	return g.Exact(ctx, identifier)
}

// Stage runs one service stage. When the service is down it returns an error
// wrapping ErrUnavailable; callers map that to 503 with HandleError.
func (g *Gateway) Stage(ctx context.Context, stage string, req, resp any) error {
	if g.Client == nil {
		return ErrUnavailable
	}
	return g.Client.Call(ctx, stage, req, resp)
}

// HandleError writes 503 retrieval_unavailable for an unavailable service and
// reports whether it handled err.
func HandleError(w http.ResponseWriter, err error) bool {
	if errors.Is(err, ErrUnavailable) {
		WriteUnavailable(w)
		return true
	}
	return false
}

// WaitReady polls until the stage endpoint answers (any HTTP status other than
// transport failure), or the timeout passes.
func (c *Client) WaitReady(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		err := c.Call(ctx, StagePlan, map[string]any{}, nil)
		if !errors.Is(err, errTransport) {
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}
