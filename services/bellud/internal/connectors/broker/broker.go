// Package broker is the only way to call a provider. Every outbound request
// passes one policy http.RoundTripper: policy check, rate limit, credential
// injection, guarded dial, then response redaction, key stripping and size
// caps. A blocked call sends zero bytes and is audited before it returns.
package broker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/audit"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/manifest"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/policy"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/redactor"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/vault"
)

// Limits.
const (
	CallTimeout = 30 * time.Second
	// RatePerSecond is the per-connection request rate.
	RatePerSecond = 10
	// DoMaxBytes caps responses of Do (agent and generic reads).
	DoMaxBytes = 64 << 10
	// ClientMaxBytes caps responses of HTTPClient (collector listings).
	ClientMaxBytes = 16 << 20
	maxPause       = 15 * time.Minute
	maxRedirects   = 5
)

// AuthKind says how the transport authenticates a connection.
type AuthKind string

// Auth kinds.
const (
	// AuthGitHubToken injects "Authorization: Bearer <secret>" from the vault.
	AuthGitHubToken AuthKind = "github-token"
	// AuthAWSVault: the SDK signs with CredentialsProvider (vault backed).
	AuthAWSVault AuthKind = "aws-vault"
	// AuthAWSAmbient: ambient SDK chain, restricted to STS.
	AuthAWSAmbient AuthKind = "aws-ambient"
)

// ConnectionRef is what the broker needs to know about one connection.
type ConnectionRef struct {
	ID          string
	ConnectorID string
	Manifest    manifest.Manifest
	Policy      *policy.Policy
	Auth        AuthKind
	// Credential is the vault slot used for injection (unused for ambient).
	Credential vault.Ref
	// APIHost and BasePath locate the REST API for Do (e.g. api.github.com,
	// or a GHES host with "/api/v3"). Empty APIHost uses the operation host.
	APIHost  string
	BasePath string
}

// Call is one generic read.
type Call struct {
	Connection ConnectionRef
	Caller     string
	Operation  string
	Params     map[string]any
}

// Result is a redacted, key-stripped, size-capped response.
type Result struct {
	Status int
	Header http.Header
	Body   []byte
}

// Typed errors. None carries credential or request data.

// BlockedError means the policy denied the call; nothing was sent.
type BlockedError struct {
	Reason   policy.Reason
	Violated string
}

func (e *BlockedError) Error() string {
	return "broker: blocked (" + string(e.Reason) + ", " + e.Violated + ")"
}

// CredentialError means the credential could not be released; nothing was sent.
type CredentialError struct{ Code string }

func (e *CredentialError) Error() string { return "broker: credential unavailable (" + e.Code + ")" }

// NetworkError is a transport failure or the 30 s deadline.
type NetworkError struct {
	Timeout bool
	cause   error
}

func (e *NetworkError) Error() string {
	if e.Timeout {
		return "broker: network timeout"
	}
	return "broker: network error"
}

// Unwrap exposes only context errors, never transport details.
func (e *NetworkError) Unwrap() error { return e.cause }

// RateLimitedError means the provider asked us to wait longer than the call
// deadline allows; nothing was sent.
type RateLimitedError struct{ RetryAfter time.Duration }

func (e *RateLimitedError) Error() string { return "broker: rate limited" }

// Other sentinel errors.
var (
	ErrTooLarge  = errors.New("broker: response exceeds size cap")
	ErrInternal  = errors.New("broker: internal error")
	ErrBadParams = errors.New("broker: invalid parameters")
)

// Config configures a Broker.
type Config struct {
	Opener   vault.Opener
	Audit    audit.Log
	Redactor *redactor.Redactor
	// Inner is the real transport; nil builds the guarded dialer transport.
	Inner http.RoundTripper
	// Now defaults to time.Now.
	Now func() time.Time
	// RatePerSecond overrides the default of 10 (tests).
	RatePerSecond float64
	// Sleep waits for d or until ctx is done; nil uses a real timer. Tests
	// pair it with Now to drive rate limiting on a fake clock.
	Sleep func(ctx context.Context, d time.Duration) error
	// QueryValidators maps a connector id to a check that a request body of a
	// Query operation (a POST read query such as GraphQL) is read-only. A
	// Query operation of a connector without a validator is blocked (fail
	// closed). The GitHub connector is wired with github.IsGraphQLRequestBody
	// where the broker is constructed (task 10.1); the broker cannot import it.
	QueryValidators map[string]func(body []byte) bool
	// AgentGate supplies the Session_Scope inputs for callers
	// "agent:<principal>". It is consulted before every send, including after
	// a rate-limit wait and on redirect hops, so a scope or live-read change
	// cancels a call that has not been sent yet. Nil denies every agent call.
	AgentGate AgentGate
}

// AgentGate decides the scope inputs of one agent request. Implementations
// must be fast and non-blocking (an atomic snapshot read).
type AgentGate interface {
	AgentInputs(principal, connectionID, connectorID, operation string) policy.AgentInputs
}

// MaxQueryBody bounds the request body inspected for Query operations.
const MaxQueryBody = 1 << 20

// Broker is the only way to call a provider.
type Broker struct {
	cfg   Config
	inner http.RoundTripper
	imds  http.RoundTripper
	rps   float64
	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) error

	mu     sync.Mutex
	states map[string]*connState
}

type connState struct {
	mu    sync.Mutex
	until time.Time
	// sends holds the (possibly reserved, future) send times of the last
	// `limit` requests, in ascending order: a strict sliding 1 s window.
	sends []time.Time
}

// reserve claims the next send slot so that at most limit sends fall in any
// 1 s span. It returns the slot time, or ok=false when the wait exceeds
// maxDelay (nothing is reserved then).
func (s *connState) reserve(now time.Time, limit int, maxDelay time.Duration) (at time.Time, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	at = now
	if len(s.sends) >= limit {
		if w := s.sends[len(s.sends)-limit].Add(time.Second); w.After(at) {
			at = w
		}
	}
	if n := len(s.sends); n > 0 && s.sends[n-1].After(at) {
		at = s.sends[n-1]
	}
	if at.Sub(now) > maxDelay {
		return at, false
	}
	s.sends = append(s.sends, at)
	if len(s.sends) > limit {
		s.sends = append(s.sends[:0], s.sends[len(s.sends)-limit:]...)
	}
	return at, true
}

// release gives back a reserved slot that was never used.
func (s *connState) release(at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.sends) - 1; i >= 0; i-- {
		if s.sends[i].Equal(at) {
			s.sends = append(s.sends[:i], s.sends[i+1:]...)
			return
		}
	}
}

// New returns a Broker.
func New(cfg Config) *Broker {
	b := &Broker{cfg: cfg, states: map[string]*connState{}, now: cfg.Now, rps: cfg.RatePerSecond}
	if b.now == nil {
		b.now = time.Now
	}
	if b.rps <= 0 {
		b.rps = RatePerSecond
	}
	b.sleep = cfg.Sleep
	if b.sleep == nil {
		b.sleep = realSleep
	}
	if cfg.Redactor == nil {
		b.cfg.Redactor = redactor.New()
	}
	b.inner = cfg.Inner
	if b.inner == nil {
		b.inner = newTransport(false)
	}
	return b
}

func realSleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *Broker) state(id string) *connState {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.states[id]
	if s == nil {
		s = &connState{}
		b.states[id] = s
	}
	return s
}

type ctxKey int

const (
	keyOperation ctxKey = iota
	keyMaxBytes
)

// HTTPClient returns a client for SDK wrappers. Its Transport is the policy
// RoundTripper; redirects are limited and every hop is re-checked.
func (b *Broker) HTTPClient(ref ConnectionRef, caller string) *http.Client {
	return &http.Client{
		Transport: newPolicyTransport(b, ref, caller),
		Timeout:   CallTimeout + 5*time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return errors.New("broker: too many redirects")
			}
			return nil
		},
	}
}

// IMDSClient returns a client that may reach only the instance metadata
// service. It exists for the AWS ambient source and returns nil otherwise.
func (b *Broker) IMDSClient(ref ConnectionRef) *http.Client {
	if ref.Auth != AuthAWSAmbient {
		return nil
	}
	return &http.Client{
		Transport: imdsTransport{inner: newTransport(true)},
		Timeout:   5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Do executes one allowlisted REST read.
func (b *Broker) Do(ctx context.Context, c Call) (res Result, err error) {
	defer func() {
		if recover() != nil {
			res, err = Result{}, ErrInternal
		}
	}()
	t := newPolicyTransport(b, c.Connection, c.Caller)
	op, ok := t.ops[c.Operation]
	if !ok || op.Method == "" {
		return Result{}, t.block(ctx, c.Operation, "", "", policy.ReasonOpNotListed, "operation")
	}
	req, err := buildRequest(ctx, c, op)
	if err != nil {
		return Result{}, err
	}
	ctx = context.WithValue(req.Context(), keyOperation, c.Operation)
	ctx = context.WithValue(ctx, keyMaxBytes, DoMaxBytes)
	resp, err := b.HTTPClient(c.Connection, c.Caller).Do(req.WithContext(ctx))
	if err != nil {
		return Result{}, unwrapClientError(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body) // already redacted and capped by the transport
	if err != nil {
		return Result{}, &NetworkError{}
	}
	return Result{Status: resp.StatusCode, Header: resp.Header, Body: body}, nil
}

// unwrapClientError removes the *url.Error wrapper so callers can match typed errors.
func unwrapClientError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	var (
		be *BlockedError
		ce *CredentialError
		ne *NetworkError
		re *RateLimitedError
	)
	switch {
	case errors.As(err, &be):
		return be
	case errors.As(err, &ce):
		return ce
	case errors.As(err, &re):
		return re
	case errors.As(err, &ne):
		return ne
	case errors.Is(err, ErrTooLarge):
		return ErrTooLarge
	case errors.Is(err, ErrInternal):
		return ErrInternal
	}
	return &NetworkError{}
}

func buildRequest(ctx context.Context, c Call, op manifest.Operation) (*http.Request, error) {
	host := c.Connection.APIHost
	if host == "" {
		host = op.Host
	}
	if strings.ContainsAny(host, "{}*") {
		return nil, ErrBadParams
	}
	used := map[string]bool{}
	segs := strings.Split(op.Path, "/")
	for i, s := range segs {
		if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
			name := s[1 : len(s)-1]
			v, ok := c.Params[name]
			if !ok || fmt.Sprint(v) == "" {
				return nil, ErrBadParams
			}
			used[name] = true
			segs[i] = url.PathEscape(fmt.Sprint(v))
		}
	}
	u := url.URL{Scheme: "https", Host: host}
	u.Path = c.Connection.BasePath + strings.Join(segs, "/")
	u.RawPath = ""
	if op.Method == http.MethodGet || op.Method == http.MethodHead || op.Method == http.MethodOptions {
		q := url.Values{}
		keys := make([]string, 0, len(c.Params))
		for k := range c.Params {
			if !used[k] {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			q.Set(k, fmt.Sprint(c.Params[k]))
		}
		u.RawQuery = q.Encode()
		return http.NewRequestWithContext(ctx, op.Method, u.String(), nil)
	}
	// POST read query: parameters are the JSON body.
	body, err := jsonBody(c.Params)
	if err != nil {
		return nil, ErrBadParams
	}
	req, err := http.NewRequestWithContext(ctx, op.Method, u.String(), body)
	if err != nil {
		return nil, ErrBadParams
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}
