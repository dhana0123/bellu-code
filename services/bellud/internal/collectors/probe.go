package collectors

import (
	"context"
	"fmt"
	"time"
)

// Probe failure kinds, reported in ProbeError.Kind.
const (
	ProbeCredentialsRejected = "credentials_rejected"
	ProbeEndpointUnreachable = "endpoint_unreachable"
)

// ProbeAttempts is the number of consecutive failures that fail a run.
const ProbeAttempts = 3

// ProbeError ends a run before any resource was read. The collector returns it
// from Collect without a batch, so the runner applies nothing and the graph
// keeps its data. It unwraps to the last failure.
type ProbeError struct {
	Kind string
	Err  error
}

func (e *ProbeError) Error() string { return e.Kind + ": " + e.Err.Error() }
func (e *ProbeError) Unwrap() error { return e.Err }

// ProbeOption customizes Probe.
type ProbeOption func(*probeConfig)

type probeConfig struct {
	delay time.Duration
	sleep func(ctx context.Context, d time.Duration) error
}

// WithProbeSleep replaces the wait between attempts (default 1 s), for tests.
func WithProbeSleep(f func(ctx context.Context, d time.Duration) error) ProbeOption {
	return func(c *probeConfig) { c.sleep = f }
}

// Probe runs check, a cheap read-only call such as a project, subscription or
// /version lookup, at the start of a run. It returns nil on the first success.
// After 3 consecutive failures it returns *ProbeError whose Kind is
// credentials_rejected for HTTP 401/403 (ClassifyGap says missing_permission)
// and endpoint_unreachable otherwise, judged by the last failure. A cancelled
// context returns the context error.
func Probe(ctx context.Context, check func(ctx context.Context) error, opts ...ProbeOption) error {
	c := probeConfig{delay: time.Second, sleep: func(ctx context.Context, d time.Duration) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d):
			return nil
		}
	}}
	for _, o := range opts {
		o(&c)
	}
	var last error
	for i := 0; i < ProbeAttempts; i++ {
		if i > 0 {
			if err := c.sleep(ctx, c.delay); err != nil {
				return err
			}
		}
		if last = check(ctx); last == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	kind := ProbeEndpointUnreachable
	if ClassifyGap(last) == GapMissingPermission {
		kind = ProbeCredentialsRejected
	}
	return &ProbeError{Kind: kind, Err: fmt.Errorf("%d consecutive failures: %w", ProbeAttempts, last)}
}
