// Package retry is the shared rate-limit retry loop of the cloud collectors
// (GCP, Azure, Kubernetes). It waits 1 s, then doubles up to 60 s, honours a
// Retry-After header, and gives up after 5 retries.
package retry

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

const (
	// InitialDelay is the wait before the first retry.
	InitialDelay = time.Second
	// MaxDelay caps every wait, including a longer Retry-After.
	MaxDelay = 60 * time.Second
	// MaxRetries is the number of retries after the first attempt.
	MaxRetries = 5
)

// ErrRateLimited is matched with errors.Is on the error Do returns after the
// last retry was also rate limited.
var ErrRateLimited = errors.New("rate limited")

// RateLimitError marks one rate-limited response. Do retries only errors that
// wrap a RateLimitError; any other error is returned at once.
type RateLimitError struct {
	// RetryAfter is the server's Retry-After wait; zero when absent.
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string {
	if e.RetryAfter > 0 {
		return "rate limited, retry after " + e.RetryAfter.String()
	}
	return "rate limited"
}

// FromResponse returns a *RateLimitError for a 429 or 503 response and nil for
// every other status. It reads only the headers and does not close the body.
func FromResponse(resp *http.Response, now time.Time) error {
	if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusServiceUnavailable {
		return nil
	}
	return &RateLimitError{RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"), now)}
}

func parseRetryAfter(v string, now time.Time) time.Duration {
	if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil && t.After(now) {
		return t.Sub(now)
	}
	return 0
}

// Option customizes Do.
type Option func(*config)

type config struct {
	initial, max time.Duration
	retries      int
	sleep        func(ctx context.Context, d time.Duration) error
	onWait       func(d time.Duration)
}

// WithSleep replaces the wait, so tests run without real delays.
func WithSleep(f func(ctx context.Context, d time.Duration) error) Option {
	return func(c *config) { c.sleep = f }
}

// WithOnWait is called with each wait before it starts (for example to record
// it with StatusRecorder.Wait).
func WithOnWait(f func(d time.Duration)) Option { return func(c *config) { c.onWait = f } }

// Do calls fn until it succeeds, fails with a non-rate-limit error, or has been
// rate limited 6 times (the first attempt and 5 retries). In the last case the
// error wraps ErrRateLimited and the final RateLimitError.
func Do(ctx context.Context, fn func(ctx context.Context) error, opts ...Option) error {
	c := config{initial: InitialDelay, max: MaxDelay, retries: MaxRetries, sleep: sleep}
	for _, o := range opts {
		o(&c)
	}
	delay := c.initial
	for attempt := 0; ; attempt++ {
		err := fn(ctx)
		var rl *RateLimitError
		if err == nil || !errors.As(err, &rl) {
			return err
		}
		if attempt >= c.retries {
			return fmt.Errorf("%w after %d retries: %w", ErrRateLimited, c.retries, err)
		}
		wait := min(max(delay, rl.RetryAfter), c.max)
		if c.onWait != nil {
			c.onWait(wait)
		}
		if err := c.sleep(ctx, wait); err != nil {
			return err
		}
		delay = min(delay*2, c.max)
	}
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
