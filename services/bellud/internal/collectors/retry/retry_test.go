package retry_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/collectors/retry"
)

func recorder(waits *[]time.Duration) []retry.Option {
	return []retry.Option{retry.WithSleep(func(_ context.Context, d time.Duration) error { *waits = append(*waits, d); return nil })}
}

func TestDoBacksOffAndGivesUpAfterFiveRetries(t *testing.T) {
	var waits []time.Duration
	calls := 0
	err := retry.Do(context.Background(), func(context.Context) error { calls++; return &retry.RateLimitError{} }, recorder(&waits)...)
	if !errors.Is(err, retry.ErrRateLimited) || calls != 6 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second}
	for i, w := range want {
		if waits[i] != w {
			t.Fatalf("waits=%v", waits)
		}
	}
}

func TestDoHonoursRetryAfterWithCap(t *testing.T) {
	var waits []time.Duration
	n := 0
	err := retry.Do(context.Background(), func(context.Context) error {
		n++
		switch n {
		case 1:
			return &retry.RateLimitError{RetryAfter: 30 * time.Second}
		case 2:
			return &retry.RateLimitError{RetryAfter: time.Hour}
		}
		return nil
	}, recorder(&waits)...)
	if err != nil || waits[0] != 30*time.Second || waits[1] != retry.MaxDelay {
		t.Fatalf("err=%v waits=%v", err, waits)
	}
}

func TestDoReturnsOtherErrorsAtOnce(t *testing.T) {
	boom := errors.New("boom")
	calls := 0
	err := retry.Do(context.Background(), func(context.Context) error { calls++; return boom }, retry.WithSleep(nil))
	if err != boom || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestFromResponse(t *testing.T) {
	now := time.Now()
	resp := &http.Response{StatusCode: 429, Header: http.Header{"Retry-After": {"7"}}}
	var rl *retry.RateLimitError
	if err := retry.FromResponse(resp, now); !errors.As(err, &rl) || rl.RetryAfter != 7*time.Second {
		t.Fatalf("got %v", err)
	}
	if retry.FromResponse(&http.Response{StatusCode: 200}, now) != nil {
		t.Fatal("200 must not be rate limited")
	}
}
