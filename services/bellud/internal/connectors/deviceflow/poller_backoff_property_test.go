package deviceflow

import (
	"testing"
	"time"

	"pgregory.net/rapid"
)

// Feature: github-app-signin, Property 9: Network backoff is bounded, monotone and resets
//
// For any interval and any run of consecutive network failures, the delay after
// the n-th failure equals min(interval * 2^(n-1), 60 s), is non-decreasing,
// never exceeds 60 seconds, and returns to the current interval after the next
// successful poll. When the next delay would pass the expiry, the step is
// terminal with code network.
//
// **Validates: Requirements 3.9**
func TestProperty9NetworkBackoffBoundedMonotoneResets(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		interval := time.Duration(rapid.IntRange(1, 120).Draw(t, "intervalSec")) * time.Second
		n := rapid.IntRange(1, 40).Draw(t, "failures")
		p := Poller{Interval: interval}

		var prev time.Duration
		for i := 1; i <= n; i++ {
			st := p.Next(Outcome{Kind: NetworkFailure}, 24*time.Hour)
			if st.Terminal {
				t.Fatalf("failure %d terminal with ample time: %+v", i, st)
			}
			want := interval
			for j := 1; j < i && want < MaxBackoff; j++ {
				want *= 2
			}
			want = min(want, MaxBackoff)
			if st.Delay != want {
				t.Fatalf("failure %d interval %v: delay %v, want %v", i, interval, st.Delay, want)
			}
			if st.Delay > MaxBackoff {
				t.Fatalf("delay %v exceeds cap", st.Delay)
			}
			if st.Delay < prev {
				t.Fatalf("delay decreased: %v -> %v", prev, st.Delay)
			}
			if st.Poller.Failures != i || st.Poller.Interval != interval {
				t.Fatalf("state after failure %d: %+v", i, st.Poller)
			}
			prev = st.Delay
			p = st.Poller
		}

		// Expiry: a backoff delay not shorter than the remaining time is terminal "network".
		delay := prev
		extra := time.Duration(rapid.IntRange(0, 10).Draw(t, "extraSec")) * time.Second
		st := p.Next(Outcome{Kind: NetworkFailure}, delay+extra)
		next := backoff(interval, n+1)
		if next >= delay+extra {
			if !st.Terminal || st.Reason != NetworkFailure {
				t.Fatalf("expected terminal network at remaining %v: %+v", delay+extra, st)
			}
		}
		short := rapid.Int64Range(1, int64(next)).Draw(t, "remainingNs")
		st = p.Next(Outcome{Kind: NetworkFailure}, time.Duration(short))
		if !st.Terminal || st.Reason != NetworkFailure {
			t.Fatalf("delay %v >= remaining %v must be terminal network: %+v", next, short, st)
		}

		// Reset: a successful (pending) poll returns to the current interval.
		st = p.Next(Outcome{Kind: Pending}, 24*time.Hour)
		if st.Terminal || st.Delay != interval || st.Poller.Failures != 0 {
			t.Fatalf("pending after failures: %+v", st)
		}
		// And the next failure restarts the series at the interval (capped).
		st = st.Poller.Next(Outcome{Kind: NetworkFailure}, 24*time.Hour)
		if st.Delay != min(interval, MaxBackoff) || st.Poller.Failures != 1 {
			t.Fatalf("restart after reset: %+v", st)
		}
	})
}
