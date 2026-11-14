package deviceflow

import (
	"testing"
	"time"

	"pgregory.net/rapid"
)

// Feature: github-app-signin, Property 8: The poll schedule never polls faster than the interval
//
// For any starting interval, any sequence of Pending and SlowDown outcomes and
// any GitHub-reported interval (or none), every non-terminal Step.Delay is at
// least the current interval, the interval never decreases, a SlowDown makes
// the interval strictly larger, and a missing interval defaults to 5 seconds.
//
// **Validates: Requirements 3.1, 3.2, 3.3**
func TestProperty8PollScheduleNeverFasterThanInterval(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// A zero starting interval means "GitHub sent none".
		start := time.Duration(rapid.Int64Range(0, 120_000).Draw(t, "startMs")) * time.Millisecond
		p := Poller{Interval: start}
		prev := start
		if prev <= 0 {
			prev = DefaultInterval
		}
		outcomes := rapid.IntRange(1, 40).Draw(t, "n")
		for i := 0; i < outcomes; i++ {
			o := Outcome{Kind: rapid.SampledFrom([]OutcomeKind{Pending, SlowDown}).Draw(t, "kind")}
			if o.Kind == SlowDown && rapid.Bool().Draw(t, "hasInterval") {
				o.NewInterval = time.Duration(rapid.Int64Range(1, 300_000).Draw(t, "newMs")) * time.Millisecond
			}
			// Far-future expiry so the step is never terminal.
			st := p.Next(o, 1000*time.Hour)
			if st.Terminal {
				t.Fatalf("unexpected terminal step for %+v: %+v", o, st)
			}
			cur := st.Poller.Interval
			if st.Delay < cur {
				t.Fatalf("delay %v below interval %v after %+v", st.Delay, cur, o)
			}
			if cur < prev {
				t.Fatalf("interval decreased from %v to %v after %+v", prev, cur, o)
			}
			if o.Kind == SlowDown && cur <= prev {
				t.Fatalf("slow_down did not increase interval: %v -> %v (%+v)", prev, cur, o)
			}
			if o.Kind == SlowDown && o.NewInterval > prev && cur != o.NewInterval {
				t.Fatalf("slow_down larger interval not adopted: prev %v, got %v, want %v", prev, cur, o.NewInterval)
			}
			if i == 0 && start <= 0 && o.Kind == Pending && (cur != 5*time.Second || st.Delay != 5*time.Second) {
				t.Fatalf("missing interval did not default to 5s: %+v", st)
			}
			p, prev = st.Poller, cur
		}
	})
}
