package deviceflow

import (
	"testing"
	"time"
)

const long = time.Hour

func TestPollerSchedule(t *testing.T) {
	s := time.Second
	p := Poller{}

	st := p.Next(Outcome{Kind: Pending}, long)
	if st.Delay != 5*s || st.Poller.Interval != 5*s {
		t.Fatalf("default interval: %+v", st)
	}

	st = st.Poller.Next(Outcome{Kind: SlowDown}, long)
	if st.Delay != 10*s {
		t.Fatalf("slow_down +5s: %+v", st)
	}
	st = st.Poller.Next(Outcome{Kind: SlowDown, NewInterval: 30 * s}, long)
	if st.Poller.Interval != 30*s {
		t.Fatalf("slow_down larger: %+v", st)
	}
	st = st.Poller.Next(Outcome{Kind: SlowDown, NewInterval: 10 * s}, long)
	if st.Poller.Interval != 35*s {
		t.Fatalf("slow_down smaller: %+v", st)
	}
	st = st.Poller.Next(Outcome{Kind: Pending}, long)
	if st.Poller.Interval != 35*s {
		t.Fatalf("pending keeps interval: %+v", st)
	}

	q := Poller{Interval: 5 * s}
	want := []time.Duration{5 * s, 10 * s, 20 * s, 40 * s, 60 * s, 60 * s}
	for i, w := range want {
		st = q.Next(Outcome{Kind: NetworkFailure}, long)
		if st.Delay != w || st.Poller.Failures != i+1 {
			t.Fatalf("backoff %d: %+v", i, st)
		}
		q = st.Poller
	}
	st = q.Next(Outcome{Kind: Pending}, long)
	if st.Delay != 5*s || st.Poller.Failures != 0 {
		t.Fatalf("reset: %+v", st)
	}

	st = Poller{Interval: 5 * s}.Next(Outcome{Kind: RateLimited, RetryAfter: 20 * s}, long)
	if st.Delay != 20*s || st.Poller.Failures != 0 {
		t.Fatalf("rate limit: %+v", st)
	}
	st = Poller{Interval: 30 * s}.Next(Outcome{Kind: RateLimited, RetryAfter: 2 * s}, long)
	if st.Delay != 30*s {
		t.Fatalf("rate limit floor: %+v", st)
	}
}

func TestPollerTerminal(t *testing.T) {
	for _, k := range []OutcomeKind{Token, Expired, Denied, Disabled, Misconfigured} {
		if st := (Poller{}).Next(Outcome{Kind: k}, long); !st.Terminal || st.Reason != k {
			t.Fatalf("kind %d: %+v", k, st)
		}
	}
	s := time.Second
	if st := (Poller{}).Next(Outcome{Kind: NetworkFailure}, 5*s); !st.Terminal || st.Reason != NetworkFailure {
		t.Fatalf("network cutoff: %+v", st)
	}
	if st := (Poller{}).Next(Outcome{Kind: RateLimited, RetryAfter: time.Minute}, 30*s); !st.Terminal || st.Reason != RateLimited {
		t.Fatalf("rate cutoff: %+v", st)
	}
	if st := (Poller{}).Next(Outcome{Kind: Pending}, 4*s); !st.Terminal || st.Reason != Expired {
		t.Fatalf("pending cutoff: %+v", st)
	}
	if st := (Poller{}).Next(Outcome{Kind: Pending}, 6*s); st.Terminal {
		t.Fatalf("should continue: %+v", st)
	}
}
