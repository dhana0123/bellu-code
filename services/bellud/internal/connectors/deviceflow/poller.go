// Package deviceflow holds the GitHub device-flow polling schedule.
package deviceflow

import "time"

const (
	// DefaultInterval is used when GitHub returns no interval (Req 3.1).
	DefaultInterval = 5 * time.Second
	// SlowDownStep is added to the interval on slow_down when GitHub sends no larger value (Req 3.2).
	SlowDownStep = 5 * time.Second
	// MaxBackoff caps the network failure backoff.
	MaxBackoff = 60 * time.Second
)

// OutcomeKind classifies the result of one poll.
type OutcomeKind int

const (
	Pending OutcomeKind = iota
	SlowDown
	Token
	Expired
	Denied
	Disabled
	Misconfigured
	NetworkFailure
	RateLimited
)

// Poller is the schedule state. The zero Interval means DefaultInterval.
type Poller struct {
	Interval time.Duration // current minimum spacing between polls
	Failures int           // consecutive network failures
}

// Outcome is the result of one poll.
type Outcome struct {
	Kind        OutcomeKind
	NewInterval time.Duration // from a slow_down response, 0 if absent
	RetryAfter  time.Duration // from RateLimited
}

// Step is the decision after an Outcome.
type Step struct {
	Poller   Poller
	Terminal bool
	// Reason is the outcome kind that ended polling when Terminal. When the
	// expiry cutoff ends polling it is NetworkFailure or RateLimited after
	// those failures, otherwise Expired.
	Reason OutcomeKind
	// Delay is the wait before the next poll when not Terminal.
	Delay time.Duration
}

// Next is pure: no clock, no I/O. remaining is the time left until the
// device code expires.
func (p Poller) Next(o Outcome, remaining time.Duration) Step {
	if p.Interval <= 0 {
		p.Interval = DefaultInterval
	}
	switch o.Kind {
	case Token, Expired, Denied, Disabled, Misconfigured:
		return Step{Poller: p, Terminal: true, Reason: o.Kind}
	}

	var delay time.Duration
	switch o.Kind {
	case SlowDown:
		if o.NewInterval > p.Interval {
			p.Interval = o.NewInterval
		} else {
			p.Interval += SlowDownStep
		}
		p.Failures = 0
		delay = p.Interval
	case NetworkFailure:
		p.Failures++
		delay = backoff(p.Interval, p.Failures)
	case RateLimited:
		p.Failures = 0
		delay = max(p.Interval, o.RetryAfter)
	default: // Pending
		p.Failures = 0
		delay = p.Interval
	}

	if delay >= remaining {
		reason := Expired
		if o.Kind == NetworkFailure || o.Kind == RateLimited {
			reason = o.Kind
		}
		return Step{Poller: p, Terminal: true, Reason: reason}
	}
	return Step{Poller: p, Delay: delay}
}

func backoff(interval time.Duration, failures int) time.Duration {
	d := interval
	for i := 1; i < failures; i++ {
		d *= 2
		if d >= MaxBackoff {
			return MaxBackoff
		}
	}
	return min(d, MaxBackoff)
}
