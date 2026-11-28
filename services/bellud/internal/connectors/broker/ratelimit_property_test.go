package broker

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/policy"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/vault"
	"pgregory.net/rapid"
)

// fakeClock is advanced only by Sleep and by the test itself.
type fakeClock struct {
	mu  sync.Mutex
	cur time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cur
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.cur = c.cur.Add(d)
	c.mu.Unlock()
}

func (c *fakeClock) Sleep(_ context.Context, d time.Duration) error {
	c.Advance(d)
	return nil
}

// rateHarness drives one connection on a fake clock and records, per sent
// request, the fake send time and the Retry-After seconds it answered with.
type rateHarness struct {
	clk   *fakeClock
	start time.Time
	b     *Broker
	ref   ConnectionRef

	mu    sync.Mutex
	sent  []time.Time
	pause map[int]int // index of sent request -> Retry-After seconds
	next  func(i int) int
}

func newRateHarness(t *testing.T, next func(i int) int) *rateHarness {
	h := &rateHarness{pause: map[int]int{}, next: next}
	// The call deadline is real time; start the fake clock at real now so
	// deadline checks stay meaningful.
	h.start = time.Now()
	h.clk = &fakeClock{cur: h.start}
	inner := &countingRT{fn: func(r *http.Request) (*http.Response, error) {
		h.mu.Lock()
		i := len(h.sent)
		h.sent = append(h.sent, h.clk.Now())
		secs := h.next(i)
		if secs > 0 {
			h.pause[i] = secs
		}
		h.mu.Unlock()
		if secs > 0 {
			return respond(429, `{}`, "Retry-After", strconv.Itoa(secs))(r)
		}
		return respond(200, `{}`)(r)
	}}
	h.b = New(Config{
		Opener: fakeOpener{secret: token}, Audit: &memAudit{}, Inner: inner,
		Now: h.clk.Now, Sleep: h.clk.Sleep,
	})
	h.ref = newRef(t, AuthGitHubToken)
	h.ref.Credential = vault.Ref{Owner: vault.OwnerConnection, OwnerID: "c1", Slot: "token"}
	return h
}

func (h *rateHarness) call() error {
	_, err := h.b.Do(context.Background(), Call{Connection: h.ref, Caller: policy.CallerCollector, Operation: "GET /big"})
	return err
}

// Feature: cloud-connectors, Property 31: Rate limiting
//
// No sliding one-second window contains more than 10 sent requests.
//
// Validates: Requirements 7.12
func TestPropertyRateLimitWindow(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		h := newRateHarness(t, func(int) int { return 0 })
		n := rapid.IntRange(1, 60).Draw(rt, "requests")
		for i := 0; i < n; i++ {
			// Idle gaps of 0..300 ms between calls, bursts when 0.
			h.clk.Advance(time.Duration(rapid.IntRange(0, 300).Draw(rt, "gap_ms")) * time.Millisecond)
			if err := h.call(); err != nil {
				rt.Fatalf("call %d: %v", i, err)
			}
		}
		if len(h.sent) != n {
			rt.Fatalf("sent %d of %d", len(h.sent), n)
		}
		const limit = 10
		for i := 0; i+limit < len(h.sent); i++ {
			// Requests i..i+10 are 11 sends; they must not fit in one second.
			if span := h.sent[i+limit].Sub(h.sent[i]); span < time.Second {
				rt.Fatalf("11 requests within %v starting at send %d", span, i)
			}
		}
	})
}

// Feature: cloud-connectors, Property 31: Rate limiting
//
// Nothing is sent before a provider-indicated retry time.
//
// Validates: Requirements 7.12
func TestPropertyRateLimitHonoursRetryAfter(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		n := rapid.IntRange(1, 40).Draw(rt, "requests")
		// Provider answers 429 + Retry-After 1..5 s on some requests.
		answers := rapid.SliceOfN(rapid.OneOf(rapid.Just(0), rapid.Just(0), rapid.IntRange(1, 5)), n, n).Draw(rt, "retry_after")
		h := newRateHarness(t, func(i int) int { return answers[i] })
		for i := 0; i < n; i++ {
			h.clk.Advance(time.Duration(rapid.IntRange(0, 500).Draw(rt, "gap_ms")) * time.Millisecond)
			// A call that would wait past the 30 s deadline is refused unsent.
			if err := h.call(); err != nil {
				if _, ok := err.(*RateLimitedError); !ok {
					rt.Fatalf("call %d: %v", i, err)
				}
			}
		}
		for i, secs := range h.pause {
			until := h.sent[i].Add(time.Duration(secs) * time.Second)
			for j := i + 1; j < len(h.sent); j++ {
				if h.sent[j].Before(until) {
					rt.Fatalf("send %d at +%v before retry time +%v set by send %d",
						j, h.sent[j].Sub(h.start), until.Sub(h.start), i)
				}
			}
		}
	})
}
