package findings

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// Feature: bellu-wiz-security-platform, Property 5: Snooze expiry reopens findings. ExpireSnoozes sets every ignored or accepted_risk Finding whose expiry is at or before now to open and appends one event with actor system; a Finding whose expiry has not passed is unchanged.
// **Validates: Requirements 3.11**
func TestPropertySnoozeExpiryReopens(t *testing.T) {
	ctx := context.Background()
	rapid.Check(t, func(rt *rapid.T) {
		s, _, c := newStore(t)
		base := c.t
		n := rapid.IntRange(0, 15).Draw(rt, "n")
		type item struct {
			id      string
			to      Status
			expires time.Time
		}
		items := make([]item, n)
		for i := range items {
			it := item{
				id:      fmt.Sprintf("f-%d", i),
				to:      rapid.SampledFrom([]Status{StatusIgnored, StatusAcceptedRisk}).Draw(rt, "status"),
				expires: base.Add(time.Duration(rapid.IntRange(1, 1000).Draw(rt, "expiresSec")) * time.Second),
			}
			items[i] = it
			if _, err := s.Report(ctx, ScanRef{JobID: "seed"}, []Finding{sample(it.id)}); err != nil {
				rt.Fatal(err)
			}
			exp := it.expires
			if err := s.SetStatus(ctx, it.id, it.to, Actor{ID: "user"}, "because", &exp); err != nil {
				rt.Fatal(err)
			}
		}
		// Some draws land exactly on an expiry, which must count as expired.
		var now time.Time
		if n > 0 && rapid.Bool().Draw(rt, "onBoundary") {
			now = items[rapid.IntRange(0, n-1).Draw(rt, "boundaryIdx")].expires
		} else {
			now = base.Add(time.Duration(rapid.IntRange(0, 1100).Draw(rt, "nowSec")) * time.Second)
		}

		beforeF := map[string]Finding{}
		beforeE := map[string][]StatusEvent{}
		for _, it := range items {
			f, ev, err := s.Get(ctx, it.id)
			if err != nil {
				rt.Fatal(err)
			}
			beforeF[it.id], beforeE[it.id] = f, ev
		}

		c.t = now
		got, err := s.ExpireSnoozes(ctx, now)
		if err != nil {
			rt.Fatal(err)
		}
		want := 0
		for _, it := range items {
			f, ev, err := s.Get(ctx, it.id)
			if err != nil {
				rt.Fatal(err)
			}
			if it.expires.After(now) {
				if !reflect.DeepEqual(f, beforeF[it.id]) || !reflect.DeepEqual(ev, beforeE[it.id]) {
					rt.Fatalf("finding %s (expires %v, now %v) changed", it.id, it.expires, now)
				}
				continue
			}
			want++
			prev := beforeE[it.id]
			if f.Status != StatusOpen {
				rt.Fatalf("finding %s: status %s, want open", it.id, f.Status)
			}
			if len(ev) != len(prev)+1 || !reflect.DeepEqual(ev[:len(prev)], prev) {
				rt.Fatalf("finding %s: %d events, want %d appended to the old ones", it.id, len(ev), len(prev)+1)
			}
			last := ev[len(ev)-1]
			if last.Actor != "system" || last.Prev != it.to || last.New != StatusOpen {
				rt.Fatalf("finding %s: last event %s %s to %s, want system %s to open", it.id, last.Actor, last.Prev, last.New, it.to)
			}
		}
		if got != want {
			rt.Fatalf("ExpireSnoozes returned %d, want %d", got, want)
		}
		// A second pass finds nothing left to do.
		if again, err := s.ExpireSnoozes(ctx, now); err != nil || again != 0 {
			rt.Fatalf("second pass: %d %v", again, err)
		}
	})
}

// RunExpiry reopens an expired finding within one interval. With the 30 s
// production interval this is the "within 60 s" bound of Requirement 3.11.
func TestRunExpiryReopensWithinInterval(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, _, c := newStore(t)
	if _, err := s.Report(ctx, ScanRef{}, []Finding{sample("a")}); err != nil {
		t.Fatal(err)
	}
	exp := c.t.Add(time.Hour)
	if err := s.SetStatus(ctx, "a", StatusIgnored, Actor{ID: "user"}, "noise", &exp); err != nil {
		t.Fatal(err)
	}
	c.t = exp.Add(time.Second)

	const interval = 50 * time.Millisecond
	done := make(chan struct{})
	errs := make(chan error, 1)
	go func() {
		defer close(done)
		s.RunExpiry(ctx, interval, func(err error) {
			select {
			case errs <- err:
			default:
			}
		})
	}()

	deadline := time.Now().Add(10 * interval)
	for {
		f, ev, err := s.Get(ctx, "a")
		if err != nil {
			t.Fatal(err)
		}
		if f.Status == StatusOpen {
			if last := ev[len(ev)-1]; last.Actor != "system" || last.Prev != StatusIgnored || last.New != StatusOpen {
				t.Fatalf("last event: %+v", last)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("finding still %s after %v", f.Status, 10*interval)
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	select {
	case err := <-errs:
		t.Fatalf("onErr: %v", err)
	default:
	}
}
