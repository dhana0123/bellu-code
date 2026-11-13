package lifecycle

import (
	"context"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
	"pgregory.net/rapid"
)

// rfWait polls cond for up to 3 s; it reports false on timeout so the caller
// can fail through the rapid.T of the current check.
func rfWait(cond func() bool) bool {
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(time.Millisecond)
	}
	return true
}

// Feature: cloud-connectors, Property 24: Credential refresh schedule
// Validates: Requirements 3.4, 4.10, 14.6
//
// The refresh of a session credential is scheduled at expiry − 300 s, or at
// once when less time remains; after it the new expiry is stored and the
// connection stays ACTIVE.
func TestPropertyCredentialRefreshSchedule(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// Remaining validity in seconds. Anything above 3800 s would make the
		// 1 h collection timer the earliest one, so the range stops there.
		remaining := time.Duration(rapid.OneOf(
			rapid.Int64Range(-600, 3800),
			rapid.SampledFrom([]int64{-1, 0, 1, 299, 300, 301}),
		).Draw(rt, "remainingSec")) * time.Second
		newRemaining := time.Duration(rapid.Int64Range(3600, 30*24*3600).Draw(rt, "newRemainingSec")) * time.Second
		newExp := svT0.Add(newRemaining)

		p := &svProvider{collect: svOK, refresh: func() (time.Time, error) { return newExp, nil }}
		f := newSvFix(t, p, func(c *store.Connection) {
			e := svT0.Add(remaining)
			c.CredentialExpiresAt = &e
		})
		defer func() { _ = f.sup.Stop(context.Background(), "c1") }()
		f.sup.Start(f.conn)

		if remaining <= RefreshLead {
			// Less than 300 s left: refresh starts at once, without the clock moving.
			if !rfWait(func() bool { return p.refreshCalls.Load() == 1 }) {
				rt.Fatalf("no immediate refresh with %v remaining", remaining)
			}
		} else {
			want := remaining - RefreshLead
			if !rfWait(func() bool { n, ok := f.clk.next(); return ok && n == want }) {
				rt.Fatalf("no refresh timer of %v for %v remaining", want, remaining)
			}
			if p.refreshCalls.Load() != 0 {
				rt.Fatalf("refreshed before expiry − 300 s (%v remaining)", remaining)
			}
			f.clk.Advance(want)
			if !rfWait(func() bool { return p.refreshCalls.Load() == 1 }) {
				rt.Fatalf("no refresh at expiry − 300 s (%v remaining)", remaining)
			}
		}

		if !rfWait(func() bool {
			e := f.stored().CredentialExpiresAt
			return e != nil && e.Equal(newExp)
		}) {
			rt.Fatalf("new expiry not stored")
		}
		now := f.clk.Now()
		stored := f.stored()
		if got, want := ExpiresSoon(stored, now), newExp.Sub(now) < ExpiresSoonWindow; got != want {
			rt.Fatalf("ExpiresSoon = %v, want %v (now %v, expiry %v)", got, want, now, newExp)
		}
		if stored.Status != string(StatusActive) || len(f.host.statuses()) != 0 {
			rt.Fatalf("refresh must keep the connection ACTIVE, got %s %+v", stored.Status, f.host.statuses())
		}
	})
}

// Feature: cloud-connectors, Property 24: Credential refresh schedule
// Validates: Requirements 3.4, 4.10, 14.6
//
// expiresSoon holds if and only if fewer than 7 days remain, and it is a
// derived flag: it never changes the stored status.
func TestPropertyExpiresSoonIff(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		now := svT0.Add(time.Duration(rapid.Int64Range(0, 1<<30).Draw(rt, "nowSec")) * time.Second)
		offset := time.Duration(rapid.OneOf(
			rapid.Int64Range(-2*24*3600, 14*24*3600),
			rapid.SampledFrom([]int64{7*24*3600 - 1, 7 * 24 * 3600, 7*24*3600 + 1}),
		).Draw(rt, "offsetSec")) * time.Second
		exp := now.Add(offset)
		conn := store.Connection{Status: string(StatusActive), CredentialExpiresAt: &exp}
		if got, want := ExpiresSoon(conn, now), offset < 7*24*time.Hour; got != want {
			rt.Fatalf("ExpiresSoon(%v remaining) = %v, want %v", offset, got, want)
		}
		if conn.Status != string(StatusActive) {
			rt.Fatalf("status changed")
		}
		if ExpiresSoon(store.Connection{Status: string(StatusActive)}, now) {
			rt.Fatalf("a connection without expiry must not be flagged")
		}
	})
}
