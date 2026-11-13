package lifecycle

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"pgregory.net/rapid"
)

// Feature: cloud-connectors, Property 30: Failure backoff
//
// For any sequence of collection results, the delay after the n-th
// consecutive failure is min(1 min · 2^(n−1), 15 min) and resets to the
// regular interval after a success.
//
// **Validates: Requirements 7.5**

// oracleBackoff is an independent loop-based model of the formula.
func oracleBackoff(n int) time.Duration {
	d := time.Minute
	for i := 1; i < n; i++ {
		d *= 2
		if d >= 15*time.Minute {
			return 15 * time.Minute
		}
	}
	return d
}

func TestPropertyFailureBackoffFormula(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		n := rapid.IntRange(1, 1<<20).Draw(rt, "n")
		if got, want := FailureBackoff(n), oracleBackoff(n); got != want {
			rt.Fatalf("FailureBackoff(%d) = %v, want %v", n, got, want)
		}
		if n > 1 && FailureBackoff(n) < FailureBackoff(n-1) {
			rt.Fatalf("backoff not monotonic at %d", n)
		}
	})
}

// waitUntil polls cond for a bounded time without failing the outer test.
func waitUntil(cond func() bool) bool {
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(time.Millisecond)
	}
	return true
}

func TestPropertyFailureBackoffSupervisor(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		results := rapid.SliceOfN(rapid.Bool(), 1, 12).Draw(rt, "failures")

		var calls atomic.Int32
		p := &svProvider{collect: func(context.Context) (graph.Batch, error) {
			i := int(calls.Add(1)) - 1
			if i < len(results) && results[i] {
				return graph.Batch{}, errors.New("boom")
			}
			return graph.Batch{}, nil
		}}
		f := newSvFix(t, p, nil)
		f.sup.Start(f.conn)
		defer func() { _ = f.sup.Stop(context.Background(), "c1") }()

		consecutive := 0
		for i, failed := range results {
			if !waitUntil(func() bool { return f.run.runs.Load() >= int32(i+1) }) {
				rt.Fatalf("run %d never happened", i+1)
			}
			want := time.Hour // success resets to the configured interval
			if failed {
				consecutive++
				want = oracleBackoff(consecutive)
			} else {
				consecutive = 0
			}
			if !waitUntil(func() bool {
				n, ok := f.clk.next()
				return ok && n == want
			}) {
				n, ok := f.clk.next()
				rt.Fatalf("results=%v after run %d (failure streak %d): next timer %v (pending=%v), want %v",
					results, i+1, consecutive, n, ok, want)
			}
			f.clk.Advance(want)
		}
	})
}
