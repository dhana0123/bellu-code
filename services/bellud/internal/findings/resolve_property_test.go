package findings

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// Feature: bellu-wiz-security-platform, Property 3: Scan completion resolves unseen findings only on success. On success every unseen open or in-progress Finding becomes resolved with resolved_at set and one event appended, and seen Findings are unaffected.
// **Validates: Requirements 3.6, 3.7**
func TestPropertyResolveMissingOnSuccess(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newStore(t)
	iter := 0
	rapid.Check(t, func(rt *rapid.T) {
		iter++
		asset := fmt.Sprintf("asset-%d", iter)
		n := rapid.IntRange(0, 12).Draw(rt, "n")
		type item struct {
			id         string
			inProgress bool
			seen       bool
		}
		items := make([]item, n)
		for i := range items {
			items[i] = item{
				id:         fmt.Sprintf("f-%d-%d", iter, i),
				inProgress: rapid.Bool().Draw(rt, "inProgress"),
				seen:       rapid.Bool().Draw(rt, "seen"),
			}
			f := sample(items[i].id)
			f.AssetID = asset
			if _, err := s.Report(ctx, ScanRef{JobID: "seed"}, []Finding{f}); err != nil {
				rt.Fatal(err)
			}
			if items[i].inProgress {
				if err := s.SetStatus(ctx, items[i].id, StatusInProgress, Actor{ID: "user"}, "", nil); err != nil {
					rt.Fatal(err)
				}
			}
		}
		// An unrelated asset and a different source must never be touched.
		other := sample(fmt.Sprintf("other-%d", iter))
		other.AssetID = asset + "-other"
		otherSrc := sample(fmt.Sprintf("othersrc-%d", iter))
		otherSrc.AssetID, otherSrc.Source = asset, "trivy"
		if _, err := s.Report(ctx, ScanRef{}, []Finding{other, otherSrc}); err != nil {
			rt.Fatal(err)
		}

		beforeF := map[string]Finding{}
		beforeE := map[string][]StatusEvent{}
		for _, id := range append([]string{other.ID, otherSrc.ID}, func() []string {
			var ids []string
			for _, it := range items {
				ids = append(ids, it.id)
			}
			return ids
		}()...) {
			f, ev, err := s.Get(ctx, id)
			if err != nil {
				rt.Fatal(err)
			}
			beforeF[id], beforeE[id] = f, ev
		}

		seen := map[string]struct{}{}
		want := 0
		for _, it := range items {
			if it.seen {
				seen[it.id] = struct{}{}
			} else {
				want++
			}
		}
		completed := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
		got, err := s.ResolveMissing(ctx, ScanRef{JobID: "scan", CompletedAt: completed}, asset, "grype", seen)
		if err != nil {
			rt.Fatal(err)
		}
		if got != want {
			rt.Fatalf("resolved %d, want %d", got, want)
		}
		for _, it := range items {
			f, ev, err := s.Get(ctx, it.id)
			if err != nil {
				rt.Fatal(err)
			}
			if it.seen {
				if !reflect.DeepEqual(f, beforeF[it.id]) || !reflect.DeepEqual(ev, beforeE[it.id]) {
					rt.Fatalf("seen finding %s changed", it.id)
				}
				continue
			}
			if f.Status != StatusResolved || f.ResolvedAt == nil || !f.ResolvedAt.Equal(completed) {
				rt.Fatalf("unseen finding %s: status %s resolved_at %v", it.id, f.Status, f.ResolvedAt)
			}
			prev := beforeE[it.id]
			if len(ev) != len(prev)+1 {
				rt.Fatalf("finding %s: %d events, want %d", it.id, len(ev), len(prev)+1)
			}
			if !reflect.DeepEqual(ev[:len(prev)], prev) {
				rt.Fatalf("finding %s: earlier events changed", it.id)
			}
			last := ev[len(ev)-1]
			wantPrev := StatusOpen
			if it.inProgress {
				wantPrev = StatusInProgress
			}
			if last.Prev != wantPrev || last.New != StatusResolved {
				rt.Fatalf("finding %s: last event %s to %s, want %s to resolved", it.id, last.Prev, last.New, wantPrev)
			}
		}
		for _, id := range []string{other.ID, otherSrc.ID} {
			f, ev, _ := s.Get(ctx, id)
			if !reflect.DeepEqual(f, beforeF[id]) || !reflect.DeepEqual(ev, beforeE[id]) {
				rt.Fatalf("finding %s of another asset or source changed", id)
			}
		}
	})
}
