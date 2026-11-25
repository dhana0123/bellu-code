package findings

import (
	"context"
	"fmt"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// Feature: bellu-wiz-security-platform, Property 2: For any stored Finding and any later report of a Finding with the same id, the Store SHALL leave first_seen unchanged and set last_seen to the report time; if the stored status was resolved, the Store SHALL additionally set the status to open, clear resolved_at, and append one status-change event.
// **Validates: Requirements 3.4, 3.5**
func TestPropertyReportTransitions(t *testing.T) {
	ctx := context.Background()
	s, _, c := newStore(t)
	n := 0

	rapid.Check(t, func(t *rapid.T) {
		n++
		id := fmt.Sprintf("f%d", n)
		asset := fmt.Sprintf("asset-%d", n) // ResolveMissing is scoped to one asset, so cases stay independent
		f := sample(id)
		f.AssetID = asset

		step := func(label string) {
			c.t = c.t.Add(time.Duration(rapid.IntRange(1, 100000).Draw(t, label)) * time.Second)
		}

		// Reach the initial status through real store transitions.
		step("t0")
		if _, err := s.Report(ctx, ScanRef{}, []Finding{f}); err != nil {
			t.Fatal(err)
		}
		firstSeen := c.t
		want := rapid.SampledFrom([]Status{StatusOpen, StatusInProgress, StatusResolved, StatusIgnored, StatusAcceptedRisk}).Draw(t, "initial")
		step("t1")
		switch want {
		case StatusInProgress:
			if err := s.SetStatus(ctx, id, StatusInProgress, Actor{ID: "u1"}, "", nil); err != nil {
				t.Fatal(err)
			}
		case StatusResolved:
			if rapid.Bool().Draw(t, "viaInProgress") {
				if err := s.SetStatus(ctx, id, StatusInProgress, Actor{ID: "u1"}, "", nil); err != nil {
					t.Fatal(err)
				}
			}
			if k, err := s.ResolveMissing(ctx, ScanRef{}, asset, f.Source, map[string]struct{}{}); err != nil || k != 1 {
				t.Fatalf("resolve: %d %v", k, err)
			}
		case StatusIgnored, StatusAcceptedRisk:
			if err := s.SetStatus(ctx, id, want, Actor{ID: "u1"}, "because", nil); err != nil {
				t.Fatal(err)
			}
		}

		before, evBefore, err := s.Get(ctx, id)
		if err != nil || before.Status != want {
			t.Fatalf("setup: status %q want %q err %v", before.Status, want, err)
		}

		// A later report with the same id, possibly with different content.
		step("t2")
		again := f
		again.Title = rapid.StringMatching(`[a-z]{1,20}`).Draw(t, "title")
		again.Severity = rapid.SampledFrom([]Severity{SevCritical, SevHigh, SevMedium, SevLow, SevInfo}).Draw(t, "severity")
		reportAt := c.t
		if _, err := s.Report(ctx, ScanRef{}, []Finding{again}); err != nil {
			t.Fatal(err)
		}

		after, evAfter, err := s.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if !after.FirstSeen.Equal(firstSeen) {
			t.Fatalf("first_seen changed: %v -> %v", firstSeen, after.FirstSeen)
		}
		if !after.LastSeen.Equal(reportAt) {
			t.Fatalf("last_seen %v, want report time %v", after.LastSeen, reportAt)
		}

		if want != StatusResolved {
			// Repeat reports of ignored and accepted_risk touch last_seen only; others stay as they were.
			if after.Status != want || len(evAfter) != len(evBefore) {
				t.Fatalf("status %q->%q, events %d->%d", want, after.Status, len(evBefore), len(evAfter))
			}
			if (want == StatusIgnored || want == StatusAcceptedRisk) && after.Title != before.Title {
				t.Fatalf("report changed a user-decided finding: %q -> %q", before.Title, after.Title)
			}
			return
		}
		if before.ResolvedAt == nil {
			t.Fatal("setup: resolved finding has no resolved_at")
		}
		if after.Status != StatusOpen || after.ResolvedAt != nil {
			t.Fatalf("not reopened: status %q resolved_at %v", after.Status, after.ResolvedAt)
		}
		if len(evAfter) != len(evBefore)+1 {
			t.Fatalf("events %d -> %d, want exactly one more", len(evBefore), len(evAfter))
		}
		last := evAfter[len(evAfter)-1]
		if last.Prev != StatusResolved || last.New != StatusOpen || !last.At.Equal(reportAt) {
			t.Fatalf("bad status-change event: %+v", last)
		}
	})
}
