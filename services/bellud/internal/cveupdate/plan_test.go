package cveupdate

import (
	"fmt"
	"testing"
	"time"
)

func snapID(i int) string { return fmt.Sprintf("s%03d", i) }

// linearIndex builds snapshots s0..sN with a delta s(i)->s(i+1) for i >= from.
func linearIndex(n, from int) *Index {
	t0 := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	idx := &Index{}
	for i := 0; i <= n; i++ {
		idx.Snapshots = append(idx.Snapshots, Snapshot{ID: snapID(i), CreatedAt: t0.AddDate(0, 0, i)})
	}
	idx.Latest = idx.Snapshots[n]
	for i := from; i < n; i++ {
		idx.Deltas = append(idx.Deltas, Delta{Base: snapID(i), Target: snapID(i + 1)})
	}
	return idx
}

func TestPlanUpdate(t *testing.T) {
	tests := []struct {
		name      string
		idx       *Index
		installed string
		max       int
		wantFull  bool
		wantUp    bool
		reason    PlanReason
		wantLen   int
	}{
		{"nothing installed", linearIndex(5, 0), "", 0, true, false, ReasonNothingInstall, 0},
		{"up to date", linearIndex(5, 0), snapID(5), 0, false, true, ReasonNone, 0},
		{"delta chain", linearIndex(5, 0), snapID(2), 0, false, false, ReasonNone, 3},
		{"single delta", linearIndex(5, 0), snapID(4), 0, false, false, ReasonNone, 1},
		{"chain at limit", linearIndex(5, 0), snapID(2), 3, false, false, ReasonNone, 3},
		{"chain over limit", linearIndex(5, 0), snapID(2), 2, true, false, ReasonChainTooLong, 0},
		{"default limit 30", linearIndex(40, 0), snapID(5), 0, true, false, ReasonChainTooLong, 0},
		{"older than oldest delta", linearIndex(5, 3), snapID(1), 0, true, false, ReasonTooOld, 0},
		{"unknown installed id", linearIndex(5, 0), "zzz", 0, true, false, ReasonMissingDelta, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := PlanUpdate(tc.idx, tc.installed, tc.max)
			if err != nil {
				t.Fatal(err)
			}
			if p.Full != tc.wantFull || p.UpToDate != tc.wantUp || p.Reason != tc.reason || len(p.Deltas) != tc.wantLen {
				t.Fatalf("got %+v", p)
			}
			if p.Full && p.Snapshot.ID != tc.idx.Latest.ID {
				t.Fatalf("full snapshot %s, want latest", p.Snapshot.ID)
			}
		})
	}
}

func TestPlanUpdateMissingDelta(t *testing.T) {
	idx := linearIndex(5, 0)
	idx.Deltas = append(idx.Deltas[:2], idx.Deltas[3:]...) // drop s2->s3
	p, err := PlanUpdate(idx, snapID(1), 0)
	if err != nil || !p.Full || p.Reason != ReasonMissingDelta {
		t.Fatalf("got %+v, %v", p, err)
	}
}

func TestPlanUpdateChainOrder(t *testing.T) {
	p, err := PlanUpdate(linearIndex(4, 0), snapID(1), 0)
	if err != nil || len(p.Deltas) != 3 {
		t.Fatalf("got %+v, %v", p, err)
	}
	for i, d := range p.Deltas {
		if d.Base != snapID(1+i) || d.Target != snapID(2+i) {
			t.Fatalf("delta %d is %s->%s", i, d.Base, d.Target)
		}
	}
}

func TestChainLimit(t *testing.T) {
	for _, ok := range []int{0, 1, 30, 365} {
		if _, err := ChainLimit(ok); err != nil {
			t.Errorf("%d: %v", ok, err)
		}
	}
	for _, bad := range []int{-1, 366, 1000} {
		if _, err := ChainLimit(bad); err == nil {
			t.Errorf("%d accepted", bad)
		}
	}
	if n, _ := ChainLimit(0); n != DefaultMaxChain {
		t.Errorf("default = %d", n)
	}
	if _, err := PlanUpdate(linearIndex(2, 0), "s000", 400); err == nil {
		t.Error("PlanUpdate accepted limit 400")
	}
}

func TestPlanUpdateNoLatest(t *testing.T) {
	if _, err := PlanUpdate(&Index{}, "s0", 0); err != ErrNoLatest {
		t.Fatalf("got %v", err)
	}
}
