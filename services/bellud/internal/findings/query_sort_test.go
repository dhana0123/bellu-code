package findings

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

// seedSorted reports findings at distinct and tied times with mixed severity
// and risk (some unscored) so every sort has ties to break.
func seedSorted(t *testing.T, s *Store, c *clock) []Finding {
	t.Helper()
	r := func(v float64) *float64 { return &v }
	specs := []struct {
		id, asset, src string
		sev            Severity
		risk           *float64
		day            int
	}{
		{"f1", "a1", "grype", SevLow, r(10), 1},
		{"f2", "a2", "trivy", SevCritical, nil, 2},
		{"f3", "a1", "trivy", SevHigh, r(55.5), 2},
		{"f4", "a3", "grype", SevHigh, r(55.5), 3},
		{"f5", "a2", "grype", SevInfo, nil, 4},
		{"f6", "a3", "trivy", SevMedium, r(0), 4},
		{"f7", "a1", "grype", SevCritical, r(99), 5},
	}
	for _, sp := range specs {
		c.t = time.Date(2025, 3, sp.day, 0, 0, 0, 0, time.UTC)
		f := sample(sp.id)
		f.AssetID, f.Source, f.Severity, f.RiskScore = sp.asset, sp.src, sp.sev, sp.risk
		if _, err := s.Report(context.Background(), ScanRef{}, []Finding{f}); err != nil {
			t.Fatal(err)
		}
	}
	all, err := s.List(context.Background(), ListQuery{Limit: 100})
	if err != nil || len(all.Items) != len(specs) {
		t.Fatalf("seed: %v %d", err, len(all.Items))
	}
	return all.Items
}

func pageAll(t *testing.T, s *Store, q ListQuery) []string {
	t.Helper()
	var ids []string
	for range 20 {
		pg, err := s.List(context.Background(), q)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range pg.Items {
			ids = append(ids, f.ID)
		}
		if pg.NextCursor == "" {
			return ids
		}
		q.Cursor = pg.NextCursor
	}
	t.Fatal("paging did not end")
	return nil
}

func TestListSortPagingMatchesFullOrder(t *testing.T) {
	s, _, c := newStore(t)
	items := seedSorted(t, s, c)
	rank := map[Severity]int{SevCritical: 4, SevHigh: 3, SevMedium: 2, SevLow: 1, SevInfo: 0}
	risk := func(f Finding) float64 {
		if f.RiskScore == nil {
			return -1
		}
		return *f.RiskScore
	}
	cmp := map[string]func(a, b Finding) int{
		SortLastSeen:  func(a, b Finding) int { return a.LastSeen.Compare(b.LastSeen) },
		SortFirstSeen: func(a, b Finding) int { return a.FirstSeen.Compare(b.FirstSeen) },
		SortSeverity:  func(a, b Finding) int { return rank[a.Severity] - rank[b.Severity] },
		SortRiskScore: func(a, b Finding) int {
			switch x, y := risk(a), risk(b); {
			case x < y:
				return -1
			case x > y:
				return 1
			}
			return 0
		},
	}
	for field, fn := range cmp {
		for _, desc := range []bool{false, true} {
			want := slices.Clone(items)
			slices.SortStableFunc(want, func(a, b Finding) int {
				if d := fn(a, b); d != 0 {
					if desc {
						return -d
					}
					return d
				}
				return slices.Compare([]byte(a.ID), []byte(b.ID))
			})
			var wantIDs []string
			for _, f := range want {
				wantIDs = append(wantIDs, f.ID)
			}
			for _, limit := range []int{1, 2, 3, 100} {
				got := pageAll(t, s, ListQuery{Sort: field, Desc: desc, Limit: limit})
				if !slices.Equal(got, wantIDs) {
					t.Errorf("sort=%s desc=%v limit=%d\n got %v\nwant %v", field, desc, limit, got, wantIDs)
				}
			}
		}
	}
}

func TestListDefaultOrderIsLastSeenDescThenID(t *testing.T) {
	s, _, c := newStore(t)
	seedSorted(t, s, c)
	got := pageAll(t, s, ListQuery{Limit: 2})
	if want := []string{"f7", "f5", "f6", "f4", "f2", "f3", "f1"}; !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestListMultiAssetSourceAndRange(t *testing.T) {
	s, _, c := newStore(t)
	seedSorted(t, s, c)
	from, to := time.Date(2025, 3, 2, 0, 0, 0, 0, time.UTC), time.Date(2025, 3, 4, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		q    ListQuery
		want []string
	}{
		{"two assets", ListQuery{AssetIDs: []string{"a2", "a3"}}, []string{"f5", "f6", "f4", "f2"}},
		{"asset and legacy asset", ListQuery{AssetID: "a2", AssetIDs: []string{"a3"}}, []string{"f5", "f6", "f4", "f2"}},
		{"two sources", ListQuery{Sources: []string{"grype", "trivy"}, Limit: 3}, []string{"f7", "f5", "f6", "f4", "f2", "f3", "f1"}},
		{"source and asset", ListQuery{Sources: []string{"trivy"}, AssetIDs: []string{"a1", "a3"}}, []string{"f6", "f3"}},
		{"range inclusive", ListQuery{From: &from, To: &to}, []string{"f5", "f6", "f4", "f2", "f3"}},
		{"from only", ListQuery{From: &to}, []string{"f7", "f5", "f6"}},
		{"to only", ListQuery{To: &from}, []string{"f2", "f3", "f1"}},
	}
	for _, tc := range cases {
		if got := pageAll(t, s, tc.q); !slices.Equal(got, tc.want) {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

func TestListRejectsBadSortAndCursor(t *testing.T) {
	s, _, _ := newStore(t)
	for name, q := range map[string]ListQuery{
		"sort":          {Sort: "title"},
		"cursor":        {Cursor: "nopipe"},
		"cursor number": {Sort: SortSeverity, Cursor: "x|f1"},
	} {
		if _, err := s.List(context.Background(), q); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
