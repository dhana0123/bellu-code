package findings

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
	"pgregory.net/rapid"
)

// Feature: bellu-wiz-security-platform, Property 8: Graph finding-node presence matches status. For any Finding and any sequence of status transitions, a finding node is present in the graph if and only if its current status is open or in_progress.
// **Validates: Requirements 3.16**
func TestPropertyGraphFindingNodePresence(t *testing.T) {
	ctx := context.Background()
	s, _, clk := newStore(t)
	e, err := graph.Open(ctx, graph.Config{Enabled: true, Dir: filepath.Join(t.TempDir(), "g"), Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close(ctx) })
	p := NewProjector(s, e)
	iter := 0

	rapid.Check(t, func(rt *rapid.T) {
		iter++
		// One engine for all cases; each case gets its own asset and finding ids.
		host := fmt.Sprintf("host-%d", iter)
		if _, err := e.Ingest().Apply(ctx, batch.Batch{Collector: "host", Entities: []batch.Entity{
			{Type: "host", Identity: map[string]string{"hostname": host}}}}); err != nil {
			rt.Fatal(err)
		}
		assetID, err := identity.Hash("host", map[string]string{"hostname": host})
		if err != nil {
			rt.Fatal(err)
		}
		asset := string(assetID)

		n := rapid.IntRange(1, 5).Draw(rt, "findings")
		fs := make([]Finding, n)
		ids := make([]string, n)
		for i := range fs {
			ids[i] = fmt.Sprintf("p8-%d-%d", iter, i)
			fs[i] = sample(ids[i])
			fs[i].AssetID = asset
		}
		if _, err := s.Report(ctx, ScanRef{JobID: "seed"}, fs); err != nil {
			rt.Fatal(err)
		}

		check := func(step string) {
			if err := p.Project(ctx); err != nil {
				rt.Fatalf("%s: project: %v", step, err)
			}
			for _, id := range ids {
				f, _, err := s.Get(ctx, id)
				if err != nil {
					rt.Fatal(err)
				}
				want := f.Status == StatusOpen || f.Status == StatusInProgress
				nodeID, err := identity.Hash("finding", map[string]string{"id": id})
				if err != nil {
					rt.Fatal(err)
				}
				_, err = e.Query().Entity(ctx, graph.EntityID(nodeID), nil)
				if err != nil && !errors.Is(err, graph.ErrNotFound) {
					rt.Fatalf("%s: entity %s: %v", step, id, err)
				}
				if got := err == nil; got != want {
					rt.Fatalf("%s: finding %s status %s: node present=%v, want %v", step, id, f.Status, got, want)
				}
				if !want {
					continue
				}
				edges, err := e.Query().Neighbors(ctx, graph.EntityID(nodeID), graph.NeighborOpts{})
				if err != nil {
					rt.Fatalf("%s: neighbors %s: %v", step, id, err)
				}
				affects := 0
				for _, ed := range edges.Items {
					if ed.Type == "affects" {
						affects++
					}
				}
				if affects != 1 || len(edges.Items) != 1 {
					rt.Fatalf("%s: finding %s has %d edges (%d affects), want exactly one affects", step, id, len(edges.Items), affects)
				}
			}
		}
		check("seed")

		steps := rapid.IntRange(1, 12).Draw(rt, "steps")
		for i := 0; i < steps; i++ {
			id := rapid.SampledFrom(ids).Draw(rt, "id")
			var name string
			switch rapid.IntRange(0, 5).Draw(rt, "op") {
			case 0:
				name = "in_progress"
				// An invalid transition is skipped, leaving the status unchanged.
				_ = s.SetStatus(ctx, id, StatusInProgress, Actor{ID: "user"}, "", nil)
			case 1, 2:
				to := rapid.SampledFrom([]Status{StatusIgnored, StatusAcceptedRisk}).Draw(rt, "snooze")
				var exp *time.Time
				if rapid.Bool().Draw(rt, "hasExpiry") {
					x := clk.now().Add(time.Duration(rapid.IntRange(1, 48).Draw(rt, "hours")) * time.Hour)
					exp = &x
				}
				name = "snooze " + string(to)
				_ = s.SetStatus(ctx, id, to, Actor{ID: "user"}, "reason", exp)
			case 3:
				seen := map[string]struct{}{}
				for _, other := range ids {
					if rapid.Bool().Draw(rt, "seen") {
						seen[other] = struct{}{}
					}
				}
				name = "resolve_missing"
				if _, err := s.ResolveMissing(ctx, ScanRef{JobID: "scan"}, asset, "grype", seen); err != nil {
					rt.Fatal(err)
				}
			case 4:
				name = "re-report"
				f := sample(id)
				f.AssetID = asset
				if _, err := s.Report(ctx, ScanRef{JobID: "rescan"}, []Finding{f}); err != nil {
					rt.Fatal(err)
				}
			default:
				name = "expire_snoozes"
				clk.t = clk.t.Add(time.Duration(rapid.IntRange(1, 72).Draw(rt, "advance")) * time.Hour)
				if _, err := s.ExpireSnoozes(ctx, clk.now()); err != nil {
					rt.Fatal(err)
				}
			}
			check(fmt.Sprintf("step %d (%s %s)", i, name, id))
		}
	})
}
