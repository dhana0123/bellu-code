package scanners

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/config"
	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
	"pgregory.net/rapid"
)

// resolveSink wraps the real findings JobSink and maps (Target, Kind) to the
// asset id and source name the findings store uses.
type resolveSink struct{ *findings.JobSink }

func (s resolveSink) Batch(batch.Batch) error { return nil }

func (s resolveSink) ResolveMissing(ctx context.Context, t Target, k Kind) (int, error) {
	return s.JobSink.ResolveMissing(ctx, t.ID, string(k))
}

type outcomePlan struct {
	mode    string // success, fail, cancel
	seen    []string
	started chan struct{}
}

// planAdapter is an in-process adapter whose behavior is chosen per target.
type planAdapter struct {
	mu    sync.Mutex
	plans map[string]*outcomePlan
}

func (a *planAdapter) Kind() Kind                                     { return KindSecret }
func (a *planAdapter) Info() Info                                     { return Info{Name: "plan", Version: "1"} }
func (a *planAdapter) Applies(t TargetType) bool                      { return t == TargetRepository }
func (a *planAdapter) Digest(context.Context, Target) (string, error) { return "", nil }
func (a *planAdapter) Run(ctx context.Context, t Target, out Sink) error {
	a.mu.Lock()
	p := a.plans[t.ID]
	a.mu.Unlock()
	for _, id := range p.seen {
		out.Seen(id)
	}
	switch p.mode {
	case "fail":
		return errors.New("scanner blew up")
	case "cancel":
		close(p.started)
		<-ctx.Done()
		return ctx.Err()
	}
	return nil
}

type snapshot struct {
	f  findings.Finding
	ev []findings.StatusEvent
}

// Feature: bellu-wiz-security-platform, Property 3: Scan completion resolves unseen findings only on success. After a failed or cancelled scan every existing Finding of the asset and scanner is unchanged; after a successful scan every unseen open or in-progress Finding is resolved and seen Findings are unaffected.
// **Validates: Requirements 3.6, 3.7**
func TestPropertyScanCompletionResolvesOnlyOnSuccess(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, t.TempDir(), "ws1", sqlite.Options{Migrations: sqlitemigrations.FS})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	fs := findings.New(db)
	t.Cleanup(fs.Close)
	ad := &planAdapter{plans: map[string]*outcomePlan{}}
	m, err := New(Config{
		Store:    db,
		Settings: config.Scanners{Parallel: 2, JobTimeout: time.Minute},
		Adapters: []Adapter{ad},
		Resolve: func(_ context.Context, typ TargetType, id string) (Target, bool, error) {
			return Target{Type: typ, ID: id, Path: "/x/" + id}, true, nil
		},
		SinkFor: func(j Job) JobSink {
			return resolveSink{fs.JobSink(ctx, findings.ScanRef{JobID: j.ID})}
		},
		CancelGrace: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)

	iter := 0
	rapid.Check(t, func(rt *rapid.T) {
		iter++
		asset := fmt.Sprintf("repo-%d", iter)
		n := rapid.IntRange(0, 8).Draw(rt, "n")
		mode := rapid.SampledFrom([]string{"success", "fail", "cancel"}).Draw(rt, "mode")
		var ids []string
		inProgress := map[string]bool{}
		plan := &outcomePlan{mode: mode, started: make(chan struct{})}
		seen := map[string]bool{}
		for i := 0; i < n; i++ {
			id := fmt.Sprintf("f-%d-%d", iter, i)
			ids = append(ids, id)
			f := findings.Finding{ID: id, RuleID: "r", Title: "t", Category: "code_and_dependencies",
				Type: findings.TypeVulnerability, Severity: findings.SevHigh, AssetID: asset, Source: string(KindSecret)}
			if _, err := fs.Report(ctx, findings.ScanRef{JobID: "seed"}, []findings.Finding{f}); err != nil {
				rt.Fatal(err)
			}
			if rapid.Bool().Draw(rt, "inProgress") {
				inProgress[id] = true
				if err := fs.SetStatus(ctx, id, findings.StatusInProgress, findings.Actor{ID: "user"}, "", nil); err != nil {
					rt.Fatal(err)
				}
			}
			if rapid.Bool().Draw(rt, "seen") {
				seen[id] = true
				plan.seen = append(plan.seen, id)
			}
		}
		before := map[string]snapshot{}
		for _, id := range ids {
			f, ev, err := fs.Get(ctx, id)
			if err != nil {
				rt.Fatal(err)
			}
			before[id] = snapshot{f, ev}
		}

		ad.mu.Lock()
		ad.plans[asset] = plan
		ad.mu.Unlock()
		job, err := m.Enqueue(ctx, KindSecret, Target{Type: TargetRepository, ID: asset})
		if err != nil {
			rt.Fatal(err)
		}
		if mode == "cancel" {
			<-plan.started
			if err := m.Cancel(ctx, job.ID); err != nil {
				rt.Fatal(err)
			}
		}
		want := map[string]Status{"success": StatusSucceeded, "fail": StatusFailed, "cancel": StatusCancelled}[mode]
		var got Job
		for i := 0; i < 1000; i++ {
			got, _ = m.Get(ctx, job.ID)
			if got.Status == want {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if got.Status != want {
			rt.Fatalf("job status %s (reason %q), want %s", got.Status, got.Reason, want)
		}

		wantResolved := 0
		for _, id := range ids {
			after, ev, err := fs.Get(ctx, id)
			if err != nil {
				rt.Fatal(err)
			}
			b := before[id]
			if mode != "success" || seen[id] {
				if !reflect.DeepEqual(after, b.f) || !reflect.DeepEqual(ev, b.ev) {
					rt.Fatalf("mode %s: finding %s changed (seen=%v): %+v -> %+v, events %d -> %d", mode, id, seen[id], b.f, after, len(b.ev), len(ev))
				}
				continue
			}
			wantResolved++
			if after.Status != findings.StatusResolved || after.ResolvedAt == nil {
				rt.Fatalf("unseen finding %s not resolved after success: %+v", id, after)
			}
			if len(ev) != len(b.ev)+1 || !reflect.DeepEqual(ev[:len(b.ev)], b.ev) {
				rt.Fatalf("finding %s: events %d -> %d", id, len(b.ev), len(ev))
			}
			if last := ev[len(ev)-1]; last.New != findings.StatusResolved || last.Prev != b.f.Status {
				rt.Fatalf("finding %s: bad last event %+v", id, last)
			}
		}
		if mode == "success" && got.Resolved != wantResolved {
			rt.Fatalf("job resolved_count %d, want %d", got.Resolved, wantResolved)
		}
		if mode != "success" && got.Resolved != 0 {
			rt.Fatalf("job resolved_count %d after %s", got.Resolved, mode)
		}
	})
}
