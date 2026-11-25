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
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
	"pgregory.net/rapid"
)

type skipPlan struct {
	digest, version string
	fail            bool
	report          []findings.Finding
	runs            int
}

// skipAdapter is an in-process adapter whose digest and version are set per
// target, and which counts Run calls.
type skipAdapter struct {
	mu    sync.Mutex
	plans map[string]*skipPlan
}

func (a *skipAdapter) plan(id string) *skipPlan {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.plans[id]
}
func (a *skipAdapter) Kind() Kind                { return KindSecret }
func (a *skipAdapter) Applies(t TargetType) bool { return t == TargetRepository }
func (a *skipAdapter) Info() Info {
	// Info has no target; the version is read from the single active target.
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, p := range a.plans {
		if p.version != "" {
			return Info{Name: "skip", Version: p.version}
		}
	}
	return Info{Name: "skip", Version: "0"}
}
func (a *skipAdapter) Digest(_ context.Context, t Target) (string, error) {
	return a.plan(t.ID).digest, nil
}
func (a *skipAdapter) Run(_ context.Context, t Target, out Sink) error {
	a.mu.Lock()
	p := a.plans[t.ID]
	p.runs++
	a.mu.Unlock()
	if p.fail {
		return errors.New("scanner blew up")
	}
	if len(p.report) > 0 {
		return out.Findings(p.report)
	}
	return nil
}

// Feature: bellu-wiz-security-platform, Property 30: Skip-unchanged leaves findings untouched. When the content digest and scanner version set match the last succeeded job, the new job does not run the scanner, is skipped_unchanged and leaves the asset's Findings byte-identical; any change, or a last job that did not succeed, makes the scanner run.
// **Validates: Requirements 18.8**
func TestPropertySkipUnchangedLeavesFindingsUntouched(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, t.TempDir(), "ws1", sqlite.Options{Migrations: sqlitemigrations.FS})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	fs := findings.New(db)
	t.Cleanup(fs.Close)
	ad := &skipAdapter{plans: map[string]*skipPlan{}}
	m, err := New(Config{
		Store:    db,
		Settings: config.Scanners{Parallel: 1, JobTimeout: time.Minute},
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

	runJob := func(rt *rapid.T, asset string, want Status) Job {
		job, err := m.Enqueue(ctx, KindSecret, Target{Type: TargetRepository, ID: asset})
		if err != nil {
			rt.Fatal(err)
		}
		var got Job
		for i := 0; i < 1000; i++ {
			got, _ = m.Get(ctx, job.ID)
			if got.Status == want {
				return got
			}
			time.Sleep(5 * time.Millisecond)
		}
		rt.Fatalf("job status %s (reason %q), want %s", got.Status, got.Reason, want)
		return got
	}

	iter := 0
	rapid.Check(t, func(rt *rapid.T) {
		iter++
		asset := fmt.Sprintf("repo-%d", iter)
		n := rapid.IntRange(0, 6).Draw(rt, "n")
		var ids []string
		var reported []findings.Finding
		for i := 0; i < n; i++ {
			id := fmt.Sprintf("f-%d-%d", iter, i)
			ids = append(ids, id)
			reported = append(reported, findings.Finding{ID: id, RuleID: "r", Title: rapid.StringN(1, 20, -1).Draw(rt, "title"),
				Category: "code_and_dependencies", Type: findings.TypeVulnerability,
				Severity: rapid.SampledFrom([]findings.Severity{findings.SevHigh, findings.SevLow}).Draw(rt, "sev"),
				AssetID:  asset, Source: string(KindSecret)})
		}
		digest := rapid.StringMatching(`[a-f0-9]{8}`).Draw(rt, "digest")
		version := rapid.StringMatching(`[1-9]\.[0-9]`).Draw(rt, "version")
		plan := &skipPlan{digest: digest, version: version, report: reported}
		ad.mu.Lock()
		ad.plans = map[string]*skipPlan{asset: plan} // one active target, so Info() is unambiguous
		ad.mu.Unlock()

		prevFailed := rapid.Bool().Draw(rt, "prevFailed")
		if prevFailed {
			plan.fail = true
			runJob(rt, asset, StatusFailed)
			plan.fail = false
			if plan.runs != 1 {
				rt.Fatalf("runs %d after failed job", plan.runs)
			}
			// Same digest and version, but the previous job did not succeed: must run.
			runJob(rt, asset, StatusSucceeded)
			if plan.runs != 2 {
				rt.Fatalf("scanner did not run after failed job: runs %d", plan.runs)
			}
			return
		}

		runJob(rt, asset, StatusSucceeded)
		if plan.runs != 1 {
			rt.Fatalf("first job: runs %d", plan.runs)
		}
		before := map[string]snapshot{}
		for _, id := range ids {
			f, ev, err := fs.Get(ctx, id)
			if err != nil {
				rt.Fatal(err)
			}
			before[id] = snapshot{f, ev}
		}

		changeDigest := rapid.Bool().Draw(rt, "changeDigest")
		changeVersion := rapid.Bool().Draw(rt, "changeVersion")
		if changeDigest {
			plan.digest = digest + "x"
		}
		if changeVersion {
			plan.version = version + "x"
		}
		if changeDigest || changeVersion {
			runJob(rt, asset, StatusSucceeded)
			if plan.runs != 2 {
				rt.Fatalf("scanner did not run after change (digest=%v version=%v): runs %d", changeDigest, changeVersion, plan.runs)
			}
			return
		}
		got := runJob(rt, asset, StatusSkippedUnchanged)
		if plan.runs != 1 {
			rt.Fatalf("scanner ran for skipped job: runs %d", plan.runs)
		}
		if got.Created != 0 || got.Updated != 0 || got.Resolved != 0 {
			rt.Fatalf("skipped job counts %d/%d/%d", got.Created, got.Updated, got.Resolved)
		}
		for _, id := range ids {
			f, ev, err := fs.Get(ctx, id)
			if err != nil {
				rt.Fatal(err)
			}
			if b := before[id]; !reflect.DeepEqual(f, b.f) || !reflect.DeepEqual(ev, b.ev) {
				rt.Fatalf("finding %s changed by skipped job: %+v -> %+v", id, b.f, f)
			}
		}
	})
}
