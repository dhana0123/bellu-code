package scanners

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/config"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
)

// digestAdapter reports a settable digest and version and counts Run calls.
type digestAdapter struct {
	kind    Kind
	digest  *atomic.Value // string
	version *atomic.Value // string
	runs    *atomic.Int32
}

func (a digestAdapter) Kind() Kind                { return a.kind }
func (a digestAdapter) Info() Info                { return Info{Name: "dig", Version: a.version.Load().(string)} }
func (a digestAdapter) Applies(t TargetType) bool { return t == TargetRepository || t == TargetHost }
func (a digestAdapter) Digest(context.Context, Target) (string, error) {
	return a.digest.Load().(string), nil
}
func (a digestAdapter) Run(context.Context, Target, Sink) error { a.runs.Add(1); return nil }

type schedEnv struct {
	m       *Manager
	st      *sqlite.Store
	digest  *atomic.Value
	version *atomic.Value
	runs    *atomic.Int32
	clock   *clock
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func setupSched(t *testing.T, autoScan bool, kinds ...Kind) schedEnv {
	t.Helper()
	st, err := sqlite.Open(context.Background(), t.TempDir(), "ws1", sqlite.Options{Migrations: sqlitemigrations.FS})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e := schedEnv{st: st, digest: &atomic.Value{}, version: &atomic.Value{}, runs: &atomic.Int32{},
		clock: &clock{t: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}}
	e.digest.Store("d1")
	e.version.Store("1.0")
	var adapters []Adapter
	for _, k := range kinds {
		adapters = append(adapters, digestAdapter{k, e.digest, e.version, e.runs})
	}
	e.m, err = New(Config{
		Store:    st,
		Settings: config.Scanners{Parallel: 1, JobTimeout: time.Minute, AutoScan: autoScan},
		Adapters: adapters,
		Resolve: func(_ context.Context, typ TargetType, id string) (Target, bool, error) {
			return Target{Type: typ, ID: id}, true, nil
		},
		SinkFor: func(Job) JobSink { return &testSink{resolved: &atomic.Int32{}} },
		Now:     e.clock.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (e schedEnv) runJob(t *testing.T, k Kind, id string) Job {
	t.Helper()
	ctx := context.Background()
	j, err := e.m.Enqueue(ctx, k, Target{Type: TargetRepository, ID: id})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 400; i++ {
		got, _ := e.m.Get(ctx, j.ID)
		if got.Status != StatusQueued && got.Status != StatusRunning {
			e.clock.add(time.Second)
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("job did not finish")
	return Job{}
}

func TestSkipUnchanged(t *testing.T) {
	e := setupSched(t, false, KindSecret)
	if err := e.m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.m.Close)

	first := e.runJob(t, KindSecret, "repo1")
	if first.Status != StatusSucceeded || first.ContentDigest != "d1" {
		t.Fatalf("first job: %+v", first)
	}
	if j := e.runJob(t, KindSecret, "repo1"); j.Status != StatusSkippedUnchanged || j.ContentDigest != "d1" {
		t.Fatalf("same digest and version must skip: %+v", j)
	}
	if e.runs.Load() != 1 {
		t.Fatalf("adapter ran %d times, want 1", e.runs.Load())
	}
	e.digest.Store("d2")
	if j := e.runJob(t, KindSecret, "repo1"); j.Status != StatusSucceeded {
		t.Fatalf("changed digest must run: %+v", j)
	}
	e.version.Store("1.1")
	if j := e.runJob(t, KindSecret, "repo1"); j.Status != StatusSucceeded {
		t.Fatalf("changed adapter version must run: %+v", j)
	}
	if j := e.runJob(t, KindSecret, "repo2"); j.Status != StatusSucceeded {
		t.Fatalf("other target must run: %+v", j)
	}
}

func TestScheduleIntervalBounds(t *testing.T) {
	e := setupSched(t, false, KindSecret)
	ctx := context.Background()
	tg := Target{Type: TargetRepository, ID: "repo1"}
	for _, d := range []time.Duration{0, 15*time.Minute - time.Second, 30*24*time.Hour + time.Second} {
		if err := e.m.Schedule(ctx, Schedule{Kind: KindSecret, Target: tg, Interval: d, Enabled: true}); !errors.Is(err, ErrInvalidInterval) {
			t.Fatalf("interval %s: err %v", d, err)
		}
	}
	for _, d := range []time.Duration{15 * time.Minute, 30 * 24 * time.Hour} {
		if err := e.m.Schedule(ctx, Schedule{Kind: KindSecret, Target: tg, Interval: d, Enabled: true}); err != nil {
			t.Fatalf("interval %s: %v", d, err)
		}
	}
	if err := e.m.Schedule(ctx, Schedule{Kind: KindPosture, Target: tg, Interval: time.Hour}); !errors.Is(err, ErrKindNotApplicable) {
		t.Fatalf("unknown kind: %v", err)
	}
	var n int
	if err := e.st.DB().QueryRow(`SELECT count(*) FROM scan_schedule`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("schedule rows %d, %v; want one replaced row", n, err)
	}
}

func TestSchedulerSkipsBusyTarget(t *testing.T) {
	e := setupSched(t, false, KindSecret) // workers not started: jobs stay queued
	ctx := context.Background()
	tg := Target{Type: TargetRepository, ID: "repo1"}
	if err := e.m.Schedule(ctx, Schedule{Kind: KindSecret, Target: tg, Interval: time.Hour, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	s := NewScheduler(e.m)
	if n, err := s.RunDue(ctx); err != nil || n != 0 {
		t.Fatalf("not due yet: queued %d, %v", n, err)
	}
	e.clock.add(time.Hour)
	if n, err := s.RunDue(ctx); err != nil || n != 1 {
		t.Fatalf("due: queued %d, %v", n, err)
	}
	e.clock.add(time.Hour)
	if n, err := s.RunDue(ctx); err != nil || n != 0 {
		t.Fatalf("job still queued, schedule must be skipped: queued %d, %v", n, err)
	}
	jobs, _ := e.m.List(ctx, JobQuery{})
	if len(jobs) != 1 {
		t.Fatalf("jobs %d, want 1", len(jobs))
	}
	if err := e.m.Cancel(ctx, jobs[0].ID); err != nil {
		t.Fatal(err)
	}
	e.clock.add(time.Hour)
	if n, err := s.RunDue(ctx); err != nil || n != 1 {
		t.Fatalf("idle again: queued %d, %v", n, err)
	}
}

func TestAutoScanOnlyWhenEnabled(t *testing.T) {
	repo := batch.Entity{Type: "repository", Identity: map[string]string{"path": "/src/y"}}
	other := batch.Entity{Type: "user", Identity: map[string]string{"name": "u"}}
	b := graph.Batch{Entities: []batch.Entity{repo, other, repo}}
	id, err := identity.Hash("repository", repo.Identity)
	if err != nil {
		t.Fatal(err)
	}

	off := setupSched(t, false, KindPosture, KindVulnerability)
	if err := off.m.AutoScan(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	if jobs, _ := off.m.List(context.Background(), JobQuery{}); len(jobs) != 0 {
		t.Fatalf("auto_scan off queued %d jobs", len(jobs))
	}

	// data_classification has no adapter here: it is skipped, not an error.
	on := setupSched(t, true, KindPosture, KindVulnerability)
	if err := on.m.AutoScan(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	jobs, _ := on.m.List(context.Background(), JobQuery{})
	if len(jobs) != 2 {
		t.Fatalf("auto_scan on queued %d jobs, want posture and vulnerability for the repository once", len(jobs))
	}
	for _, j := range jobs {
		if j.Target.ID != string(id) || j.Target.Type != TargetRepository || j.Status != StatusQueued {
			t.Fatalf("unexpected job %+v", j)
		}
	}
}
