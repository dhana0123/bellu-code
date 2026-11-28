package scanners

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/config"
	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
)

type testSink struct {
	mu       sync.Mutex
	created  int
	resolved *atomic.Int32
}

func (s *testSink) Findings(fs []findings.Finding) error {
	s.mu.Lock()
	s.created += len(fs)
	s.mu.Unlock()
	return nil
}
func (s *testSink) ScannerError(string, string) error { return nil }
func (s *testSink) Batch(batch.Batch) error           { return nil }
func (s *testSink) Seen(string)                       {}
func (s *testSink) Counts() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.created, 0
}
func (s *testSink) ResolveMissing(context.Context, Target, Kind) (int, error) {
	s.resolved.Add(1)
	return 0, nil
}

type testAdapter struct {
	run func(ctx context.Context, t Target, out Sink) error
}

func (a testAdapter) Kind() Kind                                     { return KindSecret }
func (a testAdapter) Info() Info                                     { return Info{Name: "test", Version: "1.0"} }
func (a testAdapter) Applies(t TargetType) bool                      { return t == TargetRepository }
func (a testAdapter) Digest(context.Context, Target) (string, error) { return "", nil }
func (a testAdapter) Run(ctx context.Context, t Target, out Sink) error {
	return a.run(ctx, t, out)
}

type env struct {
	m        *Manager
	st       *sqlite.Store
	resolved *atomic.Int32
}

func setup(t *testing.T, parallel int, timeout time.Duration, run func(context.Context, Target, Sink) error) env {
	t.Helper()
	st, err := sqlite.Open(context.Background(), t.TempDir(), "ws1", sqlite.Options{Migrations: sqlitemigrations.FS})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	resolved := &atomic.Int32{}
	m, err := New(Config{
		Store:    st,
		Settings: config.Scanners{Parallel: parallel, JobTimeout: timeout},
		Adapters: []Adapter{testAdapter{run}},
		Resolve: func(_ context.Context, typ TargetType, id string) (Target, bool, error) {
			return Target{Type: typ, ID: id, Path: "/x/" + id}, strings.HasPrefix(id, "repo"), nil
		},
		SinkFor:     func(Job) JobSink { return &testSink{resolved: resolved} },
		CancelGrace: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return env{m, st, resolved}
}

func (e env) start(t *testing.T) {
	t.Helper()
	if err := e.m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.m.Close)
}

func (e env) wait(t *testing.T, id string, want Status) Job {
	t.Helper()
	var j Job
	for i := 0; i < 400; i++ {
		j, _ = e.m.Get(context.Background(), id)
		if j.Status == want {
			return j
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("job %s status %s (reason %q), want %s", id, j.Status, j.Reason, want)
	return j
}

func TestFIFOOrderAndResolveOnSuccess(t *testing.T) {
	var mu sync.Mutex
	var order []string
	e := setup(t, 1, time.Minute, func(_ context.Context, tg Target, out Sink) error {
		mu.Lock()
		order = append(order, tg.ID)
		mu.Unlock()
		return out.Findings([]findings.Finding{{}})
	})
	var ids []string
	for i := 0; i < 5; i++ { // enqueue before start so all are queued
		j, err := e.m.Enqueue(context.Background(), KindSecret, Target{Type: TargetRepository, ID: fmt.Sprintf("repo%d", i)})
		if err != nil || j.Status != StatusQueued {
			t.Fatal(j, err)
		}
		ids = append(ids, j.ID)
	}
	e.start(t)
	last := e.wait(t, ids[4], StatusSucceeded)
	if last.Created != 1 || last.Duration == nil || last.StartedAt == nil || last.EndedAt == nil || last.ScannerVersions["test"] != "1.0" {
		t.Fatalf("job record incomplete: %+v", last)
	}
	if got := strings.Join(order, ","); got != "repo0,repo1,repo2,repo3,repo4" {
		t.Fatalf("order %s", got)
	}
	if e.resolved.Load() != 5 {
		t.Fatalf("ResolveMissing calls %d", e.resolved.Load())
	}
}

func TestConcurrencyCap(t *testing.T) {
	var cur, peak atomic.Int32
	release := make(chan struct{})
	e := setup(t, 2, time.Minute, func(ctx context.Context, _ Target, _ Sink) error {
		n := cur.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		defer cur.Add(-1)
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil
	})
	e.start(t)
	var ids []string
	for i := 0; i < 6; i++ {
		j, err := e.m.Enqueue(context.Background(), KindSecret, Target{Type: TargetRepository, ID: fmt.Sprintf("repo%d", i)})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, j.ID)
	}
	time.Sleep(300 * time.Millisecond)
	if peak.Load() != 2 {
		t.Fatalf("peak %d, want 2", peak.Load())
	}
	close(release)
	e.wait(t, ids[5], StatusSucceeded)
	if peak.Load() != 2 {
		t.Fatalf("peak %d after drain, want 2", peak.Load())
	}
}

func TestAdmissionErrorsCreateNoRow(t *testing.T) {
	e := setup(t, 1, time.Minute, func(context.Context, Target, Sink) error { return nil })
	ctx := context.Background()
	if _, err := e.m.Enqueue(ctx, KindSecret, Target{Type: TargetImage, ID: "repo1"}); !errors.Is(err, ErrKindNotApplicable) {
		t.Fatalf("got %v", err)
	}
	if _, err := e.m.Enqueue(ctx, KindSBOM, Target{Type: TargetRepository, ID: "repo1"}); !errors.Is(err, ErrKindNotApplicable) {
		t.Fatalf("unknown kind: %v", err)
	}
	if _, err := e.m.Enqueue(ctx, KindSecret, Target{Type: TargetRepository, ID: "missing"}); !errors.Is(err, ErrTargetNotFound) {
		t.Fatalf("got %v", err)
	}
	// Fill the queue directly, then the 1,001st request is rejected.
	if _, err := e.st.DB().Exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<1000)
		INSERT INTO scan_job(id, workspace_id, kind, target_type, target_id, status, queued_at)
		SELECT 'f'||i, 'ws1', 'secret', 'repository', 'repo1', 'queued', '2020-01-01T00:00:00.000000000Z' FROM n`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.Enqueue(ctx, KindSecret, Target{Type: TargetRepository, ID: "repo1"}); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("got %v", err)
	}
	if _, err := e.m.Enqueue(ctx, KindSecret, Target{Type: TargetRepository, ID: "repo2"}); err != nil {
		t.Fatalf("other target: %v", err)
	}
	var n int
	e.st.DB().QueryRow(`SELECT count(*) FROM scan_job`).Scan(&n)
	if n != 1001 {
		t.Fatalf("rows %d, want 1001", n)
	}
}

func TestTimeoutKeepsFindingsAndRecordsDuration(t *testing.T) {
	e := setup(t, 1, 30*time.Second, nil)
	e.m.cfg.Settings.JobTimeout = 150 * time.Millisecond // below the config floor, test only
	e.m.cfg.Adapters = nil
	e.m.adapters[KindSecret] = testAdapter{func(ctx context.Context, _ Target, out Sink) error {
		_ = out.Findings([]findings.Finding{{}, {}})
		<-ctx.Done()
		return ctx.Err()
	}}
	e.start(t)
	j, _ := e.m.Enqueue(context.Background(), KindSecret, Target{Type: TargetRepository, ID: "repo1"})
	got := e.wait(t, j.ID, StatusFailed)
	if got.Reason != ReasonTimeout || got.Created != 2 || got.Duration == nil || *got.Duration < 100*time.Millisecond {
		t.Fatalf("%+v", got)
	}
	if e.resolved.Load() != 0 {
		t.Fatal("ResolveMissing called after failed scan")
	}
}

func TestCancelQueuedAndRunning(t *testing.T) {
	started := make(chan struct{}, 1)
	e := setup(t, 1, time.Minute, func(ctx context.Context, _ Target, _ Sink) error {
		started <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	})
	e.start(t)
	ctx := context.Background()
	run, _ := e.m.Enqueue(ctx, KindSecret, Target{Type: TargetRepository, ID: "repo1"})
	<-started
	queued, _ := e.m.Enqueue(ctx, KindSecret, Target{Type: TargetRepository, ID: "repo2"})
	if err := e.m.Cancel(ctx, queued.ID); err != nil {
		t.Fatal(err)
	}
	e.wait(t, queued.ID, StatusCancelled)
	t0 := time.Now()
	if err := e.m.Cancel(ctx, run.ID); err != nil {
		t.Fatal(err)
	}
	e.wait(t, run.ID, StatusCancelled)
	if time.Since(t0) > 10*time.Second {
		t.Fatal("cancel too slow")
	}
	if err := e.m.Cancel(ctx, run.ID); !errors.Is(err, ErrNotCancellable) {
		t.Fatalf("got %v", err)
	}
	if err := e.m.Cancel(ctx, "nope"); !errors.Is(err, ErrJobNotFound) {
		t.Fatalf("got %v", err)
	}
	if e.resolved.Load() != 0 {
		t.Fatal("ResolveMissing called after cancel")
	}
}

func TestCancelStopsAdapterThatIgnoresContext(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	e := setup(t, 1, time.Minute, func(context.Context, Target, Sink) error { <-block; return nil })
	e.start(t)
	j, _ := e.m.Enqueue(context.Background(), KindSecret, Target{Type: TargetRepository, ID: "repo1"})
	e.wait(t, j.ID, StatusRunning)
	if err := e.m.Cancel(context.Background(), j.ID); err != nil {
		t.Fatal(err)
	}
	e.wait(t, j.ID, StatusCancelled)
}

func TestRestartMarksRunningFailed(t *testing.T) {
	e := setup(t, 1, time.Minute, func(context.Context, Target, Sink) error { return nil })
	if _, err := e.st.DB().Exec(`INSERT INTO scan_job(id, workspace_id, kind, target_type, target_id, status, queued_at, started_at)
		VALUES('old','ws1','secret','repository','repo1','running','2020-01-01T00:00:00.000000000Z','2020-01-01T00:00:01.000000000Z')`); err != nil {
		t.Fatal(err)
	}
	e.start(t)
	j, err := e.m.Get(context.Background(), "old")
	if err != nil || j.Status != StatusFailed || j.Reason != ReasonRestarted || j.EndedAt == nil {
		t.Fatalf("%+v %v", j, err)
	}
}

func TestAdapterErrorReasons(t *testing.T) {
	e := setup(t, 1, time.Minute, func(context.Context, Target, Sink) error {
		return fmt.Errorf("dial: %w", ErrTargetUnreachable)
	})
	e.start(t)
	j, _ := e.m.Enqueue(context.Background(), KindSecret, Target{Type: TargetRepository, ID: "repo1"})
	if got := e.wait(t, j.ID, StatusFailed); got.Reason != ReasonTargetUnreachable {
		t.Fatalf("%+v", got)
	}
}
