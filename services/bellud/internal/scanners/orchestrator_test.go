package scanners

// Orchestrator unit tests (task 5.5; Requirements 18.5, 18.6, 18.7, 18.13).
// They run a real in-process adapter that writes through the real
// findings.JobSink onto a real findings.Store. manager_test.go keeps the
// minimal FIFO, cap and reason checks; these tests cover what it does not.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/config"
	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
)

// orchJobSink adapts the real findings.JobSink to scanners.JobSink.
type orchJobSink struct{ *findings.JobSink }

func (s orchJobSink) Batch(batch.Batch) error { return nil }

func (s orchJobSink) ResolveMissing(ctx context.Context, t Target, k Kind) (int, error) {
	return s.JobSink.ResolveMissing(ctx, t.ID, string(k))
}

// orchAdapter is a secret scanner whose behaviour the test supplies.
type orchAdapter struct {
	run func(ctx context.Context, t Target, out Sink) error
}

func (orchAdapter) Kind() Kind                                     { return KindSecret }
func (orchAdapter) Info() Info                                     { return Info{Name: "orch", Version: "1"} }
func (orchAdapter) Applies(t TargetType) bool                      { return t == TargetRepository }
func (orchAdapter) Digest(context.Context, Target) (string, error) { return "", nil }
func (a orchAdapter) Run(ctx context.Context, t Target, out Sink) error {
	return a.run(ctx, t, out)
}

type orchEnv struct {
	m   *Manager
	st  *sqlite.Store
	fs  *findings.Store
	dir string
}

func orchOpen(t *testing.T, dir string) (*sqlite.Store, *findings.Store) {
	t.Helper()
	st, err := sqlite.Open(context.Background(), dir, "ws1", sqlite.Options{Migrations: sqlitemigrations.FS})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	fs := findings.New(st)
	t.Cleanup(fs.Close)
	return st, fs
}

func orchManager(t *testing.T, st *sqlite.Store, fs *findings.Store, grace time.Duration, run func(context.Context, Target, Sink) error) *Manager {
	t.Helper()
	m, err := New(Config{
		Store:    st,
		Settings: config.Scanners{Parallel: 1, JobTimeout: time.Minute},
		Adapters: []Adapter{orchAdapter{run}},
		Resolve: func(_ context.Context, typ TargetType, id string) (Target, bool, error) {
			return Target{Type: typ, ID: id, Path: "/x/" + id}, strings.HasPrefix(id, "repo"), nil
		},
		SinkFor: func(j Job) JobSink {
			return orchJobSink{fs.JobSink(context.Background(), findings.ScanRef{JobID: j.ID})}
		},
		CancelGrace: grace,
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func orchEnvFor(t *testing.T, grace time.Duration, run func(context.Context, Target, Sink) error) orchEnv {
	t.Helper()
	dir := t.TempDir()
	st, fs := orchOpen(t, dir)
	return orchEnv{m: orchManager(t, st, fs, grace, run), st: st, fs: fs, dir: dir}
}

func (e orchEnv) start(t *testing.T) {
	t.Helper()
	if err := e.m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.m.Close)
}

// await polls until the job reaches want or 15 s pass.
func (e orchEnv) await(t *testing.T, id string, want Status) Job {
	t.Helper()
	var j Job
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		j, _ = e.m.Get(context.Background(), id)
		if j.Status == want {
			return j
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("job %s status %s (reason %q), want %s", id, j.Status, j.Reason, want)
	return j
}

func (e orchEnv) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := e.st.DB().QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// orchFinding is a valid secret finding on asset, unique per n.
func orchFinding(asset string, n int) findings.Finding {
	return findings.Finding{
		ID:       findings.ID("orch.secret", asset, fmt.Sprint(n)),
		RuleID:   "orch.secret",
		Title:    fmt.Sprintf("secret %d", n),
		Category: schema.OvSecrets,
		Type:     findings.TypeSecret,
		Severity: findings.SevHigh,
		Status:   findings.StatusOpen,
		AssetID:  asset,
		Source:   string(KindSecret),
	}
}

func TestOrchestratorAdmissionRejectionKinds(t *testing.T) {
	e := orchEnvFor(t, time.Second, func(context.Context, Target, Sink) error { return nil })
	ctx := context.Background()
	admission := []*AdmissionError{ErrKindNotApplicable, ErrTargetNotFound, ErrQueueFull}

	reject := func(name string, k Kind, tg Target, want *AdmissionError) {
		t.Helper()
		_, err := e.m.Enqueue(ctx, k, tg)
		var ae *AdmissionError
		if !errors.As(err, &ae) || ae.Code != want.Code {
			t.Fatalf("%s: got %v, want admission code %q", name, err, want.Code)
		}
		for _, other := range admission {
			if other.Code != want.Code && errors.Is(err, other) {
				t.Fatalf("%s: error also matches %q", name, other.Code)
			}
		}
	}
	reject("wrong target type", KindSecret, Target{Type: TargetImage, ID: "repo1"}, ErrKindNotApplicable)
	reject("kind without adapter", KindSBOM, Target{Type: TargetRepository, ID: "repo1"}, ErrKindNotApplicable)
	reject("unknown target", KindSecret, Target{Type: TargetRepository, ID: "gone"}, ErrTargetNotFound)

	if n := e.count(t, `SELECT count(*) FROM scan_job`); n != 0 {
		t.Fatalf("%d scan_job rows after kind and target rejections", n)
	}

	// Exactly MaxQueuedPerTarget queued jobs are admitted; the next is rejected.
	if _, err := e.st.DB().Exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<?)
		INSERT INTO scan_job(id, workspace_id, kind, target_type, target_id, status, queued_at)
		SELECT 'q'||i, 'ws1', 'secret', 'repository', 'repo1', 'queued', '2020-01-01T00:00:00.000000000Z' FROM n`,
		MaxQueuedPerTarget-1); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.Enqueue(ctx, KindSecret, Target{Type: TargetRepository, ID: "repo1"}); err != nil {
		t.Fatalf("job number %d: %v", MaxQueuedPerTarget, err)
	}
	reject("queue full", KindSecret, Target{Type: TargetRepository, ID: "repo1"}, ErrQueueFull)
	if n := e.count(t, `SELECT count(*) FROM scan_job WHERE target_id='repo1'`); n != MaxQueuedPerTarget {
		t.Fatalf("rows %d after queue_full rejection, want %d", n, MaxQueuedPerTarget)
	}
	// The limit is per target, and running or finished jobs do not count.
	if _, err := e.m.Enqueue(ctx, KindSecret, Target{Type: TargetRepository, ID: "repo2"}); err != nil {
		t.Fatalf("other target: %v", err)
	}
}

func TestOrchestratorJobTimeoutBounds(t *testing.T) {
	cases := []struct {
		d  time.Duration
		ok bool
	}{
		{0, false},
		{30*time.Second - time.Nanosecond, false},
		{29 * time.Second, false},
		{30 * time.Second, true},
		{time.Hour, true},
		{24 * time.Hour, true},
		{24*time.Hour + time.Nanosecond, false},
		{25 * time.Hour, false},
	}
	for _, c := range cases {
		s := config.Scanners{Parallel: 1, JobTimeout: c.d}
		if err := s.Validate(); (err == nil) != c.ok {
			t.Errorf("Validate(%s): err=%v, want ok=%v", c.d, err, c.ok)
		}
		st, _ := orchOpen(t, t.TempDir())
		_, err := New(Config{
			Store: st, Settings: s,
			Resolve: func(context.Context, TargetType, string) (Target, bool, error) { return Target{}, false, nil },
			SinkFor: func(Job) JobSink { return nil },
		})
		if (err == nil) != c.ok {
			t.Errorf("New with job timeout %s: err=%v, want ok=%v", c.d, err, c.ok)
		}
	}
}

func TestOrchestratorTimeoutKeepsStoredFindings(t *testing.T) {
	e := orchEnvFor(t, 200*time.Millisecond, func(ctx context.Context, tg Target, out Sink) error {
		if err := out.Findings([]findings.Finding{orchFinding(tg.ID, 1), orchFinding(tg.ID, 2)}); err != nil {
			return err
		}
		<-ctx.Done()
		return ctx.Err()
	})
	// Below the config floor on purpose: Validate guards the real bound in
	// TestOrchestratorJobTimeoutBounds, and a 30 s wait would slow the suite.
	e.m.cfg.Settings.JobTimeout = 300 * time.Millisecond

	// A finding from an earlier scan that this scan does not report again.
	// A failed scan must not resolve it.
	prior := orchFinding("repo1", 99)
	if _, err := e.fs.Report(context.Background(), findings.ScanRef{JobID: "earlier"}, []findings.Finding{prior}); err != nil {
		t.Fatal(err)
	}
	e.start(t)
	j, err := e.m.Enqueue(context.Background(), KindSecret, Target{Type: TargetRepository, ID: "repo1"})
	if err != nil {
		t.Fatal(err)
	}
	got := e.await(t, j.ID, StatusFailed)
	if got.Reason != ReasonTimeout {
		t.Fatalf("reason %q, want %q", got.Reason, ReasonTimeout)
	}
	if got.Created != 2 || got.Resolved != 0 {
		t.Fatalf("created %d resolved %d, want 2 and 0", got.Created, got.Resolved)
	}
	if got.Duration == nil || *got.Duration < 250*time.Millisecond {
		t.Fatalf("duration %v not recorded or shorter than the limit", got.Duration)
	}
	if got.EndedAt == nil || got.StartedAt == nil {
		t.Fatalf("missing timestamps: %+v", got)
	}
	if n := e.count(t, `SELECT count(*) FROM finding WHERE workspace_id='ws1' AND asset_id='repo1' AND status='open'`); n != 3 {
		t.Fatalf("%d open findings in the store, want 3 (2 written before timeout, 1 prior)", n)
	}
}

func TestOrchestratorCancelRunningKeepsStoredFindings(t *testing.T) {
	written := make(chan struct{})
	e := orchEnvFor(t, 200*time.Millisecond, func(ctx context.Context, tg Target, out Sink) error {
		if err := out.Findings([]findings.Finding{orchFinding(tg.ID, 1)}); err != nil {
			return err
		}
		close(written)
		<-ctx.Done()
		return ctx.Err()
	})
	e.start(t)
	j, _ := e.m.Enqueue(context.Background(), KindSecret, Target{Type: TargetRepository, ID: "repo1"})
	<-written
	if err := e.m.Cancel(context.Background(), j.ID); err != nil {
		t.Fatal(err)
	}
	got := e.await(t, j.ID, StatusCancelled)
	if got.Reason != "" || got.Created != 1 || got.Resolved != 0 {
		t.Fatalf("%+v", got)
	}
	if n := e.count(t, `SELECT count(*) FROM finding WHERE workspace_id='ws1' AND asset_id='repo1' AND status='open'`); n != 1 {
		t.Fatalf("%d open findings in the store, want 1", n)
	}
}

// An adapter that never looks at its context must still be cancelled within
// 10 s using the production grace period (18.7).
func TestOrchestratorCancelWithinTenSecondsWhenAdapterIgnoresContext(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the default cancel grace")
	}
	written, block := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() { close(block) })
	e := orchEnvFor(t, DefaultCancelGrace, func(_ context.Context, tg Target, out Sink) error {
		if err := out.Findings([]findings.Finding{orchFinding(tg.ID, 1)}); err != nil {
			return err
		}
		close(written)
		<-block // ignores ctx
		return nil
	})
	e.start(t)
	j, _ := e.m.Enqueue(context.Background(), KindSecret, Target{Type: TargetRepository, ID: "repo1"})
	<-written
	t0 := time.Now()
	if err := e.m.Cancel(context.Background(), j.ID); err != nil {
		t.Fatal(err)
	}
	got := e.await(t, j.ID, StatusCancelled)
	if d := time.Since(t0); d > 10*time.Second {
		t.Fatalf("cancel took %s, want at most 10s", d)
	}
	if got.Created != 1 || got.EndedAt == nil {
		t.Fatalf("%+v", got)
	}
	if n := e.count(t, `SELECT count(*) FROM finding WHERE asset_id='repo1' AND status='open'`); n != 1 {
		t.Fatalf("%d open findings, want 1", n)
	}
}

// A process that died mid-scan leaves a running row and the findings that scan
// had written. The next Start fails the row with reason restarted, keeps the
// findings, and still runs jobs that were only queued.
func TestOrchestratorRestartRecovery(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	// First process: a real scan writes two findings, then the process "dies"
	// with the job still running.
	st1, fs1 := orchOpen(t, dir)
	crashed := orchJobSink{fs1.JobSink(ctx, findings.ScanRef{JobID: "crashed"})}
	if err := crashed.Findings([]findings.Finding{orchFinding("repo1", 1), orchFinding("repo1", 2)}); err != nil {
		t.Fatal(err)
	}
	if _, err := st1.DB().Exec(`INSERT INTO scan_job(id, workspace_id, kind, target_type, target_id, status, queued_at, started_at)
		VALUES('crashed','ws1','secret','repository','repo1','running','2020-01-01T00:00:00.000000000Z','2020-01-01T00:00:01.000000000Z'),
		      ('waiting','ws1','secret','repository','repo2','queued','2020-01-01T00:00:02.000000000Z',NULL)`); err != nil {
		t.Fatal(err)
	}
	fs1.Close()
	st1.Close()

	// Second process on the same database.
	st2, fs2 := orchOpen(t, dir)
	ran := make(chan string, 4)
	m2 := orchManager(t, st2, fs2, time.Second, func(_ context.Context, tg Target, _ Sink) error { ran <- tg.ID; return nil })
	e := orchEnv{m: m2, st: st2, fs: fs2, dir: dir}
	e.start(t)

	got, err := m2.Get(ctx, "crashed")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusFailed || got.Reason != ReasonRestarted || got.EndedAt == nil {
		t.Fatalf("crashed job: %+v", got)
	}
	e.await(t, "waiting", StatusSucceeded)
	select {
	case id := <-ran:
		if id != "repo2" {
			t.Fatalf("scanner ran for %q, want only repo2", id)
		}
	default:
		t.Fatal("queued job did not run after restart")
	}
	select {
	case id := <-ran:
		t.Fatalf("restarted job was run again for %q", id)
	case <-time.After(200 * time.Millisecond):
	}
	if n := e.count(t, `SELECT count(*) FROM finding WHERE workspace_id='ws1' AND asset_id='repo1' AND status='open'`); n != 2 {
		t.Fatalf("%d open findings kept for the restarted job, want 2", n)
	}
	if n := e.count(t, `SELECT count(*) FROM scan_job WHERE status='running'`); n != 0 {
		t.Fatalf("%d rows still running", n)
	}
}
