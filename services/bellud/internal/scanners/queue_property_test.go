package scanners

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/config"
	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
)

// qpClock is a controlled clock. Every call returns the current time and then
// moves it forward by step, so a step of 0 gives a clock the test moves by hand.
type qpClock struct {
	mu   sync.Mutex
	t    time.Time
	step time.Duration
}

func (c *qpClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := c.t
	c.t = c.t.Add(c.step)
	return t
}

func (c *qpClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type qpSink struct{}

func (qpSink) Findings([]findings.Finding) error                         { return nil }
func (qpSink) ScannerError(string, string) error                         { return nil }
func (qpSink) Batch(batch.Batch) error                                   { return nil }
func (qpSink) Seen(string)                                               {}
func (qpSink) ResolveMissing(context.Context, Target, Kind) (int, error) { return 0, nil }
func (qpSink) Counts() (int, int)                                        { return 0, 0 }

// qpAdapter records the start of every run and the number running at once,
// then blocks until the test releases that target's gate.
type qpAdapter struct {
	kind    Kind
	started chan string
	gate    func(id string) chan struct{}
	cur     *atomic.Int32
	peak    *atomic.Int32
}

func (a qpAdapter) Kind() Kind                                     { return a.kind }
func (a qpAdapter) Info() Info                                     { return Info{Name: "qp", Version: "1"} }
func (a qpAdapter) Applies(t TargetType) bool                      { return t == TargetRepository }
func (a qpAdapter) Digest(context.Context, Target) (string, error) { return "", nil }
func (a qpAdapter) Run(ctx context.Context, t Target, _ Sink) error {
	n := a.cur.Add(1)
	for {
		p := a.peak.Load()
		if n <= p || a.peak.CompareAndSwap(p, n) {
			break
		}
	}
	defer a.cur.Add(-1)
	a.started <- t.ID
	select {
	case <-a.gate(t.ID):
	case <-ctx.Done():
	}
	return nil
}

func qpStore(t *testing.T, base string) *sqlite.Store {
	dir, err := os.MkdirTemp(base, "case")
	if err != nil {
		t.Fatal(err)
	}
	st, err := sqlite.Open(context.Background(), dir, "ws1", sqlite.Options{Migrations: sqlitemigrations.FS})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func qpResolve(_ context.Context, typ TargetType, id string) (Target, bool, error) {
	return Target{Type: typ, ID: id}, true, nil
}

func qpCount(t *rapid.T, st *sqlite.Store, q string, args ...any) int {
	var n int
	if err := st.DB().QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// Feature: bellu-wiz-security-platform, Property 29: Scan job queue discipline: jobs start FIFO by queued_at as slots free and never more than N run at once
// Validates: Requirements 18.4
func TestProperty29QueueFIFOAndConcurrencyCap(t *testing.T) {
	base := t.TempDir()
	rapid.Check(t, func(rt *rapid.T) {
		n := rapid.IntRange(1, 4).Draw(rt, "N")
		total := rapid.IntRange(1, 12).Draw(rt, "jobs")

		st := qpStore(t, base)
		defer st.Close()

		var gmu sync.Mutex
		gates := map[string]chan struct{}{}
		gate := func(id string) chan struct{} {
			gmu.Lock()
			defer gmu.Unlock()
			if gates[id] == nil {
				gates[id] = make(chan struct{})
			}
			return gates[id]
		}
		cur, peak := &atomic.Int32{}, &atomic.Int32{}
		started := make(chan string, total)
		clk := &qpClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), step: time.Second}
		m, err := New(Config{
			Store:       st,
			Settings:    config.Scanners{Parallel: n, JobTimeout: time.Minute},
			Adapters:    []Adapter{qpAdapter{KindSecret, started, gate, cur, peak}},
			Resolve:     qpResolve,
			SinkFor:     func(Job) JobSink { return qpSink{} },
			CancelGrace: 50 * time.Millisecond,
			Now:         clk.now,
		})
		if err != nil {
			rt.Fatal(err)
		}
		ctx := context.Background()
		ids := make([]string, total)
		for i := range ids {
			j, err := m.Enqueue(ctx, KindSecret, Target{Type: TargetRepository, ID: fmt.Sprintf("repo%d", i)})
			if err != nil {
				rt.Fatal(err)
			}
			ids[i] = j.ID
		}
		if err := m.Start(ctx); err != nil {
			rt.Fatal(err)
		}
		defer m.Close()
		defer func() { // free blocked adapters so Close returns at once
			for i := 0; i < total; i++ {
				g := gate(fmt.Sprintf("repo%d", i))
				select {
				case <-g:
				default:
					close(g)
				}
			}
		}()

		startedSet := map[int]bool{}
		var live []int // started, not yet released
		waitFor := func(want int) {
			for len(startedSet) < want {
				select {
				case id := <-started:
					var idx int
					fmt.Sscanf(id, "repo%d", &idx)
					startedSet[idx] = true
					live = append(live, idx)
				case <-time.After(10 * time.Second):
					rt.Fatalf("timed out waiting for %d started jobs, have %d", want, len(startedSet))
				}
			}
			// FIFO: exactly the first `want` queued jobs have started.
			for i := 0; i < total; i++ {
				if startedSet[i] != (i < want) {
					rt.Fatalf("after %d starts, job %d started=%v; started set %v", want, i, startedSet[i], startedSet)
				}
			}
			if r := qpCount(rt, st, `SELECT count(*) FROM scan_job WHERE status='running'`); r > n {
				rt.Fatalf("%d jobs running with limit %d", r, n)
			}
		}

		waitFor(min(n, total))
		for released := 0; released < total; released++ {
			k := rapid.IntRange(0, len(live)-1).Draw(rt, "release")
			idx := live[k]
			live = append(live[:k], live[k+1:]...)
			close(gate(fmt.Sprintf("repo%d", idx)))
			waitFor(min(total, n+released+1))
		}

		deadline := time.Now().Add(10 * time.Second)
		for qpCount(rt, st, `SELECT count(*) FROM scan_job WHERE status='succeeded'`) < total {
			if time.Now().After(deadline) {
				rt.Fatalf("jobs did not finish")
			}
			time.Sleep(time.Millisecond)
		}
		if p := int(peak.Load()); p > n || p != min(n, total) {
			rt.Fatalf("peak concurrency %d, want %d (limit %d)", p, min(n, total), n)
		}
		var prev time.Time
		for i, id := range ids {
			j, err := m.Get(ctx, id)
			if err != nil || j.StartedAt == nil {
				rt.Fatalf("job %d: %v %+v", i, err, j)
			}
			if i > 0 && !j.StartedAt.After(prev) {
				rt.Fatalf("job %d started at %s, not after job %d at %s", i, j.StartedAt, i-1, prev)
			}
			prev = *j.StartedAt
		}
	})
}

// Feature: bellu-wiz-security-platform, Property 29: Scan job queue discipline: a schedule never enqueues a job for a target and kind that already has a queued or running job
// Validates: Requirements 18.12
func TestProperty29ScheduleNeverDuplicatesActiveJob(t *testing.T) {
	base := t.TempDir()
	kinds := []Kind{KindSecret, KindSBOM}
	rapid.Check(t, func(rt *rapid.T) {
		targets := rapid.IntRange(1, 6).Draw(rt, "targets")
		interval := time.Duration(rapid.IntRange(15, 600).Draw(rt, "minutes")) * time.Minute

		st := qpStore(t, base)
		defer st.Close()
		clk := &qpClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
		cur, peak := &atomic.Int32{}, &atomic.Int32{}
		var adapters []Adapter
		for _, k := range kinds {
			adapters = append(adapters, qpAdapter{kind: k, cur: cur, peak: peak})
		}
		m, err := New(Config{
			Store:    st,
			Settings: config.Scanners{Parallel: 1, JobTimeout: time.Minute},
			Adapters: adapters,
			Resolve:  qpResolve,
			SinkFor:  func(Job) JobSink { return qpSink{} },
			Now:      clk.now,
		})
		if err != nil {
			rt.Fatal(err)
		}
		ctx := context.Background()
		sched := NewScheduler(m)

		type pair struct {
			k      Kind
			id     string
			active int
		}
		var pairs []pair
		seq := 0
		insert := func(p pair, status string) {
			seq++
			err := st.Write(ctx, "ws1", func(tx *sql.Tx) error {
				_, err := tx.ExecContext(ctx, `INSERT INTO scan_job(id, workspace_id, kind, target_type, target_id, status, queued_at)
					VALUES(?,?,?,?,?,?,?)`, fmt.Sprintf("sj_pre%d", seq), "ws1", p.k, TargetRepository, p.id, status, fmtTime(clk.now()))
				return err
			})
			if err != nil {
				rt.Fatal(err)
			}
		}
		for i := 0; i < targets; i++ {
			for _, k := range kinds {
				p := pair{k: k, id: fmt.Sprintf("repo%d", i)}
				if err := m.Schedule(ctx, Schedule{Kind: k, Target: Target{Type: TargetRepository, ID: p.id}, Interval: interval, Enabled: true}); err != nil {
					rt.Fatal(err)
				}
				q := rapid.IntRange(0, 2).Draw(rt, "queued")
				r := rapid.IntRange(0, 1).Draw(rt, "running")
				done := rapid.IntRange(0, 1).Draw(rt, "finished")
				for j := 0; j < q; j++ {
					insert(p, "queued")
				}
				for j := 0; j < r; j++ {
					insert(p, "running")
				}
				for j := 0; j < done; j++ {
					insert(p, "succeeded")
				}
				p.active = q + r
				pairs = append(pairs, p)
			}
		}

		total := func(p pair) int {
			return qpCount(rt, st, `SELECT count(*) FROM scan_job WHERE kind=? AND target_id=?`, p.k, p.id)
		}
		activeCount := func(p pair) int {
			return qpCount(rt, st, `SELECT count(*) FROM scan_job WHERE kind=? AND target_id=? AND status IN ('queued','running')`, p.k, p.id)
		}
		before := map[pair]int{}
		for _, p := range pairs {
			before[p] = total(p)
		}

		// Nothing is due yet.
		if n, err := sched.RunDue(ctx); err != nil || n != 0 {
			rt.Fatalf("RunDue before due time: %d, %v", n, err)
		}
		want := 0
		for _, p := range pairs {
			if p.active == 0 {
				want++
			}
		}
		clk.add(interval)
		n, err := sched.RunDue(ctx)
		if err != nil {
			rt.Fatal(err)
		}
		if n != want {
			rt.Fatalf("RunDue queued %d jobs, want %d", n, want)
		}
		for _, p := range pairs {
			wantTotal := before[p]
			if p.active == 0 {
				wantTotal++
			}
			if got := total(p); got != wantTotal {
				rt.Fatalf("%s %s had %d jobs (active %d), now %d, want %d", p.k, p.id, before[p], p.active, got, wantTotal)
			}
			if p.active == 0 && activeCount(p) != 1 {
				rt.Fatalf("%s %s has %d active jobs, want 1", p.k, p.id, activeCount(p))
			}
		}

		// Next interval: every pair now has an active job, so nothing is added.
		clk.add(interval)
		if n, err := sched.RunDue(ctx); err != nil || n != 0 {
			rt.Fatalf("second RunDue queued %d, %v", n, err)
		}
		for _, p := range pairs {
			wantTotal := before[p]
			if p.active == 0 {
				wantTotal++
			}
			if got := total(p); got != wantTotal {
				rt.Fatalf("%s %s grew to %d, want %d", p.k, p.id, got, wantTotal)
			}
		}
	})
}
