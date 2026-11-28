package scanners

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/config"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
)

// DefaultCancelGrace is how long a worker waits for an adapter to return after
// its context ends before it records the outcome anyway. It keeps cancel
// within 10 seconds (18.7) even when an adapter ignores its context.
const DefaultCancelGrace = 5 * time.Second

var errPanic = errors.New("scanners: adapter panic")

const timeLayout = "2006-01-02T15:04:05.000000000Z" // fixed width, sorts as text

// Config configures a Manager.
type Config struct {
	Store    *sqlite.Store
	Settings config.Scanners
	Adapters []Adapter
	// Resolve looks a target up. ok is false when it does not exist.
	Resolve func(ctx context.Context, typ TargetType, id string) (t Target, ok bool, err error)
	// SinkFor returns the sink for one job.
	SinkFor func(j Job) JobSink
	// CancelGrace defaults to DefaultCancelGrace.
	CancelGrace time.Duration
	// OnSucceeded, when set, is called after a job ends with status succeeded.
	OnSucceeded func(ctx context.Context, j Job)
	Now         func() time.Time
}

// Manager is the Orchestrator backed by the scan_job table.
type Manager struct {
	cfg      Config
	amu      sync.RWMutex // guards adapters; Register may run after Start
	adapters map[Kind]Adapter
	ws       string

	mu      sync.Mutex // serialises claim and cancel
	running map[string]*runState

	wake   chan struct{}
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type runState struct {
	cancel    context.CancelFunc
	cancelled atomic.Bool
}

var _ Orchestrator = (*Manager)(nil)

// New validates cfg and returns a stopped Manager.
func New(cfg Config) (*Manager, error) {
	if cfg.Store == nil || cfg.Resolve == nil || cfg.SinkFor == nil {
		return nil, errors.New("scanners: Store, Resolve and SinkFor are required")
	}
	if err := cfg.Settings.Validate(); err != nil {
		return nil, err
	}
	if cfg.CancelGrace <= 0 {
		cfg.CancelGrace = DefaultCancelGrace
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	m := &Manager{
		cfg:      cfg,
		adapters: map[Kind]Adapter{},
		ws:       cfg.Store.WorkspaceID(),
		running:  map[string]*runState{},
		wake:     make(chan struct{}, cfg.Settings.Parallel),
	}
	for _, a := range cfg.Adapters {
		m.adapters[a.Kind()] = a
	}
	return m, nil
}

func (m *Manager) adapter(k Kind) (Adapter, bool) {
	m.amu.RLock()
	defer m.amu.RUnlock()
	a, ok := m.adapters[k]
	return a, ok
}

// Register adds adapters, replacing any of the same kind. It is safe to call
// while the Manager runs.
func (m *Manager) Register(as ...Adapter) {
	m.amu.Lock()
	defer m.amu.Unlock()
	for _, a := range as {
		m.adapters[a.Kind()] = a
	}
}

func (m *Manager) now() time.Time { return m.cfg.Now().UTC() }

func fmtTime(t time.Time) string { return t.UTC().Format(timeLayout) }

// Start marks jobs left running by a previous process as failed with reason
// restarted, then starts the worker pool.
func (m *Manager) Start(ctx context.Context) error {
	err := m.cfg.Store.Write(ctx, m.ws, func(tx *sql.Tx) error {
		now := fmtTime(m.now())
		_, err := tx.ExecContext(ctx, `UPDATE scan_job SET status='failed', reason=?, ended_at=?
			WHERE workspace_id=? AND status='running'`, ReasonRestarted, now, m.ws)
		return err
	})
	if err != nil {
		return err
	}
	ctx, m.cancel = context.WithCancel(ctx)
	for i := 0; i < m.cfg.Settings.Parallel; i++ {
		m.wg.Add(1)
		go m.worker(ctx)
	}
	return nil
}

// Close stops the workers. Running jobs end as failed with reason shutdown.
func (m *Manager) Close() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
}

func newID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "sj_" + hex.EncodeToString(b)
}

// Enqueue implements Orchestrator.
func (m *Manager) Enqueue(ctx context.Context, k Kind, t Target) (Job, error) {
	a, ok := m.adapter(k)
	if !ok || !a.Applies(t.Type) {
		return Job{}, fmt.Errorf("%w: kind %q on target type %q", ErrKindNotApplicable, k, t.Type)
	}
	if _, ok, err := m.cfg.Resolve(ctx, t.Type, t.ID); err != nil {
		return Job{}, err
	} else if !ok {
		return Job{}, fmt.Errorf("%w: %s %q", ErrTargetNotFound, t.Type, t.ID)
	}
	j := Job{ID: newID(), Kind: k, Target: Target{Type: t.Type, ID: t.ID}, Status: StatusQueued, QueuedAt: m.now(), ScannerVersions: map[string]string{}}
	err := m.cfg.Store.Write(ctx, m.ws, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM scan_job
			WHERE workspace_id=? AND target_type=? AND target_id=? AND status='queued'`,
			m.ws, t.Type, t.ID).Scan(&n); err != nil {
			return err
		}
		if n >= MaxQueuedPerTarget {
			return fmt.Errorf("%w: %d jobs already queued for %s %q", ErrQueueFull, n, t.Type, t.ID)
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO scan_job(id, workspace_id, kind, target_type, target_id, status, queued_at)
			VALUES(?,?,?,?,?,'queued',?)`, j.ID, m.ws, k, t.Type, t.ID, fmtTime(j.QueuedAt))
		return err
	})
	if err != nil {
		return Job{}, err
	}
	select {
	case m.wake <- struct{}{}:
	default:
	}
	return j, nil
}

// Schedule implements Orchestrator.
func (m *Manager) Schedule(ctx context.Context, s Schedule) error {
	if s.Interval < MinScheduleInterval || s.Interval > MaxScheduleInterval {
		return fmt.Errorf("%w: %s", ErrInvalidInterval, s.Interval)
	}
	if a, ok := m.adapter(s.Kind); !ok || !a.Applies(s.Target.Type) {
		return fmt.Errorf("%w: kind %q on target type %q", ErrKindNotApplicable, s.Kind, s.Target.Type)
	}
	if _, ok, err := m.cfg.Resolve(ctx, s.Target.Type, s.Target.ID); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("%w: %s %q", ErrTargetNotFound, s.Target.Type, s.Target.ID)
	}
	next := fmtTime(m.now().Add(s.Interval))
	return m.cfg.Store.Write(ctx, m.ws, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO scan_schedule(id, workspace_id, kind, target_type, target_id, interval_s, next_at, enabled)
			VALUES(?,?,?,?,?,?,?,?)
			ON CONFLICT(workspace_id, kind, target_type, target_id)
			DO UPDATE SET interval_s=excluded.interval_s, next_at=excluded.next_at, enabled=excluded.enabled`,
			"ss_"+newID()[3:], m.ws, s.Kind, s.Target.Type, s.Target.ID, int64(s.Interval/time.Second), next, s.Enabled)
		return err
	})
}

// Cancel implements Orchestrator.
func (m *Manager) Cancel(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var changed int64
	err := m.cfg.Store.Write(ctx, m.ws, func(tx *sql.Tx) error {
		r, err := tx.ExecContext(ctx, `UPDATE scan_job SET status='cancelled', ended_at=?
			WHERE workspace_id=? AND id=? AND status='queued'`, fmtTime(m.now()), m.ws, id)
		if err != nil {
			return err
		}
		changed, err = r.RowsAffected()
		return err
	})
	if err != nil || changed > 0 {
		return err
	}
	if rs, ok := m.running[id]; ok {
		rs.cancelled.Store(true)
		rs.cancel()
		return nil
	}
	if _, err := m.Get(ctx, id); err != nil {
		return err
	}
	return ErrNotCancellable
}

const jobCols = `id, kind, target_type, target_id, status, reason, queued_at, started_at, ended_at,
	created_count, updated_count, resolved_count, content_digest, scanner_versions, duration_ms`

type scanner interface{ Scan(...any) error }

func scanJob(r scanner) (Job, error) {
	var j Job
	var reason, started, ended, digest sql.NullString
	var queued, versions string
	var dur sql.NullInt64
	if err := r.Scan(&j.ID, &j.Kind, &j.Target.Type, &j.Target.ID, &j.Status, &reason, &queued, &started, &ended,
		&j.Created, &j.Updated, &j.Resolved, &digest, &versions, &dur); err != nil {
		return Job{}, err
	}
	j.Reason, j.ContentDigest = reason.String, digest.String
	j.QueuedAt, _ = time.Parse(timeLayout, queued)
	if started.Valid {
		t, _ := time.Parse(timeLayout, started.String)
		j.StartedAt = &t
	}
	if ended.Valid {
		t, _ := time.Parse(timeLayout, ended.String)
		j.EndedAt = &t
	}
	if dur.Valid {
		d := time.Duration(dur.Int64) * time.Millisecond
		j.Duration = &d
	}
	_ = json.Unmarshal([]byte(versions), &j.ScannerVersions)
	return j, nil
}

// Get implements Orchestrator.
func (m *Manager) Get(ctx context.Context, id string) (Job, error) {
	j, err := scanJob(m.cfg.Store.DB().QueryRowContext(ctx,
		`SELECT `+jobCols+` FROM scan_job WHERE workspace_id=? AND id=?`, m.ws, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Job{}, ErrJobNotFound
	}
	return j, err
}

// List implements Orchestrator. Newest first.
func (m *Manager) List(ctx context.Context, q JobQuery) ([]Job, error) {
	if q.Limit <= 0 {
		q.Limit = 100
	}
	rows, err := m.cfg.Store.DB().QueryContext(ctx, `SELECT `+jobCols+` FROM scan_job
		WHERE workspace_id=? AND (?='' OR status=?) AND (?='' OR kind=?)
		ORDER BY queued_at DESC, rowid DESC LIMIT ?`,
		m.ws, string(q.Status), string(q.Status), string(q.Kind), string(q.Kind), q.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// claim moves the oldest queued job to running. ok is false when none is queued.
func (m *Manager) claim(ctx context.Context, runCtx context.Context) (Job, *runState, context.Context, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var j Job
	var found bool
	err := m.cfg.Store.Write(ctx, m.ws, func(tx *sql.Tx) error {
		var err error
		j, err = scanJob(tx.QueryRowContext(ctx, `SELECT `+jobCols+` FROM scan_job
			WHERE workspace_id=? AND status='queued' ORDER BY queued_at, rowid LIMIT 1`, m.ws))
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		} else if err != nil {
			return err
		}
		found = true
		now := m.now()
		j.Status, j.StartedAt = StatusRunning, &now
		_, err = tx.ExecContext(ctx, `UPDATE scan_job SET status='running', started_at=? WHERE id=?`, fmtTime(now), j.ID)
		return err
	})
	if err != nil || !found {
		return Job{}, nil, nil, false, err
	}
	jobCtx, cancel := context.WithTimeout(runCtx, m.cfg.Settings.JobTimeout)
	rs := &runState{cancel: cancel}
	m.running[j.ID] = rs
	return j, rs, jobCtx, true, nil
}

func (m *Manager) worker(ctx context.Context) {
	defer m.wg.Done()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for ctx.Err() == nil {
		j, rs, jobCtx, ok, err := m.claim(ctx, ctx)
		if err == nil && ok {
			m.run(ctx, j, rs, jobCtx)
			continue
		}
		select {
		case <-ctx.Done():
		case <-m.wake:
		case <-tick.C:
		}
	}
}

func (m *Manager) run(base context.Context, j Job, rs *runState, jobCtx context.Context) {
	defer rs.cancel()
	start := time.Now()
	sink := m.cfg.SinkFor(j)
	a, _ := m.adapter(j.Kind)
	versions := map[string]string{}
	var status Status
	var reason string
	var resolved int
	var digest string

	t, ok, err := m.cfg.Resolve(jobCtx, j.Target.Type, j.Target.ID)
	switch {
	case err != nil:
		status, reason = StatusFailed, ReasonScannerError
	case !ok:
		status, reason = StatusFailed, ReasonTargetNotFound
	default:
		versions = adapterVersions(a.Info())
		if d, derr := safeDigest(jobCtx, a, t); derr == nil && d != "" && jobCtx.Err() == nil {
			digest = d
			if m.unchanged(jobCtx, j, d, versions) {
				m.finish(base, j, StatusSkippedUnchanged, "", d, 0, sink, versions, start)
				return
			}
		}
		done := make(chan error, 1)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					done <- errPanic
				}
			}()
			done <- a.Run(jobCtx, t, sink)
		}()
		var runErr error
		select {
		case runErr = <-done:
		case <-jobCtx.Done():
			select {
			case runErr = <-done:
			case <-time.After(m.cfg.CancelGrace):
				runErr = jobCtx.Err()
			}
		}
		status, reason = m.outcome(base, jobCtx, rs, runErr)
		if status == StatusSucceeded {
			resolved, err = sink.ResolveMissing(jobCtx, t, j.Kind)
			if err != nil {
				status, reason, resolved = StatusFailed, ReasonResolveFailed, 0
				if rs.cancelled.Load() {
					status, reason = StatusCancelled, ""
				}
			}
		}
	}

	m.finish(base, j, status, reason, digest, resolved, sink, versions, start)
}

// finish records the job outcome and releases its run slot.
func (m *Manager) finish(base context.Context, j Job, status Status, reason, digest string, resolved int, sink JobSink, versions map[string]string, start time.Time) {
	created, updated := sink.Counts()
	dur := time.Since(start).Milliseconds()
	vj, _ := json.Marshal(versions)
	ctx := context.WithoutCancel(base)
	_ = m.cfg.Store.Write(ctx, m.ws, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE scan_job SET status=?, reason=NULLIF(?,''), ended_at=?,
			created_count=?, updated_count=?, resolved_count=?, content_digest=NULLIF(?,''), scanner_versions=?, duration_ms=? WHERE id=?`,
			status, reason, fmtTime(m.now()), created, updated, resolved, digest, string(vj), dur, j.ID)
		return err
	})
	m.mu.Lock()
	delete(m.running, j.ID)
	m.mu.Unlock()
	if status == StatusSucceeded && m.cfg.OnSucceeded != nil {
		m.cfg.OnSucceeded(ctx, j)
	}
}

// adapterVersions is the adapter version set compared by skip-unchanged: the
// adapter version plus each pinned library version.
func adapterVersions(i Info) map[string]string {
	v := map[string]string{i.Name: i.Version}
	for lib, ver := range i.Libraries {
		v[i.Name+"/"+lib] = ver
	}
	return v
}

// safeDigest turns an adapter panic into an error so the job runs instead.
func safeDigest(ctx context.Context, a Adapter, t Target) (d string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errPanic
		}
	}()
	return a.Digest(ctx, t)
}

// unchanged reports whether the last succeeded job of the same target and kind
// has the same digest and adapter version set (18.8).
func (m *Manager) unchanged(ctx context.Context, j Job, digest string, versions map[string]string) bool {
	var prevDigest sql.NullString
	var prevVersions string
	err := m.cfg.Store.DB().QueryRowContext(ctx, `SELECT content_digest, scanner_versions FROM scan_job
		WHERE workspace_id=? AND target_type=? AND target_id=? AND kind=? AND status='succeeded'
		ORDER BY ended_at DESC, rowid DESC LIMIT 1`, m.ws, j.Target.Type, j.Target.ID, j.Kind).Scan(&prevDigest, &prevVersions)
	if err != nil || prevDigest.String != digest {
		return false
	}
	var prev map[string]string
	return json.Unmarshal([]byte(prevVersions), &prev) == nil && maps.Equal(prev, versions)
}

// outcome maps the adapter result and context state to a final status.
func (m *Manager) outcome(base, jobCtx context.Context, rs *runState, runErr error) (Status, string) {
	switch {
	case rs.cancelled.Load():
		return StatusCancelled, ""
	case errors.Is(jobCtx.Err(), context.DeadlineExceeded):
		return StatusFailed, ReasonTimeout
	case base.Err() != nil:
		return StatusFailed, ReasonShutdown
	case runErr == nil:
		return StatusSucceeded, ""
	case errors.Is(runErr, ErrTargetUnreachable):
		return StatusFailed, ReasonTargetUnreachable
	case errors.Is(runErr, ErrCredentialsRejected):
		return StatusFailed, ReasonCredentialsRejected
	case errors.Is(runErr, errPanic):
		return StatusFailed, ReasonPanic
	default:
		return StatusFailed, ReasonScannerError
	}
}
