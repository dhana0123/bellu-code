package scanners

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"time"
)

// SchedulerTick is how often the Scheduler looks for due schedules (18.12).
const SchedulerTick = 30 * time.Second

// Scheduler enqueues jobs for due rows of scan_schedule.
type Scheduler struct {
	m      *Manager
	every  time.Duration
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewScheduler returns a stopped Scheduler that enqueues through m.
func NewScheduler(m *Manager) *Scheduler { return &Scheduler{m: m, every: SchedulerTick} }

// Start runs the tick loop until ctx ends or Close is called.
func (s *Scheduler) Start(ctx context.Context) {
	ctx, s.cancel = context.WithCancel(ctx)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		t := time.NewTicker(s.every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_, _ = s.RunDue(ctx)
			}
		}
	}()
}

// Close stops the tick loop.
func (s *Scheduler) Close() {
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
}

type dueSchedule struct {
	id       string
	kind     Kind
	target   Target
	interval time.Duration
}

// RunDue handles every enabled schedule whose next_at has passed and returns
// how many jobs it queued. A due schedule is always moved one interval ahead.
// It queues no job when one for the same target and kind is already queued or
// running, so a slow scan is not stacked on itself (18.12).
func (s *Scheduler) RunDue(ctx context.Context) (int, error) {
	m := s.m
	now := m.now()
	rows, err := m.cfg.Store.DB().QueryContext(ctx, `SELECT id, kind, target_type, target_id, interval_s FROM scan_schedule
		WHERE workspace_id=? AND enabled=1 AND next_at<=? ORDER BY next_at, id`, m.ws, fmtTime(now))
	if err != nil {
		return 0, err
	}
	var due []dueSchedule
	for rows.Next() {
		var d dueSchedule
		var secs int64
		if err := rows.Scan(&d.id, &d.kind, &d.target.Type, &d.target.ID, &secs); err != nil {
			rows.Close()
			return 0, err
		}
		d.interval = time.Duration(secs) * time.Second
		due = append(due, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	queued := 0
	var errs []error
	for _, d := range due {
		busy := false
		err := m.cfg.Store.Write(ctx, m.ws, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, `UPDATE scan_schedule SET next_at=? WHERE id=?`, fmtTime(now.Add(d.interval)), d.id); err != nil {
				return err
			}
			var n int
			err := tx.QueryRowContext(ctx, `SELECT count(*) FROM scan_job WHERE workspace_id=? AND kind=?
				AND target_type=? AND target_id=? AND status IN ('queued','running')`,
				m.ws, d.kind, d.target.Type, d.target.ID).Scan(&n)
			busy = n > 0
			return err
		})
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if busy {
			continue
		}
		if _, err := m.Enqueue(ctx, d.kind, d.target); err != nil {
			errs = append(errs, err)
			continue
		}
		queued++
	}
	return queued, errors.Join(errs...)
}
