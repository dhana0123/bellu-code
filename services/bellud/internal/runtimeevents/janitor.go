package runtimeevents

import (
	"context"
	"database/sql"
	"sync"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
)

const (
	DefaultRetentionDays = 7
	MaxRetentionDays     = 90
	DefaultMaxBytes      = int64(5) << 30
	JanitorInterval      = 30 * time.Second
)

// JanitorConfig configures the retention and size janitor.
type JanitorConfig struct {
	Store       *sqlite.Store
	WorkspaceID string
	// RetentionDays is clamped to 1..90; 0 means the default of 7.
	RetentionDays int
	// MaxBytes caps the summed size_bytes; 0 means the default of 5 GB.
	MaxBytes int64
	// Interval defaults to 30 s.
	Interval time.Duration
	Now      func() time.Time
}

// Janitor deletes the oldest runtime_event rows until retention and size cap hold.
type Janitor struct {
	cfg    JanitorConfig
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func (c *JanitorConfig) normalize() {
	if c.RetentionDays == 0 {
		c.RetentionDays = DefaultRetentionDays
	}
	c.RetentionDays = min(max(c.RetentionDays, 1), MaxRetentionDays)
	if c.MaxBytes <= 0 {
		c.MaxBytes = DefaultMaxBytes
	}
	if c.Interval <= 0 {
		c.Interval = JanitorInterval
	}
	if c.Now == nil {
		c.Now = time.Now
	}
}

// StartJanitor sweeps once, then every Interval until Stop.
func StartJanitor(cfg JanitorConfig) *Janitor {
	cfg.normalize()
	ctx, cancel := context.WithCancel(context.Background())
	j := &Janitor{cfg: cfg, cancel: cancel}
	j.wg.Add(1)
	go func() {
		defer j.wg.Done()
		t := time.NewTicker(cfg.Interval)
		defer t.Stop()
		for {
			_, _ = j.Sweep(ctx)
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	return j
}

// Stop ends the loop and waits for an in-flight sweep.
func (j *Janitor) Stop() {
	j.cancel()
	j.wg.Wait()
}

// Sweep deletes rows older than the retention, then the oldest rows while the
// total size exceeds the cap. It returns the number of rows deleted.
func (j *Janitor) Sweep(ctx context.Context) (int64, error) {
	c := j.cfg
	cutoff := c.Now().UTC().AddDate(0, 0, -c.RetentionDays).Format(time.RFC3339Nano)
	var deleted int64
	err := c.Store.Write(ctx, c.WorkspaceID, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM runtime_event WHERE workspace_id=? AND ts<?`, c.WorkspaceID, cutoff)
		if err != nil {
			return err
		}
		deleted, _ = res.RowsAffected()
		var total int64
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(size_bytes),0) FROM runtime_event WHERE workspace_id=?`, c.WorkspaceID).Scan(&total); err != nil || total <= c.MaxBytes {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT seq, size_bytes FROM runtime_event WHERE workspace_id=? ORDER BY ts, seq`, c.WorkspaceID)
		if err != nil {
			return err
		}
		var seqs []int64
		for rows.Next() && total > c.MaxBytes {
			var seq, size int64
			if err := rows.Scan(&seq, &size); err != nil {
				rows.Close()
				return err
			}
			seqs = append(seqs, seq)
			total -= size
		}
		rows.Close()
		for _, s := range seqs {
			if _, err := tx.ExecContext(ctx, `DELETE FROM runtime_event WHERE seq=?`, s); err != nil {
				return err
			}
		}
		deleted += int64(len(seqs))
		return nil
	})
	return deleted, err
}
