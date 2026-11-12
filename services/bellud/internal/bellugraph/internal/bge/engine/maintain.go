package engine

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/codec"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/store"
)

// retentionChunk is the number of Events deleted per synced batch.
const retentionChunk = store.DefaultChunk

// startMaintenance runs the Snapshot and retention loop until bgCtx ends.
// One goroutine does both jobs, so Snapshot pruning and retention deletes
// never overlap.
func (c *Core) startMaintenance() {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		snapT := time.NewTicker(c.opts.SnapshotInterval)
		defer snapT.Stop()
		var retC <-chan time.Time
		if c.opts.Retention > 0 {
			retT := time.NewTicker(c.opts.RetentionCheck)
			defer retT.Stop()
			retC = retT.C
		}
		for {
			select {
			case <-c.bgCtx.Done():
				return
			case <-snapT.C:
				c.maintainSnapshot()
			case <-c.snapKick:
				c.maintainSnapshot()
			case <-retC:
				if _, err := c.runRetention(c.bgCtx); err != nil && c.bgCtx.Err() == nil {
					c.log.Error("retention failed", "error", err.Error())
				}
			}
		}
	}()
}

func (c *Core) maintainSnapshot() {
	if c.State() == StateFailed {
		return
	}
	if err := c.writeSnapshot(); err != nil {
		c.log.Error("snapshot failed", "error", err.Error())
	}
}

// pruneSnapshots keeps the newest SnapshotKeep Snapshots plus the base
// Snapshot and deletes the rest. The caller holds snapMu.
func (c *Core) pruneSnapshots() error {
	hs, err := c.st.ListSnapshots()
	if err != nil {
		return err
	}
	var baseSeq uint64
	if base, ok, err := c.st.Base(); err != nil {
		return err
	} else if ok {
		baseSeq = base.Seq
	}
	sort.Slice(hs, func(i, j int) bool { return hs[i].Seq > hs[j].Seq })
	var drop []uint64
	for i, h := range hs {
		if i >= c.opts.SnapshotKeep && !(baseSeq > 0 && h.Seq == baseSeq) {
			drop = append(drop, h.Seq)
		}
	}
	return c.st.DeleteSnapshots(drop...)
}

// eventEntityID returns the entity ID of an entity or annotation Event.
func eventEntityID(ev codec.Event) string {
	if ev.Type == codec.EntityCreated {
		id, err := ident.Hash(ev.Kind, ev.Identity)
		if err != nil {
			return ""
		}
		return id
	}
	return ev.ID
}

// runRetention deletes Events whose Recorded_Time is older than the
// retention window. It writes the boundary Snapshot together with m/base
// first, then deletes in chunks. It returns the number of Events deleted.
// Events up to the boundary are immutable, so no writer lock is needed.
func (c *Core) runRetention(ctx context.Context) (int, error) {
	if c.opts.Retention <= 0 || c.State() == StateFailed {
		return 0, nil
	}
	cutoff := c.clock().Add(-c.opts.Retention).UnixNano()

	c.snapMu.Lock()
	defer c.snapMu.Unlock()

	v := c.st.NewView()
	last, err := v.Seq()
	if err != nil {
		v.Close()
		return 0, err
	}
	base, hasBase, err := v.Base()
	if err != nil {
		v.Close()
		return 0, err
	}
	// Binary search for the greatest b in (baseSeq, last] with recorded < cutoff.
	lo, hi, b := base.Seq+1, last, uint64(0)
	for lo <= hi {
		mid := lo + (hi-lo)/2
		ev, err := v.Event(mid)
		if err != nil {
			v.Close()
			return 0, fmt.Errorf("retention search at %d: %w", mid, err)
		}
		if ev.RecordedNS < cutoff {
			b, lo = mid, mid+1
		} else {
			hi = mid - 1
		}
	}
	if b == 0 {
		v.Close()
		return c.finishDeletes(ctx, base, hasBase)
	}

	// Build the state at b and write the boundary Snapshot with m/base.
	g, _, err := loadGraph(boundedReader{v, b})
	v.Close()
	if err != nil {
		return 0, fmt.Errorf("retention state build: %w", err)
	}
	snap := g.Export()
	h, err := c.st.WriteSnapshot(toStoreSnapshot(snap), &store.Base{Seq: b, HorizonNS: snap.Header.MaxVTNS})
	if err != nil {
		return 0, fmt.Errorf("writing boundary snapshot: %w", err)
	}
	c.log.Info("retention boundary", "seq", b, "horizon_ns", h.MaxVTNS)
	return c.finishDeletes(ctx, store.Base{Seq: b, HorizonNS: h.MaxVTNS}, true)
}

// finishDeletes removes Events with seq <= base.Seq in chunks and then the
// Snapshots older than the base. It also resumes an interrupted run. The
// caller holds snapMu.
func (c *Core) finishDeletes(ctx context.Context, base store.Base, hasBase bool) (int, error) {
	if !hasBase || base.Seq == 0 {
		return 0, nil
	}
	total := 0
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		through, ok, err := c.nextChunkEnd(base.Seq)
		if err != nil {
			return total, err
		}
		if !ok {
			break
		}
		n, err := c.st.DeleteEventsThrough(through, retentionChunk, eventEntityID)
		total += n
		c.met.RetentionDeleted(n)
		if err != nil {
			return total, fmt.Errorf("deleting events: %w", err)
		}
	}
	hs, err := c.st.ListSnapshots()
	if err != nil {
		return total, err
	}
	var drop []uint64
	for _, h := range hs {
		if h.Seq < base.Seq {
			drop = append(drop, h.Seq)
		}
	}
	if err := c.st.DeleteSnapshots(drop...); err != nil {
		return total, err
	}
	return total, nil
}

// nextChunkEnd returns the last sequence of the next chunk to delete, capped
// at limit; ok is false when no Event at or below limit remains.
func (c *Core) nextChunkEnd(limit uint64) (uint64, bool, error) {
	v := c.st.NewView()
	defer v.Close()
	it, err := v.Events(0, limit)
	if err != nil {
		return 0, false, err
	}
	defer it.Close()
	if !it.Next() {
		return 0, false, it.Err()
	}
	first := it.Seq()
	end := first + retentionChunk - 1
	if end > limit {
		end = limit
	}
	return end, true, nil
}

// boundedReader presents a store view as if the log ended at seq.
type boundedReader struct {
	*store.View
	seq uint64
}

func (r boundedReader) Seq() (uint64, error) { return r.seq, nil }

// Events caps the range at seq, so folding never passes the boundary.
func (r boundedReader) Events(from, to uint64) (*store.EventIter, error) {
	if to == 0 || to > r.seq {
		to = r.seq
	}
	return r.View.Events(from, to)
}
