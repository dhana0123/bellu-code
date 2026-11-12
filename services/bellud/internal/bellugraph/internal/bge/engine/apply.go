package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/codec"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/plan"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

// Apply validates, plans and appends one Batch, then folds it into the
// Projection and publishes the resulting changes. A Batch that changes nothing
// appends nothing and still returns a Receipt with a fresh ULID.
func (c *Core) Apply(ctx context.Context, b batch.Batch, mode Mode) (Receipt, error) {
	start := time.Now()
	// 1. Gate.
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	if err := c.writable(); err != nil {
		c.met.BatchRejected("unavailable")
		return Receipt{}, err
	}
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	if err := c.writable(); err != nil {
		c.met.BatchRejected("unavailable")
		return Receipt{}, err
	}

	// 2. Validate and plan against the Projection.
	now := c.clock().UTC()
	c.mu.RLock()
	res, err := plan.Plan(c.g, b, mode, now)
	c.mu.RUnlock()
	if err != nil {
		c.met.BatchRejected("validation")
		return Receipt{}, err
	}

	// 3. No-op.
	if len(res.Events) == 0 {
		id := c.ulids.next(c.recordedAt(now))
		c.met.BatchApplied(res.Collector)
		return Receipt{
			ID: id.String(), ObservedAt: res.ObservedAt, RecordedAt: c.recordedAt(now),
			Entities: res.Entities, Relations: res.Relations, Removed: res.Removed,
		}, nil
	}

	// 4-6. Encode, write, project, publish.
	evs, err := c.commit(res.Events, now)
	if err != nil {
		c.met.BatchRejected("store")
		c.log.Error("graph batch rejected: store write failed", "collector", res.Collector, "error", err.Error())
		return Receipt{}, err
	}
	c.met.BatchApplied(res.Collector)
	c.met.ObserveApply(time.Since(start))

	// 7. Receipt.
	return Receipt{
		ID:         ulid.ULID(evs[0].ULID).String(),
		ObservedAt: res.ObservedAt,
		RecordedAt: time.Unix(0, evs[0].RecordedNS).UTC(),
		Entities:   res.Entities, Relations: res.Relations, Removed: res.Removed,
	}, nil
}

// writable reports ErrUnavailable unless the Engine is ready for writes.
func (c *Core) writable() error {
	if c.closing.Load() {
		return fmt.Errorf("%w: graph engine is closing", errs.Unavailable)
	}
	if s := c.State(); s != StateReady {
		return fmt.Errorf("%w: graph engine is %s", errs.Unavailable, s)
	}
	return nil
}

// recordedAt is the Recorded_Time for a write at now: never before the last
// recorded Event. The caller holds applyMu.
func (c *Core) recordedAt(now time.Time) time.Time {
	if now.Before(c.g.LastRT) {
		return c.g.LastRT
	}
	return now
}

// commit stamps the planned Events (sequence, ULID, Recorded_Time), appends
// them in one synced store batch, folds them into the Projection and publishes
// them. The caller holds applyMu. On a store error nothing changes.
func (c *Core) commit(evs []codec.Event, now time.Time) ([]codec.Event, error) {
	rec := c.recordedAt(now)
	rns := rec.UnixNano()
	seq := c.g.LastSeq
	sb := c.st.NewBatch()
	for i := range evs {
		ev := &evs[i]
		seq++
		ev.Seq = seq
		ev.ULID = c.ulids.next(rec)
		ev.RecordedNS = rns
		switch ev.Type {
		case codec.EntityCreated:
			id, err := ident.Hash(ev.Kind, ev.Identity)
			if err != nil {
				sb.Close()
				return nil, err
			}
			ev.ID = id
		case codec.Annotated:
			ev.ValidNS = rns
		}
		if err := sb.AddEvent(*ev); err != nil {
			sb.Close()
			return nil, err
		}
	}
	if err := sb.SetSeq(seq); err != nil {
		sb.Close()
		return nil, err
	}
	if err := sb.Commit(); err != nil {
		if errors.Is(err, errs.Validation) {
			return nil, err
		}
		return nil, fmt.Errorf("appending batch: %w", err)
	}

	c.mu.Lock()
	for _, ev := range evs {
		c.g.Fold(ev)
	}
	c.mu.Unlock()

	c.publish(evs)
	counts := map[string]int{}
	for _, ev := range evs {
		counts[eventTypeName(ev.Type)]++
	}
	for t, n := range counts {
		c.met.EventsAppended(t, n)
	}
	c.syncGauges()
	if n := c.eventsSinceSnap.Add(uint64(len(evs))); n >= uint64(c.opts.SnapshotEvery) {
		select {
		case c.snapKick <- struct{}{}:
		default:
		}
	}
	return evs, nil
}

func eventTypeName(t codec.EventType) string {
	switch t {
	case codec.EntityCreated:
		return "entity_created"
	case codec.EntityUpdated:
		return "entity_updated"
	case codec.EntityRemoved:
		return "entity_removed"
	case codec.RelationAdded:
		return "relation_added"
	case codec.RelationRemoved:
		return "relation_removed"
	case codec.Annotated:
		return "annotated"
	case codec.ScopeDelta:
		return "scope_delta"
	}
	return "unknown"
}
