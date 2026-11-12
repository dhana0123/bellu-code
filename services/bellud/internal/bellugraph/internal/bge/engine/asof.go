package engine

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/codec"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/graph"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/query"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/store"
)

// DiffView is the difference between the states at two instants. Added and
// Changed carry the state at the later instant. Lists are capped at
// query.DiffCap and Truncated is set when a cap was hit.
type DiffView struct {
	From, To  time.Time
	Added     []EntityView
	Changed   []EntityView
	Removed   []EntityID
	Flapping  []Flap
	Truncated bool
}

// StateAt returns the Projection produced by folding, in log order, every
// Event with Valid_Time at or before at. The result is private to the caller.
// An instant before the Retention_Horizon returns errs.Validation.
func (c *Core) StateAt(ctx context.Context, at time.Time) (*graph.Graph, error) {
	done, err := c.begin(ctx, "state_at")
	if err != nil {
		return nil, err
	}
	defer done()
	v := c.st.NewView()
	defer v.Close()
	return c.guard(stateAt(ctx, v, at))
}

// guard fails the Engine on a corrupt read.
func (c *Core) guard(g *graph.Graph, err error) (*graph.Graph, error) {
	if err != nil && errors.Is(err, errs.Corrupt) {
		c.fail(err)
	}
	return g, err
}

// readGraph returns the Projection to read: the live one under a read lock
// for a nil at, or the as-of state. Call release when done.
func (c *Core) readGraph(ctx context.Context, at *time.Time) (g *graph.Graph, release func(), err error) {
	if at == nil {
		c.mu.RLock()
		return c.g, c.mu.RUnlock, nil
	}
	v := c.st.NewView()
	defer v.Close()
	g, err = c.guard(stateAt(ctx, v, *at))
	return g, func() {}, err
}

// checkHorizon rejects instants before the Retention_Horizon.
func checkHorizon(v *store.View, at time.Time) (store.Base, bool, error) {
	base, ok, err := v.Base()
	if err != nil {
		return base, false, err
	}
	if ok && at.UnixNano() < base.HorizonNS {
		return base, ok, fmt.Errorf("%w: %s is before retention horizon %s", errs.Validation,
			at.UTC().Format(time.RFC3339Nano), time.Unix(0, base.HorizonNS).UTC().Format(time.RFC3339Nano))
	}
	return base, ok, nil
}

// snapshotHeaders lists the Snapshots usable for at, newest first: seq within
// [base, last] and maxVT <= at.
func snapshotHeaders(v *store.View, base store.Base, last uint64, atNS int64) ([]codec.SnapshotHeader, error) {
	hs, err := v.ListSnapshots()
	if err != nil {
		return nil, err
	}
	out := hs[:0]
	for _, h := range hs {
		if h.Seq >= base.Seq && h.Seq <= last && h.MaxVTNS <= atNS {
			out = append(out, h)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq > out[j].Seq })
	return out, nil
}

func stateAt(ctx context.Context, v *store.View, at time.Time) (*graph.Graph, error) {
	base, hasBase, err := checkHorizon(v, at)
	if err != nil {
		return nil, err
	}
	last, err := v.Seq()
	if err != nil {
		return nil, err
	}
	atNS := at.UnixNano()
	hs, err := snapshotHeaders(v, base, last, atNS)
	if err != nil {
		return nil, err
	}
	var g *graph.Graph
	for _, h := range hs {
		s, err := v.LoadSnapshot(h.Seq)
		if err != nil {
			continue
		}
		if g, err = graph.Import(fromStoreSnapshot(s)); err == nil {
			break
		}
		g = nil
	}
	if g == nil {
		if hasBase && base.Seq > 0 {
			return nil, fmt.Errorf("%w: no valid snapshot at the retention base %d", errs.Corrupt, base.Seq)
		}
		g = graph.New()
	}
	if g.LastSeq >= last {
		return g, nil
	}
	it, err := v.Events(g.LastSeq+1, last)
	if err != nil {
		return nil, err
	}
	defer it.Close()
	n := 0
	for it.Next() {
		if n++; n%1024 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		ev, err := it.Event()
		if err != nil {
			return nil, err
		}
		if ev.ValidNS <= atNS {
			g.Fold(ev)
		}
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("%w: reading event log: %v", errs.Corrupt, err)
	}
	return g, nil
}

// entityAt returns the view of one entity as of at: the entity's record in the
// chosen Snapshot plus its own later events (x/ent) with Valid_Time <= at.
func (c *Core) entityAt(ctx context.Context, id EntityID, at time.Time) (EntityView, error) {
	v := c.st.NewView()
	defer v.Close()
	g, err := c.guard(entityAtView(ctx, v, id, at))
	if err != nil {
		return EntityView{}, err
	}
	e, ok := g.Entity(id)
	if !ok || !e.Live {
		return EntityView{}, fmt.Errorf("%w: entity %s at %s", errs.NotFound, id, at.UTC().Format(time.RFC3339Nano))
	}
	return entityView(g, e), nil
}

func entityAtView(ctx context.Context, v *store.View, id EntityID, at time.Time) (*graph.Graph, error) {
	base, _, err := checkHorizon(v, at)
	if err != nil {
		return nil, err
	}
	last, err := v.Seq()
	if err != nil {
		return nil, err
	}
	atNS := at.UnixNano()
	hs, err := snapshotHeaders(v, base, last, atNS)
	if err != nil {
		return nil, err
	}
	g := graph.New()
	var snapSeq uint64
	if len(hs) > 0 {
		snapSeq = hs[0].Seq
		rec, ok, err := v.SnapshotEntity(snapSeq, id)
		if err != nil {
			return nil, err
		}
		if ok {
			h := hs[0]
			h.NEnt, h.NRel = 1, 0
			if g, err = graph.Import(graph.Snapshot{Header: h, Ents: []graph.SnapEntity{{ID: id, Rec: rec}}}); err != nil {
				return nil, err
			}
		}
	}
	entries, err := v.EntityEntries(id)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.Seq <= snapSeq || e.Seq > last || e.ValidNS > atNS {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ev, err := v.Event(e.Seq)
		if err != nil {
			return nil, err
		}
		g.Fold(ev)
	}
	return g, nil
}

// Diff compares the states at from and to. An entity created and removed
// inside the window appears only in Flapping. It returns errs.Validation when
// to is before from or either instant is before the Retention_Horizon.
func (c *Core) Diff(ctx context.Context, from, to time.Time) (DiffView, error) {
	done, err := c.begin(ctx, "diff")
	if err != nil {
		return DiffView{}, err
	}
	defer done()
	if to.Before(from) {
		return DiffView{}, fmt.Errorf("%w: diff to %s is before from %s", errs.Validation,
			to.UTC().Format(time.RFC3339Nano), from.UTC().Format(time.RFC3339Nano))
	}
	v := c.st.NewView()
	defer v.Close()
	a, err := c.guard(stateAt(ctx, v, from))
	if err != nil {
		return DiffView{}, err
	}
	b, err := c.guard(stateAt(ctx, v, to))
	if err != nil {
		return DiffView{}, err
	}
	counts, err := c.windowCounts(v, from, to)
	if err != nil {
		return DiffView{}, err
	}
	r := query.DiffStates(a, b, counts)
	out := DiffView{From: from, To: to, Removed: r.Removed, Truncated: r.Truncated,
		Added: []EntityView{}, Changed: []EntityView{}, Flapping: make([]Flap, len(r.Flapping))}
	if out.Removed == nil {
		out.Removed = []EntityID{}
	}
	for _, id := range r.Added {
		e, _ := b.Entity(id)
		out.Added = append(out.Added, entityView(b, e))
	}
	for _, id := range r.Changed {
		e, _ := b.Entity(id)
		out.Changed = append(out.Changed, entityView(b, e))
	}
	for i, f := range r.Flapping {
		out.Flapping[i] = Flap(f)
	}
	return out, nil
}

// windowCounts counts entity Change_Events with Valid_Time in (from, to] per
// entity, using the x/vt index.
func (c *Core) windowCounts(v *store.View, from, to time.Time) (map[EntityID]int, error) {
	last, err := v.Seq()
	if err != nil {
		return nil, err
	}
	lo := from.UnixNano()
	counts := map[EntityID]int{}
	if lo == to.UnixNano() {
		return counts, nil
	}
	entries, err := v.ValidRange(lo+1, to.UnixNano())
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.Seq > last {
			continue
		}
		if _, subj, ok := changeKindSubject(e.Type); !ok || subj != SubjectEntity {
			continue
		}
		ev, err := v.Event(e.Seq)
		if err != nil {
			if errors.Is(err, errs.Corrupt) {
				c.fail(err)
			}
			return nil, err
		}
		id := ev.ID
		if ev.Type == codec.EntityCreated {
			if id, err = ident.Hash(ev.Kind, ev.Identity); err != nil {
				return nil, fmt.Errorf("%w: event %d: %v", errs.Corrupt, e.Seq, err)
			}
		}
		counts[id]++
	}
	return counts, nil
}
