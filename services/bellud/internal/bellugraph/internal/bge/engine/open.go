package engine

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/codec"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/graph"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/localid"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/metrics"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/store"
)

// Open opens the store in dir and returns a ready Core.
//
// An existing store is first opened read-only and fully loaded, so a locked,
// foreign or damaged store is reported (ErrLocked, ErrCorrupt) before any file
// is written. It is then opened for writing and any Events that were appended
// in between are folded in.
func Open(dir string, o Options) (*Core, error) {
	o = o.withDefaults()
	c := &Core{
		dir: dir, opts: o, log: o.Logger, clock: o.Clock,
		met:      metrics.New(),
		ids:      localid.New(o.Clock, o.LocalIDIdle, o.LocalIDTombstone),
		snapKick: make(chan struct{}, 1),
		state:    StateStarting,
	}
	c.Annotations = &Annotations{c: c}
	c.initHub()

	var g *graph.Graph
	if store.Exists(dir) {
		ro, err := store.OpenReadOnly(dir)
		if err != nil {
			return nil, c.openFailed(err)
		}
		g, _, err = loadGraph(ro)
		ro.Close()
		if err != nil {
			return nil, c.openFailed(err)
		}
	}
	st, err := store.Open(dir)
	if err != nil {
		return nil, c.openFailed(err)
	}
	c.st = st
	if g == nil {
		g = graph.New()
	}
	if err := catchUp(st, g); err != nil {
		st.Close()
		return nil, c.openFailed(err)
	}
	c.g = g
	c.lastSnapSeq = lastSnapshotSeq(st)
	if g.LastSeq > 0 {
		if ev, err := st.Event(g.LastSeq); err == nil {
			c.ulids.last = ev.ULID
		}
	}
	c.syncGauges()

	c.bgCtx, c.bgCancel = context.WithCancel(context.Background())
	c.startSweep()
	c.startMaintenance()
	c.setState(StateReady, fmt.Sprintf("opened %s at sequence %d", dir, g.LastSeq))
	return c, nil
}

func (c *Core) openFailed(err error) error {
	c.setState(StateFailed, err.Error())
	return err
}

func (c *Core) startSweep() {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		t := time.NewTicker(c.opts.LocalIDSweep)
		defer t.Stop()
		for {
			select {
			case <-c.bgCtx.Done():
				return
			case <-t.C:
				c.ids.Sweep()
			}
		}
	}()
}

// syncGauges refreshes the size gauges from the Projection.
func (c *Core) syncGauges() {
	c.met.SetEntities(c.g.LiveCount())
	c.met.SetRelations(c.g.RelationCount())
	c.met.SetLastSequence(c.g.LastSeq)
}

// reader is the part of the store used to load a Projection.
type reader interface {
	Seq() (uint64, error)
	Base() (store.Base, bool, error)
	ListSnapshots() ([]codec.SnapshotHeader, error)
	LoadSnapshot(seq uint64) (store.Snapshot, error)
	Events(from, to uint64) (*store.EventIter, error)
}

// loadGraph builds the Projection from the newest valid Snapshot plus the log
// tail, verifying every CRC and the contiguity of the sequence. It returns the
// sequence of the Snapshot it started from.
func loadGraph(r reader) (*graph.Graph, uint64, error) {
	last, err := r.Seq()
	if err != nil {
		return nil, 0, err
	}
	base, hasBase, err := r.Base()
	if err != nil {
		return nil, 0, err
	}
	g, snapSeq, err := loadSnapshot(r, last, base.Seq)
	if err != nil {
		return nil, 0, err
	}
	if g == nil {
		if hasBase && base.Seq > 0 {
			return nil, 0, fmt.Errorf("%w: no valid snapshot at or after the retention base %d", errs.Corrupt, base.Seq)
		}
		g = graph.New()
	}
	if err := foldTail(r, g, last); err != nil {
		return nil, 0, err
	}
	return g, snapSeq, nil
}

// loadSnapshot returns the newest valid Snapshot with baseSeq <= seq <= last,
// falling back to older ones; nil when none is usable.
func loadSnapshot(r reader, last, baseSeq uint64) (*graph.Graph, uint64, error) {
	hs, err := r.ListSnapshots()
	if err != nil {
		return nil, 0, err
	}
	sort.Slice(hs, func(i, j int) bool { return hs[i].Seq > hs[j].Seq })
	for _, h := range hs {
		if h.Seq > last || h.Seq < baseSeq {
			continue
		}
		s, err := r.LoadSnapshot(h.Seq)
		if err != nil {
			continue
		}
		g, err := graph.Import(fromStoreSnapshot(s))
		if err != nil {
			continue
		}
		return g, h.Seq, nil
	}
	return nil, 0, nil
}

// foldTail folds the Events after g.LastSeq up to and including last.
func foldTail(r reader, g *graph.Graph, last uint64) error {
	if g.LastSeq > last {
		return fmt.Errorf("%w: projection at sequence %d is ahead of the log at %d", errs.Corrupt, g.LastSeq, last)
	}
	if g.LastSeq == last {
		return nil
	}
	it, err := r.Events(g.LastSeq+1, 0)
	if err != nil {
		return err
	}
	defer it.Close()
	for it.Next() {
		ev, err := it.Event()
		if err != nil {
			return err
		}
		if ev.Seq != g.LastSeq+1 {
			return fmt.Errorf("%w: event log gap: expected sequence %d, found %d", errs.Corrupt, g.LastSeq+1, ev.Seq)
		}
		g.Fold(ev)
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("%w: reading event log: %v", errs.Corrupt, err)
	}
	if g.LastSeq != last {
		return fmt.Errorf("%w: event log ends at sequence %d, store says %d", errs.Corrupt, g.LastSeq, last)
	}
	return nil
}

// catchUp folds Events appended between the read-only load and the writable open.
func catchUp(st *store.Store, g *graph.Graph) error {
	last, err := st.Seq()
	if err != nil {
		return err
	}
	return foldTail(st, g, last)
}

func lastSnapshotSeq(st *store.Store) uint64 {
	hs, err := st.ListSnapshots()
	if err != nil {
		return 0
	}
	var m uint64
	for _, h := range hs {
		if h.Seq > m {
			m = h.Seq
		}
	}
	return m
}

func fromStoreSnapshot(s store.Snapshot) graph.Snapshot {
	out := graph.Snapshot{
		Header: s.Header,
		Ents:   make([]graph.SnapEntity, len(s.Entities)),
		Rels:   make([]graph.SnapRel, len(s.Relations)),
	}
	for i, e := range s.Entities {
		out.Ents[i] = graph.SnapEntity{ID: e.ID, Rec: e.Rec}
	}
	for i, r := range s.Relations {
		out.Rels[i] = graph.SnapRel{Key: graph.RelKey{Type: r.Type, From: r.From, To: r.To}, Rec: r.Rec}
	}
	return out
}

func toStoreSnapshot(s graph.Snapshot) store.Snapshot {
	out := store.Snapshot{
		Header:    s.Header,
		Entities:  make([]store.SnapEntity, len(s.Ents)),
		Relations: make([]store.SnapRelation, len(s.Rels)),
	}
	for i, e := range s.Ents {
		out.Entities[i] = store.SnapEntity{ID: e.ID, Rec: e.Rec}
	}
	for i, r := range s.Rels {
		out.Relations[i] = store.SnapRelation{Type: r.Key.Type, From: r.Key.From, To: r.Key.To, Rec: r.Rec}
	}
	return out
}

// writeSnapshot exports the Projection at its current sequence and stores it.
func (c *Core) writeSnapshot() error {
	c.snapMu.Lock()
	defer c.snapMu.Unlock()
	start := time.Now()
	c.mu.RLock()
	snap := c.g.Export()
	c.mu.RUnlock()
	if snap.Header.Seq == 0 || snap.Header.Seq == c.lastSnapSeq {
		return nil
	}
	if _, err := c.st.WriteSnapshot(toStoreSnapshot(snap), nil); err != nil {
		return fmt.Errorf("writing snapshot: %w", err)
	}
	c.lastSnapSeq = snap.Header.Seq
	c.eventsSinceSnap.Store(0)
	c.met.ObserveSnapshot(time.Since(start))
	if err := c.pruneSnapshots(); err != nil {
		c.log.Error("pruning snapshots failed", "error", err.Error())
	}
	return nil
}
