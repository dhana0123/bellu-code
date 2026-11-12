package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/codec"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/subscribe"
)

// SubscribeOpts selects the changes a Subscriber receives. From, when set, is
// the last Log_Sequence the caller has seen: stored Change_Events after it are
// replayed before live delivery. Nil means live only.
type SubscribeOpts struct {
	Filter ChangeFilter // Kind, Subject, EntityKind and Entity apply; Paging is ignored
	From   *uint64
}

// GoneError reports a resume position older than the retained Event_Log.
type GoneError struct {
	From   uint64
	Oldest uint64 // oldest retained Log_Sequence
}

func (e *GoneError) Error() string {
	return fmt.Sprintf("gone: resume sequence %d is older than the oldest retained sequence %d", e.From, e.Oldest)
}

// Unwrap makes errors.Is(err, errs.Validation) match.
func (e *GoneError) Unwrap() error { return errs.Validation }

// Subscribe delivers Change_Events matching o.Filter on the returned Sub's
// channel, in strictly increasing Log_Sequence order. The Sub ends when ctx is
// done, when it is closed, or with an overflow error (errors.Is errs.Overflow)
// if its 256-entry buffer fills.
func (c *Core) Subscribe(ctx context.Context, o SubscribeOpts) (*subscribe.Sub[ChangeView], error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := c.readable(); err != nil {
		return nil, err
	}
	f := subscribe.Filter{
		Kind: string(o.Filter.Kind), Subject: string(o.Filter.Subject),
		EntityKind: o.Filter.EntityKind, Entity: o.Filter.Entity,
	}

	c.applyMu.Lock()
	if c.closing.Load() || c.closed {
		c.applyMu.Unlock()
		return nil, fmt.Errorf("%w: graph engine is closing", errs.Unavailable)
	}
	last := c.g.LastSeq
	if o.From == nil {
		sub := c.hub.Subscribe(f, subscribe.DefaultBuffer)
		c.applyMu.Unlock()
		c.watch(ctx, sub)
		return sub, nil
	}
	from := *o.From
	if from > last {
		c.applyMu.Unlock()
		return nil, fmt.Errorf("%w: resume sequence %d is beyond the last sequence %d", errs.Validation, from, last)
	}
	v := c.st.NewView()
	base, hasBase, err := v.Base()
	if err != nil {
		c.applyMu.Unlock()
		v.Close()
		return nil, err
	}
	if hasBase && from < base.Seq {
		c.applyMu.Unlock()
		v.Close()
		return nil, &GoneError{From: from, Oldest: base.Seq}
	}
	if from == last {
		v.Close()
		sub := c.hub.Subscribe(f, subscribe.DefaultBuffer)
		c.applyMu.Unlock()
		c.watch(ctx, sub)
		return sub, nil
	}
	// The view is a snapshot at L; live changes (seq > L) queue in the Sub.
	sub := c.hub.SubscribeReplay(f, subscribe.DefaultBuffer)
	c.applyMu.Unlock()
	c.watch(ctx, sub)
	sub.StartReplay(func(emit func(ChangeView) bool) error {
		defer v.Close()
		it, err := v.Events(from+1, last)
		if err != nil {
			return err
		}
		defer it.Close()
		for it.Next() {
			ev, err := it.Event()
			if err != nil {
				return err
			}
			cv, ok, err := c.changeOf(ev)
			if err != nil {
				return err
			}
			if ok && !emit(cv) {
				return nil
			}
		}
		return nil
	})
	return sub, nil
}

// watch closes sub when ctx ends.
func (c *Core) watch(ctx context.Context, sub *subscribe.Sub[ChangeView]) {
	if ctx.Done() == nil {
		return
	}
	go func() {
		select {
		case <-ctx.Done():
			sub.Close()
		case <-sub.Done():
		}
	}()
}

// initHub creates the subscriber hub and closes it with the Engine.
func (c *Core) initHub() {
	c.hub = subscribe.NewHub(changeMeta, c.met.SetSubscribers, c.met.SubscriberOverflow)
	c.onClose = append(c.onClose, c.hub.Close)
}

// publish delivers the Change_Events among evs to Subscribers. The caller
// holds applyMu and has committed and folded evs.
func (c *Core) publish(evs []codec.Event) {
	if c.hub == nil {
		return
	}
	out := make([]ChangeView, 0, len(evs))
	for _, ev := range evs {
		cv, ok, err := c.changeOf(ev)
		if err != nil {
			c.log.Error("graph change not published", "seq", ev.Seq, "error", err.Error())
			continue
		}
		if ok {
			out = append(out, cv)
		}
	}
	c.hub.Publish(out)
}

// changeOf classifies ev like the read path does; ok is false for events that
// are not Change_Events.
func (c *Core) changeOf(ev codec.Event) (ChangeView, bool, error) {
	kind, subj, ok := changeKindSubject(ev.Type)
	if !ok {
		return ChangeView{}, false, nil
	}
	cv := ChangeView{
		Seq: ev.Seq, Kind: kind, Subject: subj,
		ObservedAt: time.Unix(0, ev.ValidNS).UTC(), RecordedAt: time.Unix(0, ev.RecordedNS).UTC(),
	}
	if subj == SubjectRelation {
		cv.From, cv.To, cv.RelationType = ev.From, ev.To, ev.RelType
		return cv, true, nil
	}
	cv.Entity, cv.EntityKind = ev.ID, ev.Kind
	if ev.Type == codec.EntityCreated {
		id, err := ident.Hash(ev.Kind, ev.Identity)
		if err != nil {
			return ChangeView{}, false, fmt.Errorf("%w: event %d: %v", errs.Corrupt, ev.Seq, err)
		}
		cv.Entity = id
		return cv, true, nil
	}
	c.mu.RLock()
	if e, ok := c.g.Entity(ev.ID); ok {
		cv.EntityKind = e.Kind
	}
	c.mu.RUnlock()
	return cv, true, nil
}

func changeMeta(cv ChangeView) subscribe.Meta {
	return subscribe.Meta{
		Seq: cv.Seq, Kind: string(cv.Kind), Subject: string(cv.Subject),
		EntityKind: cv.EntityKind, Entity: cv.Entity, From: cv.From, To: cv.To,
	}
}
