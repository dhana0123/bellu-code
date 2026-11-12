package facade

import (
	"context"
	"sync"

	bgeengine "github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/engine"
)

// Annotate sets and removes operator annotations on the entity named by ref
// (an Entity_ID, a Local_ID or a bellugraph:// URI). The audit record is
// written before the annotation is applied.
func (e *engine) Annotate(ctx context.Context, ref string, set map[string]string, unset []string) (Entity, error) {
	if err := e.ready(); err != nil {
		return Entity{}, err
	}
	id, err := e.stack.Resolve(ref)
	if err != nil {
		return Entity{}, err
	}
	if err := e.annotateAudited(ctx, id, set, unset); err != nil {
		return Entity{}, err
	}
	return e.Entity(ctx, EntityID(id), nil)
}

// Resolve turns an entity reference into an Entity_ID.
func (e *engine) Resolve(_ context.Context, ref string) (EntityID, error) {
	if err := e.ready(); err != nil {
		return "", err
	}
	id, err := e.stack.Resolve(ref)
	return EntityID(id), err
}

// Path finds a shortest undirected path between two entity references.
func (e *engine) Path(ctx context.Context, from, to string, o PathOpts) (PathResult, error) {
	if err := e.ready(); err != nil {
		return PathResult{}, err
	}
	a, err := e.stack.Resolve(from)
	if err != nil {
		return PathResult{}, err
	}
	b, err := e.stack.Resolve(to)
	if err != nil {
		return PathResult{}, err
	}
	r, err := e.stack.Path(ctx, a, b, bgeengine.PathOpts{MaxDepth: o.MaxDepth, StoredOnly: o.StoredOnly})
	if err != nil {
		return PathResult{}, err
	}
	out := PathResult{
		Connected: r.Connected, Path: toEdges(r.Path), Exhausted: r.Exhausted,
		DepthSearched: r.DepthSearched, SharedAttributes: r.SharedAttributes,
	}
	for _, id := range r.SharedNeighbors {
		out.SharedNeighbors = append(out.SharedNeighbors, EntityID(id))
	}
	return out, nil
}

// Impact lists the entities impacted by a failure of ref.
func (e *engine) Impact(ctx context.Context, ref string, o ImpactOpts) (ImpactResult, error) {
	if err := e.ready(); err != nil {
		return ImpactResult{}, err
	}
	id, err := e.stack.Resolve(ref)
	if err != nil {
		return ImpactResult{}, err
	}
	r, err := e.stack.Impact(ctx, id, bgeengine.ImpactOpts{Depth: o.Depth, StoredOnly: o.StoredOnly})
	if err != nil {
		return ImpactResult{}, err
	}
	out := ImpactResult{Items: make([]Impacted, len(r.Items))}
	for i, it := range r.Items {
		out.Items[i] = Impacted{ID: EntityID(it.ID), Kind: it.Kind, Hops: it.Hops, Via: toEdges(it.Via)}
	}
	return out, nil
}

// Subscribe delivers committed changes matching o until the subscription is
// closed, ctx ends or the subscriber overflows.
func (e *engine) Subscribe(ctx context.Context, o SubscribeOpts) (Subscription, error) {
	if err := e.ready(); err != nil {
		return nil, err
	}
	sub, err := e.stack.Subscribe(ctx, bgeengine.SubscribeOpts{
		Filter: bgeengine.ChangeFilter{
			Kind: bgeengine.ChangeKind(o.Kind), Subject: bgeengine.ChangeSubject(o.Subject),
			EntityKind: o.EntityKind, Entity: bgeengine.EntityID(o.Entity),
		},
		From: o.From,
	})
	if err != nil {
		return nil, err
	}
	s := &subscription{sub: sub, out: make(chan SeqChange), stop: make(chan struct{})}
	go s.pump()
	return s, nil
}

type subscription struct {
	sub interface {
		C() <-chan bgeengine.ChangeView
		Err() error
		Close()
	}
	out  chan SeqChange
	stop chan struct{}
	once sync.Once
}

func (s *subscription) pump() {
	defer close(s.out)
	for cv := range s.sub.C() {
		select {
		case s.out <- SeqChange{Seq: cv.Seq, Change: toChange(cv)}:
		case <-s.stop:
			return
		}
	}
}

func (s *subscription) C() <-chan SeqChange { return s.out }
func (s *subscription) Err() error          { return s.sub.Err() }
func (s *subscription) Close() {
	s.once.Do(func() {
		close(s.stop)
		s.sub.Close()
	})
}
