package facade

import (
	"context"
	"fmt"
	"time"

	bgeengine "github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/engine"
)

// Entity returns the entity state. With at == nil it is the current state.
// With at it is the state folded, in log order, from every event with
// observed_at <= at (inclusive); an instant before the entity's first event, a
// deleted entity or an unknown ID is ErrNotFound.
func (e *engine) Entity(ctx context.Context, id EntityID, at *time.Time) (Entity, error) {
	if err := e.ready(); err != nil {
		return Entity{}, err
	}
	if at != nil {
		t := at.UTC()
		at = &t
	}
	v, err := e.stack.Entity(ctx, bgeengine.EntityID(id), at)
	if err != nil {
		return Entity{}, err
	}
	return toEntity(v), nil
}

// Find pages the live entities matching q, ordered by Entity_ID.
func (e *engine) Find(ctx context.Context, q FindQuery) (Page[Entity], error) {
	if err := e.ready(); err != nil {
		return Page[Entity]{}, err
	}
	pg, err := e.stack.Find(ctx, bgeengine.FindQuery{Kind: q.Type, Attributes: q.Attributes, Paging: toPaging(q.Paging)}, nil)
	if err != nil {
		return Page[Entity]{}, err
	}
	return toPage(pg, toEntity), nil
}

// Neighbors traverses relations from id up to opt.Depth hops and returns each
// reached relation once, at its fewest hops, ordered by hops, type and ends.
func (e *engine) Neighbors(ctx context.Context, id EntityID, opt NeighborOpts) (Page[Edge], error) {
	if err := e.ready(); err != nil {
		return Page[Edge]{}, err
	}
	pg, err := e.stack.Neighbors(ctx, bgeengine.EntityID(id), bgeengine.NeighborOpts{
		Direction: opt.Direction, RelationType: opt.RelationType, Depth: opt.Depth,
		Resolve: opt.Resolve, Paging: toPaging(opt.Paging),
	}, nil)
	if err != nil {
		return Page[Edge]{}, err
	}
	return toPage(pg, toEdge), nil
}

// History lists the entity's changes (its own events and events of relations
// touching it) within r, oldest first. A deleted entity keeps its history
// while the engine retains the log; an ID the log never saw is ErrNotFound.
func (e *engine) History(ctx context.Context, id EntityID, r TimeRange, p Paging) (Page[Change], error) {
	if err := e.ready(); err != nil {
		return Page[Change]{}, err
	}
	if err := r.validate(); err != nil {
		return Page[Change]{}, err
	}
	pg, err := e.stack.History(ctx, bgeengine.EntityID(id), toRange(r), toPaging(p))
	if err != nil {
		return Page[Change]{}, err
	}
	return toPage(pg, toChange), nil
}

// Changes lists changes with observed_at in r matching f, oldest first
// (observed_at, then log order).
func (e *engine) Changes(ctx context.Context, r TimeRange, f ChangeFilter) (Page[Change], error) {
	if err := e.ready(); err != nil {
		return Page[Change]{}, err
	}
	if err := r.validate(); err != nil {
		return Page[Change]{}, err
	}
	pg, err := e.stack.Changes(ctx, toRange(r), bgeengine.ChangeFilter{
		Kind: bgeengine.ChangeKind(f.Kind), Subject: bgeengine.ChangeSubject(f.Subject),
		Entity: bgeengine.EntityID(f.Entity), Paging: toPaging(f.Paging),
	}, bgeengine.OrderAsc)
	if err != nil {
		return Page[Change]{}, err
	}
	return toPage(pg, toChange), nil
}

// Diff derives added, changed and removed entities between two observed_at
// instants from the full states at each: an entity created and deleted in
// between appears nowhere.
func (e *engine) Diff(ctx context.Context, from, to time.Time) (Diff, error) {
	if err := e.ready(); err != nil {
		return Diff{}, err
	}
	d, err := e.stack.Diff(ctx, from.UTC(), to.UTC())
	if err != nil {
		return Diff{}, err
	}
	return toDiff(d), nil
}

func (r TimeRange) validate() error {
	if !r.From.IsZero() && !r.To.IsZero() && r.To.Before(r.From) {
		return fmt.Errorf("%w: range end %s is before start %s", ErrValidation, r.To.Format(time.RFC3339), r.From.Format(time.RFC3339))
	}
	return nil
}
