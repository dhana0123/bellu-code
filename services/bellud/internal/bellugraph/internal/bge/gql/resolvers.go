package gql

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/engine"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
)

// Resolver is the root resolver over the Engine.
type Resolver struct{ cfg Options }

// From is the resolver for the from field.
func (r *edgeResolver) From(ctx context.Context, obj *Edge) (*Entity, error) {
	return r.entity(ctx, obj.fromID, obj.at)
}

// To is the resolver for the to field.
func (r *edgeResolver) To(ctx context.Context, obj *Edge) (*Entity, error) {
	return r.entity(ctx, obj.toID, obj.at)
}

// LocalID is the resolver for the localId field.
func (r *entityResolver) LocalID(ctx context.Context, obj *Entity) (string, error) {
	return r.cfg.Core.LocalID(obj.ID), nil
}

// Neighbors is the resolver for the neighbors field.
func (r *entityResolver) Neighbors(ctx context.Context, obj *Entity, direction *Direction, relationType *string, depth *int, resolve *bool, first *int, after *string) (*EdgePage, error) {
	return r.neighbors(ctx, obj.ID, direction, relationType, depth, resolve, obj.at, first, after)
}

// History is the resolver for the history field.
func (r *entityResolver) History(ctx context.Context, obj *Entity, from *time.Time, to *time.Time, first *int, after *string) (*ChangePage, error) {
	return r.history(ctx, obj.ID, from, to, first, after)
}

// Dependents is the resolver for the dependents field. Endpoint_Resolution
// runs over the live graph only, so an entity read as of an instant has no
// dependents.
func (r *entityResolver) Dependents(ctx context.Context, obj *Entity) ([]*Entity, error) {
	if obj.at != nil {
		return []*Entity{}, nil
	}
	ids, err := r.cfg.Core.Dependents(ctx, obj.ID)
	if err != nil {
		return nil, err
	}
	return r.entities(ctx, ids, nil)
}

// AnnotateEntity is the resolver for the annotateEntity field.
func (r *mutationResolver) AnnotateEntity(ctx context.Context, id string, set any, remove []string) (*Entity, error) {
	if r.cfg.CallerRole == nil || r.cfg.CallerRole(ctx) != RoleWrite {
		return nil, fmt.Errorf("%w: needs write role", errs.Forbidden)
	}
	if r.cfg.Annotate == nil {
		return nil, fmt.Errorf("%w: annotation is not available", errs.Unavailable)
	}
	values, err := stringMap("set", set)
	if err != nil {
		return nil, err
	}
	if len(values) == 0 && len(remove) == 0 {
		return nil, fmt.Errorf("%w: give annotations to set or keys to remove", errs.Validation)
	}
	eid, err := r.ref("id", id)
	if err != nil {
		return nil, err
	}
	if err := r.cfg.Annotate(ctx, eid, values, remove); err != nil {
		return nil, err
	}
	v, err := r.cfg.Core.Entity(ctx, eid, nil)
	if err != nil {
		return nil, err
	}
	return entityOf(v, nil), nil
}

// Entity is the resolver for the entity field.
func (r *queryResolver) Entity(ctx context.Context, id string, asOf *time.Time) (*Entity, error) {
	eid, err := r.ref("id", id)
	if err != nil {
		return nil, err
	}
	return r.entity(ctx, eid, asOf)
}

// Find is the resolver for the find field.
func (r *queryResolver) Find(ctx context.Context, kind *string, attributes []*AttrFilter, asOf *time.Time, first *int, after *string) (*EntityPage, error) {
	q := engine.FindQuery{Paging: paging(first, after)}
	if kind != nil {
		q.Kind = *kind
	}
	if len(attributes) > 0 {
		q.Attributes = make(map[string]string, len(attributes))
		for _, a := range attributes {
			if prev, ok := q.Attributes[a.Key]; ok && prev != a.Value {
				return nil, fmt.Errorf("%w: attribute %s is given twice with different values", errs.Validation, a.Key)
			}
			q.Attributes[a.Key] = a.Value
		}
	}
	p, err := r.cfg.Core.Find(ctx, q, asOf)
	if err != nil {
		return nil, err
	}
	out := &EntityPage{Items: make([]*Entity, len(p.Items)), Total: p.Total, Truncated: p.Truncated, NextCursor: cursor(p.NextCursor)}
	for i, e := range p.Items {
		out.Items[i] = entityOf(e, asOf)
	}
	return out, nil
}

// Neighbors is the resolver for the neighbors field.
func (r *queryResolver) Neighbors(ctx context.Context, id string, direction *Direction, relationType *string, depth *int, resolve *bool, asOf *time.Time, first *int, after *string) (*EdgePage, error) {
	eid, err := r.ref("id", id)
	if err != nil {
		return nil, err
	}
	return r.neighbors(ctx, eid, direction, relationType, depth, resolve, asOf, first, after)
}

// History is the resolver for the history field.
func (r *queryResolver) History(ctx context.Context, id string, from *time.Time, to *time.Time, first *int, after *string) (*ChangePage, error) {
	eid, err := r.ref("id", id)
	if err != nil {
		return nil, err
	}
	return r.history(ctx, eid, from, to, first, after)
}

// RecentChanges is the resolver for the recentChanges field: newest first.
func (r *queryResolver) RecentChanges(ctx context.Context, since *time.Time, filter *ChangeFilter, first *int, after *string) (*ChangePage, error) {
	f, err := r.changeFilter(filter)
	if err != nil {
		return nil, err
	}
	f.Paging = paging(first, after)
	p, err := r.cfg.Core.Changes(ctx, engine.TimeRange{From: zeroIfNil(since)}, f, engine.OrderDesc)
	if err != nil {
		return nil, err
	}
	return changePage(p), nil
}

// RecentDigest is the resolver for the recentDigest field.
func (r *queryResolver) RecentDigest(ctx context.Context, since *time.Time, filter *ChangeFilter) (*Digest, error) {
	f, err := r.changeFilter(filter)
	if err != nil {
		return nil, err
	}
	d, err := r.cfg.Core.Digest(ctx, engine.TimeRange{From: zeroIfNil(since)}, f)
	if err != nil {
		return nil, err
	}
	return &Digest{Total: d.Total, ByKind: counts(d.ByKind), BySubject: counts(d.BySubject),
		ByEntityKind: counts(d.ByEntityKind), Top: flapsOf(d.Top)}, nil
}

// Diff is the resolver for the diff field.
func (r *queryResolver) Diff(ctx context.Context, from time.Time, to time.Time) (*Diff, error) {
	d, err := r.cfg.Core.Diff(ctx, from, to)
	if err != nil {
		return nil, err
	}
	out := &Diff{From: d.From.UTC(), To: d.To.UTC(), Removed: d.Removed, Flapping: flapsOf(d.Flapping), Truncated: d.Truncated,
		Added: make([]*Entity, len(d.Added)), Changed: make([]*Entity, len(d.Changed))}
	if out.Removed == nil {
		out.Removed = []string{}
	}
	// Added and Changed carry the state at the later instant.
	for i, e := range d.Added {
		out.Added[i] = entityOf(e, &out.To)
	}
	for i, e := range d.Changed {
		out.Changed[i] = entityOf(e, &out.To)
	}
	return out, nil
}

// Path is the resolver for the path field.
func (r *queryResolver) Path(ctx context.Context, from string, to string, maxDepth *int, asOf *time.Time) (*PathResult, error) {
	a, err := r.ref("from", from)
	if err != nil {
		return nil, err
	}
	b, err := r.ref("to", to)
	if err != nil {
		return nil, err
	}
	res, err := r.cfg.Core.Path(ctx, a, b, engine.PathOpts{MaxDepth: intOr(maxDepth, engine.DefaultPathDepth), At: asOf})
	if err != nil {
		return nil, err
	}
	shared, err := r.entities(ctx, res.SharedNeighbors, asOf)
	if err != nil {
		return nil, err
	}
	return &PathResult{
		Connected: res.Connected, Path: edgesOf(res.Path, asOf), Exhausted: res.Exhausted, DepthSearched: res.DepthSearched,
		SharedNeighbors: shared, SharedAttributes: sharedAttrs(res.SharedAttributes),
	}, nil
}

// Impact is the resolver for the impact field.
func (r *queryResolver) Impact(ctx context.Context, id string, depth *int, asOf *time.Time) ([]*Impacted, error) {
	eid, err := r.ref("id", id)
	if err != nil {
		return nil, err
	}
	res, err := r.cfg.Core.Impact(ctx, eid, engine.ImpactOpts{Depth: intOr(depth, engine.DefaultImpactDepth), At: asOf})
	if err != nil {
		return nil, err
	}
	out := make([]*Impacted, len(res.Items))
	for i, it := range res.Items {
		e, err := r.entity(ctx, it.ID, asOf)
		if err != nil {
			return nil, err
		}
		out[i] = &Impacted{Entity: e, Hops: it.Hops, Via: edgesOf(it.Via, asOf)}
	}
	return out, nil
}

// Changes is the resolver for the changes field. fromSeq is the last
// Log_Sequence the client has seen; stored changes after it are replayed
// first. The stream ends when the subscription ends (client gone, Engine
// closing or the subscriber falling too far behind).
func (r *subscriptionResolver) Changes(ctx context.Context, filter *ChangeFilter, fromSeq *string) (<-chan *Change, error) {
	f, err := r.changeFilter(filter)
	if err != nil {
		return nil, err
	}
	o := engine.SubscribeOpts{Filter: f}
	if fromSeq != nil && strings.TrimSpace(*fromSeq) != "" {
		seq, err := strconv.ParseUint(strings.TrimSpace(*fromSeq), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: fromSeq %q is not a decimal sequence", errs.Validation, *fromSeq)
		}
		o.From = &seq
	}
	sub, err := r.cfg.Core.Subscribe(ctx, o)
	if err != nil {
		return nil, err
	}
	out := make(chan *Change)
	go func() {
		defer close(out)
		defer sub.Close()
		for c := range sub.C() {
			select {
			case out <- changeOf(c):
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}

// Edge returns EdgeResolver implementation.
func (r *Resolver) Edge() EdgeResolver { return &edgeResolver{r} }

// Entity returns EntityResolver implementation.
func (r *Resolver) Entity() EntityResolver { return &entityResolver{r} }

// Mutation returns MutationResolver implementation.
func (r *Resolver) Mutation() MutationResolver { return &mutationResolver{r} }

// Query returns QueryResolver implementation.
func (r *Resolver) Query() QueryResolver { return &queryResolver{r} }

// Subscription returns SubscriptionResolver implementation.
func (r *Resolver) Subscription() SubscriptionResolver { return &subscriptionResolver{r} }

type edgeResolver struct{ *Resolver }
type entityResolver struct{ *Resolver }
type mutationResolver struct{ *Resolver }
type queryResolver struct{ *Resolver }
type subscriptionResolver struct{ *Resolver }
