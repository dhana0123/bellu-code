package facade

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/change"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/model"
)

// Apply appends one collector observation as a single atomic log append.
//
// The Batch is a FULL observation of the Collector's scope. Entity_IDs come
// from Hash. Relation From/To are Entity_IDs too (not engine ULIDs): each must
// name an entity in the same Batch or one live in the graph, and the facade
// resolves it to the engine's (kind, identity) endpoint reference.
//
// Everything is validated before the engine is touched, so a rejected Batch
// appends nothing. Accepted observations are then staged in one engine batch,
// which the engine appends durably in one write and applies to the projection
// only after the append succeeds; a failed append leaves the graph unchanged.
//
// The engine classifies each observation (created / attribute_updated /
// state_changed / unchanged). Entities and relations asserted earlier by the
// same Collector scope and absent from this Batch are retired through the
// engine's per-producer reference counting (producer == scope == Collector),
// which emits entity.deleted / relation.removed only when no other collector
// still asserts them. observed_at is Batch.ObservedAt exactly (now when zero);
// recorded_at is stamped by the engine at append.
func (e *engine) Apply(ctx context.Context, b Batch) (Receipt, error) {
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	if k := e.State().Kind; k != StateReady {
		return Receipt{}, fmt.Errorf("%w: %s", ErrUnavailable, k)
	}
	e.applyMu.Lock() // plan and append see the same projection
	defer e.applyMu.Unlock()

	p, err := e.plan(b)
	if err != nil {
		return Receipt{}, err
	}

	var (
		first    string
		recorded time.Time
		errs     []error
		removed  int
	)
	note := func(ev model.Event) {
		id, rec := eventIDAndRecorded(ev)
		if first == "" {
			first = id
		}
		if rec.After(recorded) {
			recorded = rec
		}
	}
	err = e.stack.Engine.Batch(func(bt *change.Batch) {
		bt.SetScope(p.collector)
		for _, o := range p.entities {
			ev, err := bt.ObserveEntity(o)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			note(ev)
		}
		for _, o := range p.relations {
			ev, emitted, err := bt.ObserveRelation(o)
			if err != nil {
				errs = append(errs, err)
			} else if emitted {
				note(ev)
			}
		}
		for _, o := range p.removeRelations {
			if ev, emitted, err := bt.RemoveRelation(o); err != nil {
				errs = append(errs, err)
			} else if emitted {
				removed++
				note(ev)
			}
		}
		for _, o := range p.removeEntities {
			if ev, emitted, err := bt.DeleteEntity(o); err != nil {
				errs = append(errs, err)
			} else if emitted {
				removed++
				note(ev)
			}
		}
	})
	if err != nil {
		return Receipt{}, fmt.Errorf("appending batch: %w", err)
	}
	if len(errs) > 0 {
		// Only reachable when an endpoint outside the Batch expired between
		// validation and append (liveness sweep); the engine has already
		// committed the rest of the staged unit.
		return Receipt{}, fmt.Errorf("batch partially applied: %w", errors.Join(errs...))
	}
	if first == "" {
		first = model.NewEventID()
	}
	if recorded.IsZero() {
		recorded = time.Now().UTC()
	}
	return Receipt{
		ID: first, ObservedAt: p.observedAt, RecordedAt: recorded,
		Entities: len(p.entities), Relations: len(p.relations), Removed: removed,
	}, nil
}

func eventIDAndRecorded(ev model.Event) (string, time.Time) {
	switch {
	case ev.Entity != nil:
		return ev.Entity.EventID, ev.Entity.RecordedAt
	case ev.Relation != nil:
		return ev.Relation.EventID, ev.Relation.RecordedAt
	}
	return "", time.Time{}
}

type plan struct {
	collector       string
	observedAt      time.Time
	entities        []change.EntityObservation
	relations       []change.RelationObservation
	removeRelations []change.RelationObservation
	removeEntities  []change.EntityObservation
}

// plan validates b against the registry and the projection and computes the
// engine observations. It never mutates the engine.
func (e *engine) plan(b Batch) (plan, error) {
	p := plan{collector: b.Collector, observedAt: b.ObservedAt}
	if strings.TrimSpace(b.Collector) == "" {
		return p, fmt.Errorf("%w: batch collector is required", ErrValidation)
	}
	if p.observedAt.IsZero() {
		p.observedAt = time.Now().UTC()
	}

	refs := make(map[EntityID]change.EndpointRef, len(b.Entities))
	for i, en := range b.Entities {
		kvs, err := identityKVs(en.Type, en.Identity)
		if err != nil {
			return p, fmt.Errorf("entity %d: %w", i, err)
		}
		id := EntityID(model.Entity{Type: en.Type, Identity: kvs}.IdentityHash())
		if _, dup := refs[id]; dup {
			return p, fmt.Errorf("%w: entity %d (%s) duplicates an earlier entity in the batch", ErrValidation, i, id)
		}
		// Identity values outside the registered set are descriptive; an
		// explicit attribute of the same name wins.
		attrs := make(map[string]any, len(en.Attributes)+len(en.Identity))
		for k, v := range en.Identity {
			if !slices.Contains(identityAttrs[en.Type], k) {
				attrs[k] = v
			}
		}
		for k, v := range en.Attributes {
			attrs[k] = v
		}
		akv, err := attrKVs(attrs)
		if err != nil {
			return p, fmt.Errorf("entity %d (%s): %w", i, id, err)
		}
		refs[id] = change.EndpointRef{Type: en.Type, Identity: kvs}
		p.entities = append(p.entities, change.EntityObservation{
			Type: en.Type, Identity: kvs, Attributes: akv,
			EventTime: p.observedAt, Producer: b.Collector,
		})
	}

	// Relations: attributed ones are rejected outright (Requirement 11.14).
	for i, r := range b.Relations {
		if len(r.Attributes) > 0 {
			return p, fmt.Errorf("%w: relation %d (%s %s -> %s) carries attributes; relations must not (model qualifiers on entities)",
				ErrValidation, i, r.Type, r.From, r.To)
		}
		if r.Type == "" {
			return p, fmt.Errorf("%w: relation %d has no type", ErrValidation, i)
		}
	}
	g := e.stack.Graph
	endpoint := func(id string) (change.EndpointRef, bool) {
		if ref, ok := refs[EntityID(id)]; ok {
			return ref, true
		}
		ulid, ok := g.ResolveFingerprint(id)
		if !ok {
			return change.EndpointRef{}, false
		}
		ent, ok, deleted := g.GetEntity(ulid)
		if !ok || deleted {
			return change.EndpointRef{}, false
		}
		return change.EndpointRef{Type: ent.Type, Identity: ent.Identity}, true
	}
	wanted := make(map[string]struct{}, len(b.Relations))
	for i, r := range b.Relations {
		from, ok := endpoint(r.From)
		if !ok {
			return p, fmt.Errorf("%w: relation %d (%s) from-endpoint %q is not in the batch or the graph", ErrValidation, i, r.Type, r.From)
		}
		to, ok := endpoint(r.To)
		if !ok {
			return p, fmt.Errorf("%w: relation %d (%s) to-endpoint %q is not in the batch or the graph", ErrValidation, i, r.Type, r.To)
		}
		wanted[relKey(r.Type, r.From, r.To)] = struct{}{}
		p.relations = append(p.relations, change.RelationObservation{
			Type: r.Type, From: from, To: to, EventTime: p.observedAt, Producer: b.Collector,
		})
	}

	// Full-observation removals: what this scope asserted and no longer reports.
	eng := e.stack.Engine
	gone := map[EntityID]struct{}{}
	for _, ent := range g.ListEntities("") {
		fp := EntityID(ent.IdentityHash())
		if _, kept := refs[fp]; kept || !slices.Contains(eng.AssertingScopes(ent.ID), b.Collector) {
			continue
		}
		gone[fp] = struct{}{}
		p.removeEntities = append(p.removeEntities, change.EntityObservation{
			Type: ent.Type, Identity: ent.Identity, Attributes: ent.Attributes,
			EventTime: p.observedAt, Producer: b.Collector,
		})
	}
	for _, rel := range g.ListRelations("", "", "") {
		if !slices.Contains(eng.RelationAssertingScopes(rel.ID), b.Collector) {
			continue
		}
		from, ok1, _ := g.GetEntity(rel.From)
		to, ok2, _ := g.GetEntity(rel.To)
		if !ok1 || !ok2 {
			continue
		}
		ff, tf := from.IdentityHash(), to.IdentityHash()
		if _, kept := wanted[relKey(rel.Type, ff, tf)]; kept {
			continue
		}
		p.removeRelations = append(p.removeRelations, change.RelationObservation{
			Type:      rel.Type,
			From:      change.EndpointRef{Type: from.Type, Identity: from.Identity},
			To:        change.EndpointRef{Type: to.Type, Identity: to.Identity},
			EventTime: p.observedAt, Producer: b.Collector,
		})
	}
	for i, r := range b.Relations {
		for _, id := range []string{r.From, r.To} {
			if _, ok := gone[EntityID(id)]; ok {
				return p, fmt.Errorf("%w: relation %d (%s) names %q, which this batch retires", ErrValidation, i, r.Type, id)
			}
		}
	}
	return p, nil
}

func relKey(typ, from, to string) string { return typ + "\x1f" + from + "\x1f" + to }
