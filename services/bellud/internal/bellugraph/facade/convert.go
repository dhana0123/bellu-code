package facade

import (
	bgeengine "github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/engine"
)

// This file converts between the Facade's wire-facing types and the engine
// core's read models. All conversion happens at the Facade boundary.

func toPaging(p Paging) bgeengine.Paging {
	return bgeengine.Paging{PageSize: p.PageSize, Cursor: p.Cursor}
}

func toRange(r TimeRange) bgeengine.TimeRange {
	return bgeengine.TimeRange{From: r.From, To: r.To}
}

func toPage[A, B any](p bgeengine.Page[A], f func(A) B) Page[B] {
	out := Page[B]{
		Items: make([]B, len(p.Items)), Total: p.Total, Truncated: p.Truncated,
		Limit: p.Limit, NextCursor: p.NextCursor,
	}
	for i, it := range p.Items {
		out.Items[i] = f(it)
	}
	return out
}

func toEntity(v bgeengine.EntityView) Entity {
	return Entity{
		ID: EntityID(v.ID), Type: v.Kind, Label: v.Label, Attributes: v.Attributes,
		Annotations: v.Annotations, ObservedAt: v.ObservedAt.UTC(), RecordedAt: v.RecordedAt.UTC(),
	}
}

func toEdge(v bgeengine.EdgeView) Edge {
	return Edge{
		From: EntityID(v.From), To: EntityID(v.To), Type: v.Type,
		Direction: v.Direction, Hops: v.Hops, Derived: v.Derived,
	}
}

func toChange(v bgeengine.ChangeView) Change {
	return Change{
		Kind: ChangeKind(v.Kind), Subject: ChangeSubject(v.Subject), Entity: EntityID(v.Entity),
		From: EntityID(v.From), To: EntityID(v.To), RelationType: v.RelationType,
		ObservedAt: v.ObservedAt.UTC(), RecordedAt: v.RecordedAt.UTC(),
	}
}

func toReceipt(r bgeengine.Receipt) Receipt {
	return Receipt{
		ID: r.ID, ObservedAt: r.ObservedAt, RecordedAt: r.RecordedAt,
		Entities: r.Entities, Relations: r.Relations, Removed: r.Removed,
	}
}

func toDiff(d bgeengine.DiffView) Diff {
	out := Diff{
		From: d.From, To: d.To, Added: make([]Entity, len(d.Added)), Changed: make([]Entity, len(d.Changed)),
		Removed: make([]EntityID, len(d.Removed)), Flapping: make([]Flap, len(d.Flapping)), Truncated: d.Truncated,
	}
	for i, v := range d.Added {
		out.Added[i] = toEntity(v)
	}
	for i, v := range d.Changed {
		out.Changed[i] = toEntity(v)
	}
	for i, id := range d.Removed {
		out.Removed[i] = EntityID(id)
	}
	for i, f := range d.Flapping {
		out.Flapping[i] = Flap{ID: EntityID(f.ID), Changes: f.Changes}
	}
	return out
}

func toEdges(vs []bgeengine.EdgeView) []Edge {
	out := make([]Edge, len(vs))
	for i, v := range vs {
		out[i] = toEdge(v)
	}
	return out
}
