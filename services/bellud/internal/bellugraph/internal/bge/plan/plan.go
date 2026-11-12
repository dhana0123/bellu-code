// Package plan validates a collector Batch and turns it into the events that
// move the Projection to the observed state. Plan is pure over a read-only
// View: it writes nothing and mutates nothing.
package plan

import (
	"fmt"
	"sort"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/codec"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/graph"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

// EntityID is the stable entity identifier.
type EntityID = string

// Mode selects how absent assertions are treated.
type Mode int

const (
	// ModeFull treats the Batch as the collector's complete observation:
	// whatever the collector asserted before and the Batch omits is retracted.
	ModeFull Mode = iota
	// ModePartial only adds and updates; it never retracts.
	ModePartial
)

// View is the read-only graph access Plan needs. *graph.Graph implements it.
type View interface {
	Entity(id EntityID) (*graph.EntityState, bool)
	Relation(k graph.RelKey) (*graph.RelState, bool)
	Scope(collector string) *graph.Scope
	RelationsOf(id EntityID) []graph.RelKey
}

// Result is the validated outcome of one Batch.
//
// Events carry Type, Collector, ValidNS (= ObservedAt) and the body fields.
// Seq, ULID and RecordedNS are left zero for the engine to assign. Order:
// entity created/updated, relation added, relation removed, entity removed,
// then at most one ScopeDelta.
type Result struct {
	Collector  string
	ObservedAt time.Time
	Events     []codec.Event
	// Entities and Relations are the sizes of the submitted Batch.
	Entities, Relations int
	// Removed counts EntityRemoved and RelationRemoved events.
	Removed int
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errs.Validation, fmt.Sprintf(format, args...))
}

type pent struct {
	id       EntityID
	kind     string
	identity map[string]string
	attrs    map[string]codec.Value
}

// Plan validates b against v and returns the events to append. now supplies
// ObservedAt when b.ObservedAt is zero; a supplied value is kept exactly.
func Plan(v View, b batch.Batch, mode Mode, now time.Time) (Result, error) {
	p := Result{Collector: b.Collector, Entities: len(b.Entities), Relations: len(b.Relations)}
	if b.Collector == "" {
		return p, invalid("collector is empty")
	}
	p.ObservedAt = b.ObservedAt
	if p.ObservedAt.IsZero() {
		p.ObservedAt = now.UTC()
	}
	vns := p.ObservedAt.UnixNano()
	c := b.Collector

	// Entities.
	ents := make([]pent, 0, len(b.Entities))
	inBatch := make(map[EntityID]struct{}, len(b.Entities))
	for i, e := range b.Entities {
		pe, err := convertEntity(e)
		if err != nil {
			return p, fmt.Errorf("entity %d: %w", i, err)
		}
		if _, dup := inBatch[pe.id]; dup {
			return p, invalid("duplicate entity %q (kind %q)", pe.id, pe.kind)
		}
		inBatch[pe.id] = struct{}{}
		ents = append(ents, pe)
	}

	// Removals decided up front so relation checks can see them.
	scope := v.Scope(c)
	var retiredEnts []EntityID // to emit EntityRemoved
	var dropEnts []EntityID    // only this collector's assertion goes
	removedSet := map[EntityID]struct{}{}
	if mode == ModeFull && scope != nil {
		for _, id := range sortedIDs(scope.Ents) {
			if _, ok := inBatch[id]; ok {
				continue
			}
			es, ok := v.Entity(id)
			if !ok || !es.Live {
				dropEnts = append(dropEnts, id)
				continue
			}
			if othersAssert(es.Asserted, c) {
				dropEnts = append(dropEnts, id)
				continue
			}
			retiredEnts = append(retiredEnts, id)
			removedSet[id] = struct{}{}
		}
	}

	// Relations.
	rels := make([]graph.RelKey, 0, len(b.Relations))
	seenRel := map[graph.RelKey]struct{}{}
	for i, r := range b.Relations {
		if r.Type == "" {
			return p, invalid("relation %d (from %q to %q) has no type", i, r.From, r.To)
		}
		if len(r.Attributes) > 0 {
			return p, invalid("relation %d (%q from %q to %q) carries attributes; relations take none", i, r.Type, r.From, r.To)
		}
		for _, ep := range [...]struct{ role, id string }{{"from", r.From}, {"to", r.To}} {
			if _, retired := removedSet[ep.id]; retired {
				return p, invalid("relation %q from %q to %q: %s endpoint %q is retired by this batch", r.Type, r.From, r.To, ep.role, ep.id)
			}
			if _, ok := inBatch[ep.id]; ok {
				continue
			}
			if es, ok := v.Entity(ep.id); !ok || !es.Live {
				return p, invalid("relation %q from %q to %q: %s endpoint %q is neither in the batch nor live in the graph", r.Type, r.From, r.To, ep.role, ep.id)
			}
		}
		k := graph.RelKey{Type: r.Type, From: r.From, To: r.To}
		if _, dup := seenRel[k]; dup {
			continue
		}
		seenRel[k] = struct{}{}
		rels = append(rels, k)
	}

	var addEnts []EntityID
	var addRels []graph.RelKey

	// Entity classification.
	for _, pe := range ents {
		es, ok := v.Entity(pe.id)
		if !ok || !es.Live {
			p.Events = append(p.Events, codec.Event{
				Type: codec.EntityCreated, Collector: c, ValidNS: vns,
				Kind: pe.kind, Identity: pe.identity, Attrs: pe.attrs,
			})
			continue
		}
		if _, asserted := es.Asserted[c]; !asserted {
			addEnts = append(addEnts, pe.id)
		}
		set := map[string]codec.Value{}
		for _, k := range sortedKeys(pe.attrs) {
			if old, has := es.Attrs[k]; !has || !old.Equal(pe.attrs[k]) {
				set[k] = pe.attrs[k]
			}
		}
		var unset []string
		for _, k := range sortedKeys(es.Owner) {
			if es.Owner[k] != c {
				continue
			}
			if _, still := pe.attrs[k]; !still {
				unset = append(unset, k)
			}
		}
		if len(set) == 0 && len(unset) == 0 {
			continue
		}
		class := codec.ClassAttr
		for k := range set {
			if ident.IsStateAttr(k) {
				class = codec.ClassState
			}
		}
		for _, k := range unset {
			if ident.IsStateAttr(k) {
				class = codec.ClassState
			}
		}
		p.Events = append(p.Events, codec.Event{
			Type: codec.EntityUpdated, Collector: c, ValidNS: vns,
			ID: pe.id, Class: class, Set: set, Unset: unset,
		})
	}

	// Relation classification.
	for _, k := range rels {
		rs, ok := v.Relation(k)
		if !ok {
			p.Events = append(p.Events, codec.Event{
				Type: codec.RelationAdded, Collector: c, ValidNS: vns,
				RelType: k.Type, From: k.From, To: k.To,
			})
			continue
		}
		if _, asserted := rs.Asserted[c]; !asserted {
			addRels = append(addRels, k)
		}
	}

	// ModeFull relation removals.
	var delRels []graph.RelKey
	relRemoved := map[graph.RelKey]struct{}{}
	if mode == ModeFull {
		if scope != nil {
			for _, k := range sortedRelKeys(scope.Rels) {
				if _, ok := seenRel[k]; ok {
					continue
				}
				rs, ok := v.Relation(k)
				if !ok {
					delRels = append(delRels, k)
					continue
				}
				_, touchesRemoved := removedSet[k.From]
				if _, t := removedSet[k.To]; t {
					touchesRemoved = true
				}
				if othersAssert(rs.Asserted, c) && !touchesRemoved {
					delRels = append(delRels, k)
					continue
				}
				relRemoved[k] = struct{}{}
			}
		}
		// Relations touching a removed entity go too, whoever asserts them.
		for _, id := range retiredEnts {
			for _, k := range v.RelationsOf(id) {
				relRemoved[k] = struct{}{}
			}
		}
	}
	for _, k := range sortedRelKeys(relRemoved) {
		p.Events = append(p.Events, codec.Event{
			Type: codec.RelationRemoved, Collector: c, ValidNS: vns,
			RelType: k.Type, From: k.From, To: k.To,
		})
		p.Removed++
	}
	for _, id := range retiredEnts {
		p.Events = append(p.Events, codec.Event{
			Type: codec.EntityRemoved, Collector: c, ValidNS: vns, ID: id,
		})
		p.Removed++
	}

	// ScopeDelta.
	if len(addEnts)+len(dropEnts)+len(addRels)+len(delRels) > 0 {
		p.Events = append(p.Events, codec.Event{
			Type: codec.ScopeDelta, Collector: c, ValidNS: vns,
			AddEnts: addEnts, DelEnts: dropEnts,
			AddRels: refs(addRels), DelRels: refs(delRels),
		})
	}
	return p, nil
}

func convertEntity(e batch.Entity) (pent, error) {
	id, err := ident.Hash(e.Type, e.Identity)
	if err != nil {
		return pent{}, err
	}
	keys, _ := ident.IdentityAttributes(e.Type)
	registered := make(map[string]struct{}, len(keys))
	identity := make(map[string]string, len(keys))
	for _, k := range keys {
		registered[k] = struct{}{}
		identity[k] = e.Identity[k]
	}
	attrs := make(map[string]codec.Value, len(e.Identity)+len(e.Attributes))
	// Identity keys outside the registered set are descriptive; explicit
	// attributes win over them.
	for k, s := range e.Identity {
		if _, reg := registered[k]; reg {
			continue
		}
		if k == "" {
			return pent{}, invalid("entity kind %q has an empty attribute name", e.Type)
		}
		attrs[k] = codec.Value{T: codec.TagString, S: s}
	}
	for k, raw := range e.Attributes {
		if k == "" {
			return pent{}, invalid("entity kind %q has an empty attribute name", e.Type)
		}
		val, err := codec.FromAny(k, raw)
		if err != nil {
			return pent{}, fmt.Errorf("entity kind %q: %w", e.Type, err)
		}
		attrs[k] = val
	}
	return pent{id: id, kind: e.Type, identity: identity, attrs: attrs}, nil
}

func othersAssert(asserted map[string]struct{}, self string) bool {
	for c := range asserted {
		if c != self {
			return true
		}
	}
	return false
}

func refs(l []graph.RelKey) []codec.RelRef {
	if len(l) == 0 {
		return nil
	}
	out := make([]codec.RelRef, len(l))
	for i, k := range l {
		out[i] = codec.RelRef{Type: k.Type, From: k.From, To: k.To}
	}
	return out
}

func sortedIDs(m map[EntityID]struct{}) []EntityID {
	out := make([]EntityID, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedRelKeys[V any](m map[graph.RelKey]V) []graph.RelKey {
	out := make([]graph.RelKey, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.From != b.From {
			return a.From < b.From
		}
		return a.To < b.To
	})
	return out
}
