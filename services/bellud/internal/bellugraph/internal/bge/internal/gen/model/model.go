// Package model is a deliberately naive reference interpreter of Batch
// semantics (classification, Collector_Scopes, retirement only when no other
// scope asserts an entity, revival and annotations). It keeps the full event
// list and recomputes every answer by brute force. It does not import the
// Engine's graph, plan or query packages.
//
// Decisions the design leaves open, fixed here so that tests agree:
//   - Entity.Identity holds the registered identity keys only; identity keys
//     outside the registered set become descriptive attributes, and explicit
//     attributes win.
//   - Scopes are the only record of assertions: an entity or relation is
//     asserted by every collector whose scope contains it. Removing an entity
//     or relation clears it from every scope.
//   - Events of one Batch are ordered: entity events in Batch order, relations
//     added in Batch order, RelationRemoved sorted by key, EntityRemoved
//     sorted by ID, then one ScopeDelta (omitted when empty).
//   - An Annotated event updates the entity's Valid/Recorded/Seq, because the
//     annotations are part of the reported entity state.
//   - The annotation key limit of 64 applies to the keys left after the call.
package model

import (
	"fmt"
	"regexp"
	"sort"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/codec"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
)

// Mode selects whether a Batch retracts what its collector omitted.
type Mode int

const (
	// Full retracts every assertion of the collector that the Batch omits.
	Full Mode = iota
	// Partial only adds and updates.
	Partial
)

// EventType mirrors the 7 event types of the design.
type EventType uint8

const (
	EntityCreated EventType = iota + 1
	EntityUpdated
	EntityRemoved
	RelationAdded
	RelationRemoved
	Annotated
	ScopeDelta
)

// RelKey is the identity of a relation.
type RelKey struct{ Type, From, To string }

// Event is one model log entry. Only the fields of its Type are meaningful.
type Event struct {
	Seq             uint64
	Valid, Recorded time.Time
	Type            EventType
	Collector       string

	ID           string            // entity events
	Kind         string            // EntityCreated
	Identity     map[string]string // EntityCreated
	Set          map[string]codec.Value
	Unset        []string
	StateChanged bool // EntityUpdated: a state/status attribute is in Set or Unset

	Rel RelKey // relation events

	AnnSet map[string]string // Annotated (Unset holds removed keys)
	Actor  string            // Annotated

	AddEnts, DelEnts []string // ScopeDelta
	AddRels, DelRels []RelKey // ScopeDelta
}

// Change is the Change_Event view of an Event.
type Change struct {
	Kind     string // added, changed, removed
	Subject  string // entity, relation
	ID       string // entity ID (entity subject)
	Rel      RelKey // relation subject
	Seq      uint64
	Valid    time.Time
	Recorded time.Time
}

// ChangeOf returns the Change_Event of ev; ok is false for ScopeDelta.
func ChangeOf(ev Event) (Change, bool) {
	c := Change{Seq: ev.Seq, Valid: ev.Valid, Recorded: ev.Recorded, Subject: "entity", ID: ev.ID}
	switch ev.Type {
	case EntityCreated:
		c.Kind = "added"
	case EntityUpdated, Annotated:
		c.Kind = "changed"
	case EntityRemoved:
		c.Kind = "removed"
	case RelationAdded:
		c.Kind, c.Subject, c.Rel = "added", "relation", ev.Rel
	case RelationRemoved:
		c.Kind, c.Subject, c.Rel = "removed", "relation", ev.Rel
	default:
		return Change{}, false
	}
	return c, true
}

// Changes returns the Change_Events of evs in order.
func Changes(evs []Event) []Change {
	var out []Change
	for _, ev := range evs {
		if c, ok := ChangeOf(ev); ok {
			out = append(out, c)
		}
	}
	return out
}

// Entity is the folded state of one entity. Removed entities stay with
// Live == false.
type Entity struct {
	ID       string
	Kind     string
	Identity map[string]string
	Attrs    map[string]codec.Value
	Owner    map[string]string // attribute -> collector that last set it
	Live     bool
	Valid    time.Time
	Recorded time.Time
	Seq      uint64
}

// Rel is a live relation.
type Rel struct {
	Key      RelKey
	Valid    time.Time
	Recorded time.Time
	Seq      uint64
}

// Scope is what one collector currently asserts.
type Scope struct {
	Ents map[string]struct{}
	Rels map[RelKey]struct{}
}

// Annotation is the operator-owned annotation set of an entity.
type Annotation struct {
	Values    map[string]string
	UpdatedAt time.Time
	By        string
}

// State is the result of folding events. Step is its only mutator.
type State struct {
	Entities map[string]*Entity
	Rels     map[RelKey]*Rel
	Scopes   map[string]*Scope
	Ann      map[string]Annotation
	LastSeq  uint64
	LastRT   time.Time
	MaxVT    time.Time
}

// NewState returns the empty state.
func NewState() *State {
	return &State{
		Entities: map[string]*Entity{},
		Rels:     map[RelKey]*Rel{},
		Scopes:   map[string]*Scope{},
		Ann:      map[string]Annotation{},
	}
}

func (s *State) scope(c string) *Scope {
	sc := s.Scopes[c]
	if sc == nil {
		sc = &Scope{Ents: map[string]struct{}{}, Rels: map[RelKey]struct{}{}}
		s.Scopes[c] = sc
	}
	return sc
}

// Step folds one event.
func (s *State) Step(ev Event) {
	switch ev.Type {
	case EntityCreated:
		e := &Entity{ID: ev.ID, Kind: ev.Kind, Identity: cloneStrs(ev.Identity), Attrs: map[string]codec.Value{}, Owner: map[string]string{}, Live: true}
		for k, v := range ev.Set {
			e.Attrs[k] = v
			e.Owner[k] = ev.Collector
		}
		s.Entities[ev.ID] = e
		s.scope(ev.Collector).Ents[ev.ID] = struct{}{}
		stamp(e, ev)
	case EntityUpdated:
		// Events for unknown or removed targets change nothing (out-of-order
		// Valid_Times make them reachable in as-of folds).
		if e := s.Entities[ev.ID]; e != nil && e.Live {
			for k, v := range ev.Set {
				e.Attrs[k] = v
				e.Owner[k] = ev.Collector
			}
			for _, k := range ev.Unset {
				delete(e.Attrs, k)
				delete(e.Owner, k)
			}
			stamp(e, ev)
		}
	case EntityRemoved:
		if e := s.Entities[ev.ID]; e != nil {
			e.Live = false
			stamp(e, ev)
			for _, sc := range s.Scopes {
				delete(sc.Ents, ev.ID)
			}
		}
	case RelationAdded:
		s.Rels[ev.Rel] = &Rel{Key: ev.Rel, Valid: ev.Valid, Recorded: ev.Recorded, Seq: ev.Seq}
		s.scope(ev.Collector).Rels[ev.Rel] = struct{}{}
	case RelationRemoved:
		delete(s.Rels, ev.Rel)
		for _, sc := range s.Scopes {
			delete(sc.Rels, ev.Rel)
		}
	case Annotated:
		e := s.Entities[ev.ID]
		if e == nil {
			break
		}
		a := s.Ann[ev.ID]
		vals := cloneStrs(a.Values)
		for k, v := range ev.AnnSet {
			vals[k] = v
		}
		for _, k := range ev.Unset {
			delete(vals, k)
		}
		if len(vals) == 0 {
			delete(s.Ann, ev.ID)
		} else {
			s.Ann[ev.ID] = Annotation{Values: vals, UpdatedAt: ev.Recorded, By: ev.Actor}
		}
		stamp(e, ev)
	case ScopeDelta:
		sc := s.scope(ev.Collector)
		for _, id := range ev.AddEnts {
			if s.IsLive(id) { // a delta naming an unknown or removed entity changes nothing
				sc.Ents[id] = struct{}{}
			}
		}
		for _, id := range ev.DelEnts {
			delete(sc.Ents, id)
		}
		for _, k := range ev.AddRels {
			if s.Rels[k] != nil {
				sc.Rels[k] = struct{}{}
			}
		}
		for _, k := range ev.DelRels {
			delete(sc.Rels, k)
		}
	}
	s.LastSeq = ev.Seq
	s.LastRT = ev.Recorded
	if ev.Valid.After(s.MaxVT) {
		s.MaxVT = ev.Valid
	}
}

func stamp(e *Entity, ev Event) { e.Valid, e.Recorded, e.Seq = ev.Valid, ev.Recorded, ev.Seq }

// IsLive reports whether id is a live entity.
func (s *State) IsLive(id string) bool {
	e := s.Entities[id]
	return e != nil && e.Live
}

// LiveIDs returns the live Entity_IDs, sorted.
func (s *State) LiveIDs() []string {
	var out []string
	for id, e := range s.Entities {
		if e.Live {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// LiveRels returns the live relation keys, sorted by (type, from, to).
func (s *State) LiveRels() []RelKey {
	out := make([]RelKey, 0, len(s.Rels))
	for k := range s.Rels {
		out = append(out, k)
	}
	sortRels(out)
	return out
}

// Asserted returns the collectors that assert entity id, sorted.
func (s *State) Asserted(id string) []string {
	var out []string
	for c, sc := range s.Scopes {
		if _, ok := sc.Ents[id]; ok {
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}

// AssertedRel returns the collectors that assert relation k, sorted.
func (s *State) AssertedRel(k RelKey) []string {
	var out []string
	for c, sc := range s.Scopes {
		if _, ok := sc.Rels[k]; ok {
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}

// Annotation returns the annotations of a live entity.
func (s *State) Annotation(id string) (Annotation, bool) {
	if !s.IsLive(id) {
		return Annotation{}, false
	}
	a, ok := s.Ann[id]
	return a, ok
}

// Model owns the event list and the current State.
type Model struct {
	Log []Event
	cur *State
}

// New returns an empty model.
func New() *Model { return &Model{cur: NewState()} }

// Current returns the folded current state. Callers must not mutate it.
func (m *Model) Current() *State { return m.cur }

// AsOf folds, from empty and in log order, every event with Valid <= at.
func (m *Model) AsOf(at time.Time) *State {
	s := NewState()
	for _, ev := range m.Log {
		if !ev.Valid.After(at) {
			s.Step(ev)
		}
	}
	return s
}

// Fold interprets one Batch at clock reading now and appends the resulting
// events. A rejected Batch returns an error wrapping errs.Validation and
// changes nothing. A Batch that changes nothing returns no events.
func (m *Model) Fold(b batch.Batch, mode Mode, now time.Time) ([]Event, error) {
	p, err := m.plan(b, mode)
	if err != nil {
		return nil, err
	}
	now = now.UTC()
	valid := b.ObservedAt
	if valid.IsZero() {
		valid = now
	}
	recorded := now
	if recorded.Before(m.cur.LastRT) {
		recorded = m.cur.LastRT
	}
	for i := range p {
		p[i].Valid, p[i].Recorded, p[i].Collector = valid, recorded, b.Collector
	}
	return m.commit(p), nil
}

// Annotate sets and unsets operator annotations on a live entity at clock
// reading now.
func (m *Model) Annotate(id, actor string, set map[string]string, unset []string, now time.Time) (Event, error) {
	if !m.cur.IsLive(id) {
		return Event{}, fmt.Errorf("%w: entity %q", errs.NotFound, id)
	}
	keys := map[string]struct{}{}
	if a, ok := m.cur.Ann[id]; ok {
		for k := range a.Values {
			keys[k] = struct{}{}
		}
	}
	for k, v := range set {
		if !annKey.MatchString(k) {
			return Event{}, fmt.Errorf("%w: annotation key %q", errs.Validation, k)
		}
		if len(v) > 1024 {
			return Event{}, fmt.Errorf("%w: annotation %q value exceeds 1024 bytes", errs.Validation, k)
		}
		keys[k] = struct{}{}
	}
	for _, k := range unset {
		delete(keys, k)
	}
	for k := range set { // a key set and unset in one call is set last
		keys[k] = struct{}{}
	}
	if len(keys) > 64 {
		return Event{}, fmt.Errorf("%w: more than 64 annotation keys", errs.Validation)
	}
	now = now.UTC()
	if now.Before(m.cur.LastRT) {
		now = m.cur.LastRT
	}
	un := append([]string(nil), unset...)
	sort.Strings(un)
	ev := Event{Valid: now, Recorded: now, Type: Annotated, ID: id, Actor: actor, AnnSet: cloneStrs(set), Unset: un}
	return m.commit([]Event{ev})[0], nil
}

var annKey = regexp.MustCompile(`^[a-z0-9_.-]{1,64}$`)

func (m *Model) commit(evs []Event) []Event {
	for i := range evs {
		evs[i].Seq = m.cur.LastSeq + 1
		m.cur.Step(evs[i])
		m.Log = append(m.Log, evs[i])
	}
	return evs
}

type obs struct {
	id       string
	kind     string
	identity map[string]string
	attrs    map[string]codec.Value
}

// plan classifies b against the current state and returns unstamped events.
func (m *Model) plan(b batch.Batch, mode Mode) ([]Event, error) {
	if b.Collector == "" {
		return nil, fmt.Errorf("%w: collector is empty", errs.Validation)
	}
	cur := m.cur
	var ents []obs
	inBatch := map[string]bool{}
	for _, e := range b.Entities {
		id, err := ident.Hash(e.Type, e.Identity)
		if err != nil {
			return nil, err
		}
		if inBatch[id] {
			return nil, fmt.Errorf("%w: duplicate entity %s", errs.Validation, id)
		}
		inBatch[id] = true
		o := obs{id: id, kind: e.Type, identity: map[string]string{}, attrs: map[string]codec.Value{}}
		registered, _ := ident.IdentityAttributes(e.Type)
		isReg := map[string]bool{}
		for _, k := range registered {
			isReg[k] = true
			o.identity[k] = e.Identity[k]
		}
		for k, v := range e.Identity {
			if !isReg[k] {
				o.attrs[k] = codec.Value{T: codec.TagString, S: v}
			}
		}
		for k, v := range e.Attributes {
			cv, err := codec.FromAny(k, v)
			if err != nil {
				return nil, err
			}
			o.attrs[k] = cv
		}
		ents = append(ents, o)
	}

	var rels []RelKey
	inBatchRel := map[RelKey]bool{}
	for _, r := range b.Relations {
		if r.Type == "" {
			return nil, fmt.Errorf("%w: relation without a type (%s -> %s)", errs.Validation, r.From, r.To)
		}
		if len(r.Attributes) > 0 {
			return nil, fmt.Errorf("%w: relation %s %s -> %s carries attributes", errs.Validation, r.Type, r.From, r.To)
		}
		k := RelKey{r.Type, r.From, r.To}
		if !inBatchRel[k] {
			inBatchRel[k] = true
			rels = append(rels, k)
		}
	}

	// Retractions (Full mode only).
	sc := cur.scope0(b.Collector)
	retire := map[string]bool{}
	var delEnts []string
	var delRels []RelKey
	retireRel := map[RelKey]bool{}
	if mode == Full {
		for id := range sc.Ents {
			if inBatch[id] {
				continue
			}
			if len(othersAssert(cur, b.Collector, id)) == 0 && cur.IsLive(id) {
				retire[id] = true // EntityRemoved retracts every assertion
				continue
			}
			delEnts = append(delEnts, id)
		}
		for k := range sc.Rels {
			if inBatchRel[k] {
				continue
			}
			if len(othersAssertRel(cur, b.Collector, k)) == 0 {
				retireRel[k] = true // RelationRemoved retracts every assertion
				continue
			}
			delRels = append(delRels, k)
		}
	}

	for _, k := range rels {
		for _, end := range []string{k.From, k.To} {
			if inBatch[end] {
				continue
			}
			if retire[end] {
				return nil, fmt.Errorf("%w: relation %s endpoint %s is retired by the same batch", errs.Validation, k.Type, end)
			}
			if !cur.IsLive(end) {
				return nil, fmt.Errorf("%w: relation %s endpoint %s is neither in the batch nor live", errs.Validation, k.Type, end)
			}
		}
	}

	var evs []Event
	var addEnts []string
	for _, o := range ents {
		e := cur.Entities[o.id]
		if e == nil || !e.Live {
			// Created asserts for its collector; no ScopeDelta entry is needed.
			evs = append(evs, Event{Type: EntityCreated, ID: o.id, Kind: o.kind, Identity: o.identity, Set: o.attrs})
			continue
		}
		if _, ok := sc.Ents[o.id]; !ok {
			addEnts = append(addEnts, o.id)
		}
		set := map[string]codec.Value{}
		var unset []string
		for k, v := range o.attrs {
			if old, ok := e.Attrs[k]; !ok || !old.Equal(v) {
				set[k] = v
			}
		}
		for k := range e.Attrs {
			if _, ok := o.attrs[k]; !ok && e.Owner[k] == b.Collector {
				unset = append(unset, k)
			}
		}
		if len(set) == 0 && len(unset) == 0 {
			continue
		}
		sort.Strings(unset)
		state := false
		for k := range set {
			state = state || ident.IsStateAttr(k)
		}
		for _, k := range unset {
			state = state || ident.IsStateAttr(k)
		}
		evs = append(evs, Event{Type: EntityUpdated, ID: o.id, Set: set, Unset: unset, StateChanged: state})
	}
	var addRels []RelKey
	for _, k := range rels {
		if cur.Rels[k] == nil {
			// RelationAdded asserts for its collector.
			evs = append(evs, Event{Type: RelationAdded, Rel: k})
		} else if _, ok := sc.Rels[k]; !ok {
			addRels = append(addRels, k)
		}
	}

	// Relations touching retired entities go with them.
	removeRel := map[RelKey]bool{}
	for k := range retireRel {
		if cur.Rels[k] != nil {
			removeRel[k] = true
		}
	}
	for k := range cur.Rels {
		if retire[k.From] || retire[k.To] {
			removeRel[k] = true
		}
	}
	rk := make([]RelKey, 0, len(removeRel))
	for k := range removeRel {
		rk = append(rk, k)
	}
	sortRels(rk)
	for _, k := range rk {
		evs = append(evs, Event{Type: RelationRemoved, Rel: k})
	}
	var rids []string
	for id := range retire {
		rids = append(rids, id)
	}
	sort.Strings(rids)
	for _, id := range rids {
		evs = append(evs, Event{Type: EntityRemoved, ID: id})
	}

	sort.Strings(addEnts)
	sort.Strings(delEnts)
	sortRels(addRels)
	sortRels(delRels)
	if len(addEnts)+len(delEnts)+len(addRels)+len(delRels) > 0 {
		evs = append(evs, Event{Type: ScopeDelta, AddEnts: addEnts, DelEnts: delEnts, AddRels: addRels, DelRels: delRels})
	}
	return evs, nil
}

func (s *State) scope0(c string) Scope {
	if sc := s.Scopes[c]; sc != nil {
		return *sc
	}
	return Scope{Ents: map[string]struct{}{}, Rels: map[RelKey]struct{}{}}
}

func othersAssert(s *State, self, id string) []string {
	var out []string
	for _, c := range s.Asserted(id) {
		if c != self {
			out = append(out, c)
		}
	}
	return out
}

func othersAssertRel(s *State, self string, k RelKey) []string {
	var out []string
	for _, c := range s.AssertedRel(k) {
		if c != self {
			out = append(out, c)
		}
	}
	return out
}

// DiffResult is the comparison of two as-of states.
type DiffResult struct {
	Added, Removed, Changed []string
	Flapping                []Flap
}

// Flap is an entity with at least two changes and equal start and end states.
type Flap struct {
	ID    string
	Count int
}

// Diff compares AsOf(from) with AsOf(to) and lists flapping entities.
func (m *Model) Diff(from, to time.Time) DiffResult {
	a, b := m.AsOf(from), m.AsOf(to)
	var d DiffResult
	ids := map[string]struct{}{}
	for id := range a.Entities {
		ids[id] = struct{}{}
	}
	for id := range b.Entities {
		ids[id] = struct{}{}
	}
	counts := map[string]int{}
	for _, ev := range m.Log {
		switch ev.Type {
		case EntityCreated, EntityUpdated, EntityRemoved, Annotated:
			if ev.Valid.After(from) && !ev.Valid.After(to) {
				counts[ev.ID]++
			}
		}
	}
	// An entity absent from both states (its events precede its creation in
	// Valid_Time) can still flap: absent in both counts as the same state.
	for id := range counts {
		ids[id] = struct{}{}
	}
	sorted := make([]string, 0, len(ids))
	for id := range ids {
		sorted = append(sorted, id)
	}
	sort.Strings(sorted)
	for _, id := range sorted {
		la, lb := a.IsLive(id), b.IsLive(id)
		switch {
		case lb && !la:
			d.Added = append(d.Added, id)
		case la && !lb:
			d.Removed = append(d.Removed, id)
		case la && lb && !sameEntity(a, b, id):
			d.Changed = append(d.Changed, id)
		}
		if counts[id] >= 2 && sameStates(a, b, id) {
			d.Flapping = append(d.Flapping, Flap{ID: id, Count: counts[id]})
		}
	}
	sort.SliceStable(d.Flapping, func(i, j int) bool {
		if d.Flapping[i].Count != d.Flapping[j].Count {
			return d.Flapping[i].Count > d.Flapping[j].Count
		}
		return d.Flapping[i].ID < d.Flapping[j].ID
	})
	return d
}

// sameStates is "A(e) == B(e)" with absent-in-both (or removed in both) equal.
func sameStates(a, b *State, id string) bool {
	la, lb := a.IsLive(id), b.IsLive(id)
	if la != lb {
		return false
	}
	return !la || sameEntity(a, b, id)
}

func sameEntity(a, b *State, id string) bool {
	ea, eb := a.Entities[id], b.Entities[id]
	if len(ea.Attrs) != len(eb.Attrs) {
		return false
	}
	for k, v := range ea.Attrs {
		if w, ok := eb.Attrs[k]; !ok || !v.Equal(w) {
			return false
		}
	}
	xa, xb := a.Ann[id].Values, b.Ann[id].Values
	if len(xa) != len(xb) {
		return false
	}
	for k, v := range xa {
		if w, ok := xb[k]; !ok || v != w {
			return false
		}
	}
	return true
}

func sortRels(r []RelKey) {
	sort.Slice(r, func(i, j int) bool {
		if r[i].Type != r[j].Type {
			return r[i].Type < r[j].Type
		}
		if r[i].From != r[j].From {
			return r[i].From < r[j].From
		}
		return r[i].To < r[j].To
	})
}

func cloneStrs(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
