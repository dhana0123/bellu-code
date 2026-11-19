// Package graph holds the Bellu Graph Engine's in-memory Projection: entity,
// relation, scope and annotation state, the indexes over it, and Fold, the
// only function that mutates it.
//
// A Graph is not safe for concurrent use. The Engine guards it with its own
// lock. Pointers and slices returned by readers alias internal state and must
// be treated as read-only; use Clone for an independent copy.
package graph

import (
	"sort"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/codec"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
)

// EntityID is the stable entity identifier computed by ident.Hash.
type EntityID = string

// KindListeningPort is the kind indexed by (protocol, port).
const KindListeningPort = "listening_port"

// RelKey identifies a relation by type and endpoints.
type RelKey struct {
	Type     string
	From, To EntityID
}

// PortKey is the key of the port index.
type PortKey struct{ Protocol, Port string }

// EntityState is the projected state of one entity. Removed entities stay in
// the Graph with Live false so that they can be revived and read as-of.
type EntityState struct {
	ID       EntityID
	Kind     string
	Identity map[string]string
	Attrs    map[string]codec.Value
	// Owner maps an attribute to the collector that last set it.
	Owner map[string]string
	Live  bool
	// Asserted is the set of collectors currently asserting the entity.
	Asserted map[string]struct{}
	// VT, RT and Seq belong to the latest folded entity or annotation event.
	VT, RT time.Time
	Seq    uint64
}

// RelState is the projected state of one live relation.
type RelState struct {
	Key      RelKey
	Asserted map[string]struct{}
	VT, RT   time.Time
	Seq      uint64
	// Attrs are the relation's edge attributes, replaced by each
	// RelationAdded and RelationUpdated event.
	Attrs codec.EdgeAttrs
}

// Scope is what one collector currently asserts. Empty scopes do not exist.
type Scope struct {
	Ents map[EntityID]struct{}
	Rels map[RelKey]struct{}
}

// Annotation is operator-owned data attached to an entity.
type Annotation struct {
	Values    map[string]string
	UpdatedAt time.Time
	By        string
}

// Graph is the Projection.
type Graph struct {
	ents   map[EntityID]*EntityState
	rels   map[RelKey]*RelState
	out    map[EntityID]map[RelKey]struct{}
	in     map[EntityID]map[RelKey]struct{}
	byKind map[string][]EntityID // sorted live IDs per kind
	all    []EntityID            // sorted live IDs
	ports  map[PortKey][]EntityID
	scopes map[string]*Scope
	ann    map[EntityID]*Annotation

	LastSeq uint64
	LastRT  time.Time
	MaxVT   time.Time
}

// New returns an empty Graph.
func New() *Graph {
	return &Graph{
		ents:   map[EntityID]*EntityState{},
		rels:   map[RelKey]*RelState{},
		out:    map[EntityID]map[RelKey]struct{}{},
		in:     map[EntityID]map[RelKey]struct{}{},
		byKind: map[string][]EntityID{},
		ports:  map[PortKey][]EntityID{},
		scopes: map[string]*Scope{},
		ann:    map[EntityID]*Annotation{},
	}
}

func toTime(ns int64) time.Time {
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns).UTC()
}

func toNS(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

// ---- sorted index helpers ----

func sortedInsert(s []string, v string) []string {
	i := sort.SearchStrings(s, v)
	if i < len(s) && s[i] == v {
		return s
	}
	s = append(s, "")
	copy(s[i+1:], s[i:])
	s[i] = v
	return s
}

func sortedRemove(s []string, v string) []string {
	i := sort.SearchStrings(s, v)
	if i == len(s) || s[i] != v {
		return s
	}
	return append(s[:i], s[i+1:]...)
}

func (g *Graph) indexLive(e *EntityState) {
	g.byKind[e.Kind] = sortedInsert(g.byKind[e.Kind], e.ID)
	g.all = sortedInsert(g.all, e.ID)
	if pk, ok := portKeyOf(e); ok {
		g.ports[pk] = sortedInsert(g.ports[pk], e.ID)
	}
}

func (g *Graph) unindexLive(e *EntityState) {
	if l := sortedRemove(g.byKind[e.Kind], e.ID); len(l) == 0 {
		delete(g.byKind, e.Kind)
	} else {
		g.byKind[e.Kind] = l
	}
	g.all = sortedRemove(g.all, e.ID)
	if pk, ok := portKeyOf(e); ok {
		if l := sortedRemove(g.ports[pk], e.ID); len(l) == 0 {
			delete(g.ports, pk)
		} else {
			g.ports[pk] = l
		}
	}
}

func portKeyOf(e *EntityState) (PortKey, bool) {
	if e.Kind != KindListeningPort {
		return PortKey{}, false
	}
	return PortKey{e.Identity["protocol"], e.Identity["port"]}, true
}

// ---- readers ----

// Entity returns the entity state, live or removed.
func (g *Graph) Entity(id EntityID) (*EntityState, bool) {
	e, ok := g.ents[id]
	return e, ok
}

// Relation returns a live relation.
func (g *Graph) Relation(k RelKey) (*RelState, bool) {
	r, ok := g.rels[k]
	return r, ok
}

// Scope returns the collector's scope, or nil when it asserts nothing.
func (g *Graph) Scope(collector string) *Scope { return g.scopes[collector] }

// Collectors returns the collectors with a non-empty scope, sorted.
func (g *Graph) Collectors() []string {
	out := make([]string, 0, len(g.scopes))
	for c := range g.scopes {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Annotation returns the entity's annotation.
func (g *Graph) Annotation(id EntityID) (Annotation, bool) {
	a, ok := g.ann[id]
	if !ok {
		return Annotation{}, false
	}
	return Annotation{Values: copyStrMap(a.Values), UpdatedAt: a.UpdatedAt, By: a.By}, true
}

// AnnotationCount is the number of entities with an annotation.
func (g *Graph) AnnotationCount() int { return len(g.ann) }

// LiveIDs returns all live entity IDs, sorted. The slice is read-only.
func (g *Graph) LiveIDs() []EntityID { return g.all }

// LiveIDsOfKind returns the live IDs of one kind, sorted. Read-only.
func (g *Graph) LiveIDsOfKind(kind string) []EntityID { return g.byKind[kind] }

// LiveKinds returns the kinds that have live entities, sorted.
func (g *Graph) LiveKinds() []string {
	out := make([]string, 0, len(g.byKind))
	for k := range g.byKind {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// PortEntities returns the live listening_port IDs for (protocol, port),
// sorted. Read-only.
func (g *Graph) PortEntities(protocol, port string) []EntityID {
	return g.ports[PortKey{protocol, port}]
}

// EntityCount is the number of entities, live or removed.
func (g *Graph) EntityCount() int { return len(g.ents) }

// LiveCount is the number of live entities.
func (g *Graph) LiveCount() int { return len(g.all) }

// RelationCount is the number of live relations.
func (g *Graph) RelationCount() int { return len(g.rels) }

func sortRelKeys(l []RelKey) {
	sort.Slice(l, func(i, j int) bool { return relLess(l[i], l[j]) })
}

func relLess(a, b RelKey) bool {
	if a.Type != b.Type {
		return a.Type < b.Type
	}
	if a.From != b.From {
		return a.From < b.From
	}
	return a.To < b.To
}

func keysOf(m map[RelKey]struct{}) []RelKey {
	out := make([]RelKey, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sortRelKeys(out)
	return out
}

// RelationsFrom returns the live relations leaving id, sorted by (type, from, to).
func (g *Graph) RelationsFrom(id EntityID) []RelKey { return keysOf(g.out[id]) }

// RelationsTo returns the live relations entering id, sorted.
func (g *Graph) RelationsTo(id EntityID) []RelKey { return keysOf(g.in[id]) }

// RelationsOf returns every live relation touching id, sorted and without
// duplicates (a self-relation appears once).
func (g *Graph) RelationsOf(id EntityID) []RelKey {
	m := make(map[RelKey]struct{}, len(g.out[id])+len(g.in[id]))
	for k := range g.out[id] {
		m[k] = struct{}{}
	}
	for k := range g.in[id] {
		m[k] = struct{}{}
	}
	return keysOf(m)
}

// AllRelations returns every live relation key, sorted.
func (g *Graph) AllRelations() []RelKey {
	out := make([]RelKey, 0, len(g.rels))
	for k := range g.rels {
		out = append(out, k)
	}
	sortRelKeys(out)
	return out
}

// ---- Fold ----

func (g *Graph) scopeFor(c string) *Scope {
	s := g.scopes[c]
	if s == nil {
		s = &Scope{Ents: map[EntityID]struct{}{}, Rels: map[RelKey]struct{}{}}
		g.scopes[c] = s
	}
	return s
}

func (g *Graph) dropEmptyScope(c string) {
	if s := g.scopes[c]; s != nil && len(s.Ents) == 0 && len(s.Rels) == 0 {
		delete(g.scopes, c)
	}
}

func (g *Graph) assertEnt(e *EntityState, c string) {
	if c == "" {
		return
	}
	e.Asserted[c] = struct{}{}
	g.scopeFor(c).Ents[e.ID] = struct{}{}
}

func (g *Graph) retractEnt(e *EntityState, c string) {
	delete(e.Asserted, c)
	if s := g.scopes[c]; s != nil {
		delete(s.Ents, e.ID)
		g.dropEmptyScope(c)
	}
}

func (g *Graph) assertRel(r *RelState, c string) {
	if c == "" {
		return
	}
	r.Asserted[c] = struct{}{}
	g.scopeFor(c).Rels[r.Key] = struct{}{}
}

func (g *Graph) retractRel(r *RelState, c string) {
	delete(r.Asserted, c)
	if s := g.scopes[c]; s != nil {
		delete(s.Rels, r.Key)
		g.dropEmptyScope(c)
	}
}

func (g *Graph) touch(e *EntityState, ev codec.Event) {
	e.VT, e.RT, e.Seq = toTime(ev.ValidNS), toTime(ev.RecordedNS), ev.Seq
}

// Fold applies one event. It is the only mutator of a Graph. Events that
// refer to unknown or non-live targets change no entity or relation state but
// still advance LastSeq, LastRT and MaxVT.
func (g *Graph) Fold(ev codec.Event) {
	switch ev.Type {
	case codec.EntityCreated:
		g.foldCreated(ev)
	case codec.EntityUpdated:
		if e := g.ents[ev.ID]; e != nil && e.Live {
			for k, v := range ev.Set {
				e.Attrs[k] = copyValue(v)
				if ev.Collector != "" {
					e.Owner[k] = ev.Collector
				} else {
					delete(e.Owner, k)
				}
			}
			for _, k := range ev.Unset {
				delete(e.Attrs, k)
				delete(e.Owner, k)
			}
			g.touch(e, ev)
		}
	case codec.EntityRemoved:
		if e := g.ents[ev.ID]; e != nil {
			if e.Live {
				g.unindexLive(e)
			}
			e.Live = false
			for c := range e.Asserted {
				g.retractEnt(e, c)
			}
			g.touch(e, ev)
		}
	case codec.RelationAdded:
		g.foldRelAdded(ev)
	case codec.RelationUpdated:
		g.foldRelUpdated(ev)
	case codec.RelationRemoved:
		g.removeRel(RelKey{ev.RelType, ev.From, ev.To})
	case codec.Annotated:
		g.foldAnnotated(ev)
	case codec.ScopeDelta:
		g.foldScope(ev)
	}
	g.LastSeq = ev.Seq
	g.LastRT = toTime(ev.RecordedNS)
	if vt := toTime(ev.ValidNS); vt.After(g.MaxVT) {
		g.MaxVT = vt
	}
}

func (g *Graph) foldCreated(ev codec.Event) {
	id, err := ident.Hash(ev.Kind, ev.Identity)
	if err != nil {
		return
	}
	e := g.ents[id]
	if e == nil {
		e = &EntityState{ID: id, Kind: ev.Kind, Asserted: map[string]struct{}{}}
		g.ents[id] = e
	}
	e.Identity = copyStrMap(ev.Identity)
	e.Attrs = copyValues(ev.Attrs)
	e.Owner = make(map[string]string, len(ev.Attrs))
	if ev.Collector != "" {
		for k := range ev.Attrs {
			e.Owner[k] = ev.Collector
		}
	}
	if !e.Live {
		e.Live = true
		g.indexLive(e)
	}
	g.assertEnt(e, ev.Collector)
	g.touch(e, ev)
}

func (g *Graph) foldRelAdded(ev codec.Event) {
	k := RelKey{ev.RelType, ev.From, ev.To}
	r := g.rels[k]
	if r == nil {
		r = &RelState{Key: k, Asserted: map[string]struct{}{}}
		g.rels[k] = r
		addEdge(g.out, k.From, k)
		addEdge(g.in, k.To, k)
	}
	g.assertRel(r, ev.Collector)
	r.Attrs = ev.EdgeAttrs
	r.VT, r.RT, r.Seq = toTime(ev.ValidNS), toTime(ev.RecordedNS), ev.Seq
}

// foldRelUpdated replaces the attributes of a live relation. An update for a
// relation that is not live changes nothing.
func (g *Graph) foldRelUpdated(ev codec.Event) {
	r := g.rels[RelKey{ev.RelType, ev.From, ev.To}]
	if r == nil {
		return
	}
	r.Attrs = ev.EdgeAttrs
	r.VT, r.RT, r.Seq = toTime(ev.ValidNS), toTime(ev.RecordedNS), ev.Seq
}

func addEdge(m map[EntityID]map[RelKey]struct{}, id EntityID, k RelKey) {
	s := m[id]
	if s == nil {
		s = map[RelKey]struct{}{}
		m[id] = s
	}
	s[k] = struct{}{}
}

func delEdge(m map[EntityID]map[RelKey]struct{}, id EntityID, k RelKey) {
	if s := m[id]; s != nil {
		delete(s, k)
		if len(s) == 0 {
			delete(m, id)
		}
	}
}

func (g *Graph) removeRel(k RelKey) {
	r := g.rels[k]
	if r == nil {
		return
	}
	for c := range r.Asserted {
		g.retractRel(r, c)
	}
	delete(g.rels, k)
	delEdge(g.out, k.From, k)
	delEdge(g.in, k.To, k)
}

func (g *Graph) foldAnnotated(ev codec.Event) {
	e := g.ents[ev.ID]
	if e == nil {
		return
	}
	a := g.ann[ev.ID]
	if a == nil {
		a = &Annotation{Values: map[string]string{}}
	}
	for k, v := range ev.AnnoSet {
		a.Values[k] = v
	}
	for _, k := range ev.Unset {
		delete(a.Values, k)
	}
	if len(a.Values) == 0 {
		delete(g.ann, ev.ID)
	} else {
		a.UpdatedAt, a.By = toTime(ev.RecordedNS), ev.Actor
		g.ann[ev.ID] = a
	}
	g.touch(e, ev)
}

func (g *Graph) foldScope(ev codec.Event) {
	c := ev.Collector
	if c == "" {
		return
	}
	for _, id := range ev.AddEnts {
		if e := g.ents[id]; e != nil && e.Live {
			g.assertEnt(e, c)
		}
	}
	for _, id := range ev.DelEnts {
		if e := g.ents[id]; e != nil {
			g.retractEnt(e, c)
		}
	}
	for _, x := range ev.AddRels {
		if r := g.rels[RelKey{x.Type, x.From, x.To}]; r != nil {
			g.assertRel(r, c)
		}
	}
	for _, x := range ev.DelRels {
		if r := g.rels[RelKey{x.Type, x.From, x.To}]; r != nil {
			g.retractRel(r, c)
		}
	}
}

// ---- copying ----

func copyStrMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func copyValue(v codec.Value) codec.Value {
	if v.L != nil {
		v.L = append([]string(nil), v.L...)
	}
	return v
}

func copyValues(m map[string]codec.Value) map[string]codec.Value {
	out := make(map[string]codec.Value, len(m))
	for k, v := range m {
		out[k] = copyValue(v)
	}
	return out
}

func copySet(m map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{}, len(m))
	for k := range m {
		out[k] = struct{}{}
	}
	return out
}

// Clone returns a deep copy that shares no mutable state with g.
func (g *Graph) Clone() *Graph {
	c := New()
	for id, e := range g.ents {
		n := *e
		n.Identity = copyStrMap(e.Identity)
		n.Attrs = copyValues(e.Attrs)
		n.Owner = copyStrMap(e.Owner)
		n.Asserted = copySet(e.Asserted)
		c.ents[id] = &n
	}
	for k, r := range g.rels {
		n := *r
		n.Asserted = copySet(r.Asserted)
		c.rels[k] = &n
	}
	for id, s := range g.out {
		c.out[id] = copyKeySet(s)
	}
	for id, s := range g.in {
		c.in[id] = copyKeySet(s)
	}
	for k, l := range g.byKind {
		c.byKind[k] = append([]string(nil), l...)
	}
	c.all = append([]string(nil), g.all...)
	for k, l := range g.ports {
		c.ports[k] = append([]string(nil), l...)
	}
	for name, s := range g.scopes {
		n := &Scope{Ents: copySet(s.Ents), Rels: copyKeySet(s.Rels)}
		c.scopes[name] = n
	}
	for id, a := range g.ann {
		c.ann[id] = &Annotation{Values: copyStrMap(a.Values), UpdatedAt: a.UpdatedAt, By: a.By}
	}
	c.LastSeq, c.LastRT, c.MaxVT = g.LastSeq, g.LastRT, g.MaxVT
	return c
}

func copyKeySet(m map[RelKey]struct{}) map[RelKey]struct{} {
	out := make(map[RelKey]struct{}, len(m))
	for k := range m {
		out[k] = struct{}{}
	}
	return out
}
