package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/codec"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/graph"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/query"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/resolve"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/store"
)

// Page size bounds, re-exported from query.
const (
	DefaultPageSize = query.DefaultPageSize
	MaxPageSize     = query.MaxPageSize
)

// Traversal directions.
const (
	DirOut  = query.DirOut
	DirIn   = query.DirIn
	DirBoth = query.DirBoth
)

// DerivedFn supplies derived edges to Neighbors; nil means stored only.
type DerivedFn = query.DerivedFn

// Paging selects a page. PageSize 0 means DefaultPageSize.
type Paging struct {
	PageSize int
	Cursor   string
}

// Page is one page of results. Total counts the whole matching set and
// Truncated is true when more items follow (NextCursor).
type Page[T any] struct {
	Items      []T
	Total      int
	Truncated  bool
	Limit      int
	NextCursor string
}

// EntityID is the stable entity identifier.
type EntityID = graph.EntityID

// EntityView is the current state of one entity.
type EntityView struct {
	ID          EntityID
	Kind        string
	Label       string
	Attributes  map[string]any // identity and descriptive attributes
	Annotations map[string]string
	ObservedAt  time.Time
	RecordedAt  time.Time
}

// EdgeView is a relation reached by Neighbors.
type EdgeView struct {
	Type      string
	From, To  EntityID
	Direction string
	Hops      int
	Derived   bool
}

// FindQuery filters live entities. An empty Kind matches every kind.
type FindQuery struct {
	Kind       string
	Attributes map[string]string // AND over identity and descriptive attributes
	Paging
}

// NeighborOpts selects a traversal. Zero Direction is DirBoth, zero Depth 1.
// Derived is optional; nil means stored relations only.
type NeighborOpts struct {
	Direction    string
	RelationType string
	Depth        int
	Derived      DerivedFn
	// Resolve adds Endpoint_Resolution (derived resolves_to relations) computed
	// over the graph being read. It is ignored when Derived is set.
	Resolve bool
	Paging
}

// TimeRange bounds Valid_Time inclusively. A zero bound is open.
type TimeRange struct{ From, To time.Time }

// ChangeKind and ChangeSubject classify a Change_Event.
type (
	ChangeKind    string
	ChangeSubject string
)

// Change kinds and subjects.
const (
	ChangeAdded     ChangeKind    = "added"
	ChangeChanged   ChangeKind    = "changed"
	ChangeRemoved   ChangeKind    = "removed"
	SubjectEntity   ChangeSubject = "entity"
	SubjectRelation ChangeSubject = "relation"
)

// ChangeView is one Change_Event.
type ChangeView struct {
	Seq          uint64
	Kind         ChangeKind
	Subject      ChangeSubject
	Entity       EntityID // subject entity (entity changes)
	EntityKind   string   // kind of the subject entity (entity changes)
	From, To     EntityID // relation endpoints (relation changes)
	RelationType string
	ObservedAt   time.Time
	RecordedAt   time.Time
}

// ChangeFilter narrows Changes and Digest. Zero fields match everything.
// Entity matches a change about the entity or a relation touching it.
// EntityKind matches entity changes whose subject has that kind; relation
// changes have no entity kind and never match it.
type ChangeFilter struct {
	Kind       ChangeKind
	Subject    ChangeSubject
	EntityKind string
	Entity     EntityID
	Paging
}

// Order is the ordering of Changes.
type Order int

// Orders.
const (
	OrderAsc  Order = iota // (Valid_Time, seq) ascending
	OrderDesc              // (Valid_Time, seq) descending
)

// Flap is an entity with its change count.
type Flap struct {
	ID      EntityID
	Changes int
}

// Digest summarizes the Change_Events of a range and filter.
type Digest struct {
	Total        int
	ByKind       map[string]int
	BySubject    map[string]int
	ByEntityKind map[string]int
	Top          []Flap // up to 10 entities by change count desc, then ID
}

const digestTop = 10

// begin checks the Engine can serve a read and times it.
func (c *Core) begin(ctx context.Context, op string) (done func(), err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := c.readable(); err != nil {
		return nil, err
	}
	start := time.Now()
	return func() { c.met.Query(op, time.Since(start)) }, nil
}

// Entity returns the state of a live entity. A non-nil at selects the state
// as of that Valid_Time instant.
func (c *Core) Entity(ctx context.Context, id EntityID, at *time.Time) (EntityView, error) {
	done, err := c.begin(ctx, "entity")
	if err != nil {
		return EntityView{}, err
	}
	defer done()
	if at != nil {
		return c.entityAt(ctx, id, *at)
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.g.Entity(id)
	if !ok || !e.Live {
		return EntityView{}, fmt.Errorf("%w: entity %s", errs.NotFound, id)
	}
	return entityView(c.g, e), nil
}

func entityView(g *graph.Graph, e *graph.EntityState) EntityView {
	attrs := make(map[string]any, len(e.Attrs)+len(e.Identity))
	for k, v := range e.Attrs {
		attrs[k] = v.ToAny()
	}
	for k, v := range e.Identity {
		attrs[k] = v
	}
	v := EntityView{
		ID: e.ID, Kind: e.Kind, Label: ident.Label(e.Kind, e.Identity, attrs),
		Attributes: attrs, ObservedAt: e.VT, RecordedAt: e.RT,
	}
	if a, ok := g.Annotation(e.ID); ok {
		v.Annotations = a.Values
	}
	return v
}

// Find returns the live entities matching q, ordered by Entity_ID.
func (c *Core) Find(ctx context.Context, q FindQuery, at *time.Time) (Page[EntityView], error) {
	done, err := c.begin(ctx, "find")
	if err != nil {
		return Page[EntityView]{}, err
	}
	defer done()
	limit, err := query.PageLimit(q.PageSize)
	if err != nil {
		return Page[EntityView]{}, err
	}
	keys := make([]string, 0, len(q.Attributes))
	for k := range q.Attributes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := []string{"find", q.Kind}
	for _, k := range keys {
		parts = append(parts, k, q.Attributes[k])
	}
	qh := query.QueryHash(parts...)
	var after string
	if q.Cursor != "" {
		b, err := query.DecodeCursor("find", qh, q.Cursor)
		if err != nil {
			return Page[EntityView]{}, err
		}
		after = string(b)
	}
	g, release, err := c.readGraph(ctx, at)
	if err != nil {
		return Page[EntityView]{}, err
	}
	defer release()
	ids := query.Find(g, q.Kind, q.Attributes)
	start := 0
	if q.Cursor != "" {
		start = query.AfterString(ids, after)
	}
	end := min(start+limit, len(ids))
	pg := Page[EntityView]{Items: make([]EntityView, 0, end-start), Total: len(ids), Limit: limit}
	for _, id := range ids[start:end] {
		e, _ := g.Entity(id)
		pg.Items = append(pg.Items, entityView(g, e))
	}
	if end < len(ids) {
		pg.Truncated = true
		pg.NextCursor = query.EncodeCursor("find", qh, []byte(ids[end-1]))
	}
	return pg, nil
}

// Neighbors returns the relations reachable from id within o.Depth hops, each
// once at its fewest hops, ordered by (hops, type, from, to).
func (c *Core) Neighbors(ctx context.Context, id EntityID, o NeighborOpts, at *time.Time) (Page[EdgeView], error) {
	done, err := c.begin(ctx, "neighbors")
	if err != nil {
		return Page[EdgeView]{}, err
	}
	defer done()
	limit, err := query.PageLimit(o.PageSize)
	if err != nil {
		return Page[EdgeView]{}, err
	}
	dir, depth := o.Direction, o.Depth
	if dir == "" {
		dir = DirBoth
	}
	if depth == 0 {
		depth = 1
	}
	if dir != DirOut && dir != DirIn && dir != DirBoth {
		return Page[EdgeView]{}, fmt.Errorf("%w: direction %q must be out, in or both", errs.Validation, dir)
	}
	if depth < 1 || depth > query.MaxDepth {
		return Page[EdgeView]{}, fmt.Errorf("%w: depth %d is outside 1 to %d", errs.Validation, depth, query.MaxDepth)
	}
	qh := query.QueryHash("neighbors", id, dir, o.RelationType, strconv.Itoa(depth))
	var after []byte
	if o.Cursor != "" {
		if after, err = query.DecodeCursor("neighbors", qh, o.Cursor); err != nil {
			return Page[EdgeView]{}, err
		}
	}
	g, release, err := c.readGraph(ctx, at)
	if err != nil {
		return Page[EdgeView]{}, err
	}
	defer release()
	if _, ok := g.Entity(id); !ok {
		return Page[EdgeView]{}, fmt.Errorf("%w: entity %s", errs.NotFound, id)
	}
	derived := o.Derived
	if o.Resolve && derived == nil {
		derived = resolve.DerivedFn(g)
	}
	edges := query.Neighbors(g, id, dir, o.RelationType, depth, derived)
	start := 0
	if o.Cursor != "" {
		last, err := decodeEdgeKey(after)
		if err != nil {
			return Page[EdgeView]{}, err
		}
		start = sort.Search(len(edges), func(i int) bool { return edgeKeyLess(last, edgeKeyOf(edges[i])) })
	}
	end := min(start+limit, len(edges))
	pg := Page[EdgeView]{Items: make([]EdgeView, 0, end-start), Total: len(edges), Limit: limit}
	for _, e := range edges[start:end] {
		pg.Items = append(pg.Items, EdgeView(e))
	}
	if end < len(edges) {
		pg.Truncated = true
		pg.NextCursor = query.EncodeCursor("neighbors", qh, encodeEdgeKey(edgeKeyOf(edges[end-1])))
	}
	return pg, nil
}

type edgeKey struct {
	hops          int
	typ, from, to string
}

func edgeKeyOf(e query.Edge) edgeKey { return edgeKey{e.Hops, e.Type, e.From, e.To} }

func edgeKeyLess(a, b edgeKey) bool {
	if a.hops != b.hops {
		return a.hops < b.hops
	}
	if a.typ != b.typ {
		return a.typ < b.typ
	}
	if a.from != b.from {
		return a.from < b.from
	}
	return a.to < b.to
}

func encodeEdgeKey(k edgeKey) []byte {
	b := binary.BigEndian.AppendUint32(nil, uint32(k.hops))
	return append(b, k.typ+"\x00"+k.from+"\x00"+k.to...)
}

func decodeEdgeKey(b []byte) (edgeKey, error) {
	if len(b) < 4 {
		return edgeKey{}, fmt.Errorf("%w: malformed cursor", errs.Validation)
	}
	parts := strings.Split(string(b[4:]), "\x00")
	if len(parts) != 3 {
		return edgeKey{}, fmt.Errorf("%w: malformed cursor", errs.Validation)
	}
	return edgeKey{int(binary.BigEndian.Uint32(b)), parts[0], parts[1], parts[2]}, nil
}

// History returns the entity's own Change_Events and those of relations
// touching it within r, oldest first.
func (c *Core) History(ctx context.Context, id EntityID, r TimeRange, p Paging) (Page[ChangeView], error) {
	done, err := c.begin(ctx, "history")
	if err != nil {
		return Page[ChangeView]{}, err
	}
	defer done()
	limit, err := query.PageLimit(p.PageSize)
	if err != nil {
		return Page[ChangeView]{}, err
	}
	qh := query.QueryHash("history", id, strconv.FormatInt(rangeNS(r.From, math.MinInt64), 10), strconv.FormatInt(rangeNS(r.To, math.MaxInt64), 10))
	c.mu.RLock()
	defer c.mu.RUnlock()
	if _, ok := c.g.Entity(id); !ok {
		return Page[ChangeView]{}, fmt.Errorf("%w: entity %s", errs.NotFound, id)
	}
	v := c.st.NewView()
	defer v.Close()
	cands, err := c.entityCandidates(v, id, r, ChangeFilter{})
	if err != nil {
		return Page[ChangeView]{}, err
	}
	return c.changePage(v, "history", qh, cands, OrderAsc, p.Cursor, limit, ChangeFilter{})
}

// Changes returns the Change_Events within r matching f, ordered by
// (Valid_Time, seq) ascending or descending.
func (c *Core) Changes(ctx context.Context, r TimeRange, f ChangeFilter, order Order) (Page[ChangeView], error) {
	done, err := c.begin(ctx, "changes")
	if err != nil {
		return Page[ChangeView]{}, err
	}
	defer done()
	limit, err := query.PageLimit(f.PageSize)
	if err != nil {
		return Page[ChangeView]{}, err
	}
	if order != OrderAsc && order != OrderDesc {
		return Page[ChangeView]{}, fmt.Errorf("%w: unknown order %d", errs.Validation, order)
	}
	qh := query.QueryHash("changes", strconv.FormatInt(rangeNS(r.From, math.MinInt64), 10), strconv.FormatInt(rangeNS(r.To, math.MaxInt64), 10),
		string(f.Kind), string(f.Subject), f.EntityKind, f.Entity, strconv.Itoa(int(order)))
	c.mu.RLock()
	defer c.mu.RUnlock()
	v := c.st.NewView()
	defer v.Close()
	cands, err := c.changeCandidates(v, r, f)
	if err != nil {
		return Page[ChangeView]{}, err
	}
	return c.changePage(v, "changes", qh, cands, order, f.Cursor, limit, f)
}

// Digest summarizes the Change_Events within r matching f: counts by kind,
// subject and entity kind, and the 10 entities with the most changes.
func (c *Core) Digest(ctx context.Context, r TimeRange, f ChangeFilter) (Digest, error) {
	done, err := c.begin(ctx, "digest")
	if err != nil {
		return Digest{}, err
	}
	defer done()
	c.mu.RLock()
	defer c.mu.RUnlock()
	v := c.st.NewView()
	defer v.Close()
	cands, err := c.changeCandidates(v, r, f)
	if err != nil {
		return Digest{}, err
	}
	d := Digest{ByKind: map[string]int{}, BySubject: map[string]int{}, ByEntityKind: map[string]int{}, Top: []Flap{}}
	perEntity := map[EntityID]int{}
	for _, cd := range cands {
		cv, err := c.loadChange(v, cd.Seq)
		if err != nil {
			return Digest{}, err
		}
		if !matchesEntityKind(cv, f) {
			continue
		}
		d.Total++
		d.ByKind[string(cv.Kind)]++
		d.BySubject[string(cv.Subject)]++
		if cv.Subject == SubjectEntity {
			d.ByEntityKind[cv.EntityKind]++
			perEntity[cv.Entity]++
		}
	}
	for id, n := range perEntity {
		d.Top = append(d.Top, Flap{id, n})
	}
	sort.Slice(d.Top, func(i, j int) bool {
		if d.Top[i].Changes != d.Top[j].Changes {
			return d.Top[i].Changes > d.Top[j].Changes
		}
		return d.Top[i].ID < d.Top[j].ID
	})
	if len(d.Top) > digestTop {
		d.Top = d.Top[:digestTop]
	}
	return d, nil
}

func rangeNS(t time.Time, open int64) int64 {
	if t.IsZero() {
		return open
	}
	return t.UnixNano()
}

// changeKindSubject classifies an event type; ok is false for events that are
// not Change_Events.
func changeKindSubject(t codec.EventType) (ChangeKind, ChangeSubject, bool) {
	switch t {
	case codec.EntityCreated:
		return ChangeAdded, SubjectEntity, true
	case codec.EntityUpdated, codec.Annotated:
		return ChangeChanged, SubjectEntity, true
	case codec.EntityRemoved:
		return ChangeRemoved, SubjectEntity, true
	case codec.RelationAdded:
		return ChangeAdded, SubjectRelation, true
	case codec.RelationRemoved:
		return ChangeRemoved, SubjectRelation, true
	}
	return "", "", false
}

// keep reports whether an index entry is a Change_Event inside the read's
// consistent prefix of the log that matches the type-level filter.
func (c *Core) keep(e store.IndexEntry, f ChangeFilter) bool {
	if e.Seq > c.g.LastSeq {
		return false
	}
	k, s, ok := changeKindSubject(e.Type)
	if !ok {
		return false
	}
	return (f.Kind == "" || f.Kind == k) && (f.Subject == "" || f.Subject == s)
}

// entityCandidates lists the entries of the entity and of relations touching
// it within r, once per seq.
func (c *Core) entityCandidates(v *store.View, id EntityID, r TimeRange, f ChangeFilter) ([]store.IndexEntry, error) {
	own, err := v.EntityEntries(id)
	if err != nil {
		return nil, err
	}
	rels, err := v.RelationEntries(id)
	if err != nil {
		return nil, err
	}
	lo, hi := rangeNS(r.From, math.MinInt64), rangeNS(r.To, math.MaxInt64)
	seen := map[uint64]struct{}{}
	var out []store.IndexEntry
	for _, e := range append(own, rels...) {
		if e.ValidNS < lo || e.ValidNS > hi || !c.keep(e, f) {
			continue
		}
		if _, dup := seen[e.Seq]; dup {
			continue
		}
		seen[e.Seq] = struct{}{}
		out = append(out, e)
	}
	return out, nil
}

// changeCandidates lists the type-level matches of f within r.
func (c *Core) changeCandidates(v *store.View, r TimeRange, f ChangeFilter) ([]store.IndexEntry, error) {
	if f.Entity != "" {
		return c.entityCandidates(v, f.Entity, r, f)
	}
	all, err := v.ValidRange(rangeNS(r.From, math.MinInt64), rangeNS(r.To, math.MaxInt64))
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, e := range all {
		if c.keep(e, f) {
			out = append(out, e)
		}
	}
	return out, nil
}

func matchesEntityKind(cv ChangeView, f ChangeFilter) bool {
	return f.EntityKind == "" || (cv.Subject == SubjectEntity && cv.EntityKind == f.EntityKind)
}

// loadChange decodes the event at seq into a ChangeView.
func (c *Core) loadChange(v *store.View, seq uint64) (ChangeView, error) {
	ev, err := v.Event(seq)
	if err != nil {
		if errors.Is(err, errs.Corrupt) {
			c.fail(err)
		}
		return ChangeView{}, err
	}
	kind, subj, _ := changeKindSubject(ev.Type)
	cv := ChangeView{
		Seq: seq, Kind: kind, Subject: subj,
		ObservedAt: time.Unix(0, ev.ValidNS).UTC(), RecordedAt: time.Unix(0, ev.RecordedNS).UTC(),
	}
	if subj == SubjectRelation {
		cv.From, cv.To, cv.RelationType = ev.From, ev.To, ev.RelType
		return cv, nil
	}
	cv.Entity = ev.ID
	cv.EntityKind = ev.Kind
	if ev.Type == codec.EntityCreated {
		id, err := ident.Hash(ev.Kind, ev.Identity)
		if err != nil {
			return ChangeView{}, fmt.Errorf("%w: event %d: %v", errs.Corrupt, seq, err)
		}
		cv.Entity = id
	} else if e, ok := c.g.Entity(ev.ID); ok {
		cv.EntityKind = e.Kind
	}
	return cv, nil
}

type changeKey struct {
	valid int64
	seq   uint64
}

func encodeChangeKey(valid int64, seq uint64) []byte {
	b := binary.BigEndian.AppendUint64(nil, uint64(valid)^(1<<63))
	return binary.BigEndian.AppendUint64(b, seq)
}

func decodeChangeKey(b []byte) (changeKey, error) {
	if len(b) != 16 {
		return changeKey{}, fmt.Errorf("%w: malformed cursor", errs.Validation)
	}
	return changeKey{int64(binary.BigEndian.Uint64(b) ^ (1 << 63)), binary.BigEndian.Uint64(b[8:])}, nil
}

// changePage orders cands, applies the cursor and the entity-kind filter, and
// loads the page.
func (c *Core) changePage(v *store.View, kind string, qh uint64, cands []store.IndexEntry, order Order, cursor string, limit int, f ChangeFilter) (Page[ChangeView], error) {
	var after changeKey
	if cursor != "" {
		b, err := query.DecodeCursor(kind, qh, cursor)
		if err != nil {
			return Page[ChangeView]{}, err
		}
		if after, err = decodeChangeKey(b); err != nil {
			return Page[ChangeView]{}, err
		}
	}
	sort.Slice(cands, func(i, j int) bool {
		a, b := cands[i], cands[j]
		less := a.ValidNS < b.ValidNS || (a.ValidNS == b.ValidNS && a.Seq < b.Seq)
		if order == OrderDesc {
			return !less && (a.ValidNS != b.ValidNS || a.Seq != b.Seq)
		}
		return less
	})
	// The entity-kind filter needs the decoded event.
	var loaded map[uint64]ChangeView
	if f.EntityKind != "" {
		loaded = make(map[uint64]ChangeView, len(cands))
		kept := cands[:0]
		for _, cd := range cands {
			cv, err := c.loadChange(v, cd.Seq)
			if err != nil {
				return Page[ChangeView]{}, err
			}
			if matchesEntityKind(cv, f) {
				loaded[cd.Seq] = cv
				kept = append(kept, cd)
			}
		}
		cands = kept
	}
	start := 0
	if cursor != "" {
		start = sort.Search(len(cands), func(i int) bool {
			k := changeKey{cands[i].ValidNS, cands[i].Seq}
			after2 := k.valid > after.valid || (k.valid == after.valid && k.seq > after.seq)
			if order == OrderDesc {
				return k.valid < after.valid || (k.valid == after.valid && k.seq < after.seq)
			}
			return after2
		})
	}
	end := min(start+limit, len(cands))
	pg := Page[ChangeView]{Items: make([]ChangeView, 0, end-start), Total: len(cands), Limit: limit}
	for _, cd := range cands[start:end] {
		cv, ok := loaded[cd.Seq]
		if !ok {
			var err error
			if cv, err = c.loadChange(v, cd.Seq); err != nil {
				return Page[ChangeView]{}, err
			}
		}
		pg.Items = append(pg.Items, cv)
	}
	if end < len(cands) {
		last := cands[end-1]
		pg.Truncated = true
		pg.NextCursor = query.EncodeCursor(kind, qh, encodeChangeKey(last.ValidNS, last.Seq))
	}
	return pg, nil
}
