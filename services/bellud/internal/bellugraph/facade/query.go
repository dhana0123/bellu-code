package facade

import (
	"context"
	"fmt"
	"math"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/model"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/projection"
)

// The engine keys entities by ULID; the facade's Entity_ID is the engine
// identity fingerprint ("kind:hex"), which is stable across restarts and
// derivable by collectors. Reads translate between the two.

func (e *engine) ready() error {
	if k := e.State().Kind; k != StateReady {
		return fmt.Errorf("%w: %s", ErrUnavailable, k)
	}
	return nil
}

// Entity returns the entity state. With at == nil it is the current state.
// With at it is the state folded, in log order, from every event with
// observed_at <= at (inclusive), by the engine's as-of fold; an instant before
// the entity's first event, a deleted entity or an unknown ID is ErrNotFound.
// The fold reads the log directly, so the result does not depend on snapshots.
func (e *engine) Entity(ctx context.Context, id EntityID, at *time.Time) (Entity, error) {
	if err := e.ready(); err != nil {
		return Entity{}, err
	}
	g := e.stack.Graph
	var upTo *time.Time
	if at != nil {
		t := at.UTC()
		upTo = &t
		var err error
		if g, err = projection.At(ctx, e.stack.Store, t); err != nil {
			return Entity{}, err
		}
	}
	ent, ok := liveEntity(g, id)
	if !ok {
		return Entity{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return e.view(ctx, ent, upTo)
}

func liveEntity(g *projection.Graph, id EntityID) (model.Entity, bool) {
	ulid, ok := g.ResolveFingerprint(string(id))
	if !ok {
		return model.Entity{}, false
	}
	ent, ok, deleted := g.GetEntity(ulid)
	return ent, ok && !deleted
}

func (e *engine) view(ctx context.Context, ent model.Entity, upTo *time.Time) (Entity, error) {
	obs, rec, err := e.lastTimes(ctx, ent.ID, upTo)
	if err != nil {
		return Entity{}, err
	}
	return render(ent, obs, rec), nil
}

func render(ent model.Entity, obs, rec time.Time) Entity {
	attrs := kvMap(ent.Attributes)
	for k, v := range kvMap(ent.Identity) {
		attrs[k] = v
	}
	return Entity{
		ID: EntityID(ent.IdentityHash()), Type: ent.Type, Label: model.DisplayName(ent),
		Attributes: attrs, ObservedAt: obs.UTC(), RecordedAt: rec.UTC(),
	}
}

// lastTimes returns the bi-temporal pair of the latest entity event of ulid
// with observed_at <= upTo (any when nil).
func (e *engine) lastTimes(ctx context.Context, ulid model.EntityID, upTo *time.Time) (obs, rec time.Time, err error) {
	evs, err := e.stack.Store.ReadByEntity(ctx, ulid)
	if err != nil {
		return obs, rec, err
	}
	for _, ev := range evs {
		if ev.Entity == nil || (upTo != nil && ev.Entity.EventTime.After(*upTo)) {
			continue
		}
		if !ev.Entity.EventTime.Before(obs) {
			obs, rec = ev.Entity.EventTime, ev.Entity.RecordedAt
		}
	}
	return obs, rec, nil
}

// Find pages the live entities matching q, ordered by Entity_ID. Cursor is the
// last Entity_ID of the previous page.
func (e *engine) Find(ctx context.Context, q FindQuery) (Page[Entity], error) {
	if err := e.ready(); err != nil {
		return Page[Entity]{}, err
	}
	limit, err := q.normalize()
	if err != nil {
		return Page[Entity]{}, err
	}
	type hit struct {
		fp  string
		ent model.Entity
	}
	var hits []hit
	for _, ent := range e.stack.Graph.ListEntities(q.Type) {
		if ent.MatchAll(q.Attributes) {
			hits = append(hits, hit{ent.IdentityHash(), ent})
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].fp < hits[j].fp })
	pg := Page[Entity]{Items: []Entity{}, Total: len(hits), Limit: limit}
	start := sort.Search(len(hits), func(i int) bool { return hits[i].fp > q.Cursor })
	end := min(start+limit, len(hits))
	for _, h := range hits[start:end] {
		v, err := e.view(ctx, h.ent, nil)
		if err != nil {
			return Page[Entity]{}, err
		}
		pg.Items = append(pg.Items, v)
	}
	if end < len(hits) {
		pg.Truncated = true
		pg.NextCursor = hits[end-1].fp
	}
	return pg, nil
}

// Neighbors traverses relations from id up to opt.Depth hops and returns each
// reached relation once, at its fewest hops, ordered by hops, type and ends.
func (e *engine) Neighbors(_ context.Context, id EntityID, opt NeighborOpts) (Page[Edge], error) {
	if err := e.ready(); err != nil {
		return Page[Edge]{}, err
	}
	if _, err := opt.normalize(); err != nil {
		return Page[Edge]{}, err
	}
	depth, dir := opt.Depth, opt.Direction
	if depth == 0 {
		depth = 1
	}
	if dir == "" {
		dir = DirBoth
	}
	if depth < 1 || depth > MaxNeighborDepth {
		return Page[Edge]{}, fmt.Errorf("%w: depth %d is outside 1 to %d", ErrValidation, depth, MaxNeighborDepth)
	}
	if dir != DirOut && dir != DirIn && dir != DirBoth {
		return Page[Edge]{}, fmt.Errorf("%w: direction %q must be out, in or both", ErrValidation, dir)
	}
	g := e.stack.Graph
	root, ok := liveEntity(g, id)
	if !ok {
		return Page[Edge]{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	fp := func(ulid model.EntityID) (string, bool) {
		ent, ok, deleted := g.GetEntity(ulid)
		return ent.IdentityHash(), ok && !deleted
	}
	var edges []Edge
	seenRel := map[model.RelationID]struct{}{}
	seenEnt := map[model.EntityID]struct{}{root.ID: {}}
	frontier := []model.EntityID{root.ID}
	for hop := 1; hop <= depth && len(frontier) > 0; hop++ {
		var next []model.EntityID
		for _, cur := range frontier {
			for _, rel := range g.RelationsTouching(cur, opt.RelationType) {
				if _, dup := seenRel[rel.ID]; dup {
					continue
				}
				step, far := DirOut, rel.To
				if rel.From != cur {
					step, far = DirIn, rel.From
				}
				if dir != DirBoth && dir != step {
					continue
				}
				ff, ok1 := fp(rel.From)
				tf, ok2 := fp(rel.To)
				if !ok1 || !ok2 {
					continue
				}
				seenRel[rel.ID] = struct{}{}
				edges = append(edges, Edge{From: EntityID(ff), To: EntityID(tf), Type: rel.Type, Direction: step, Hops: hop})
				if _, seen := seenEnt[far]; !seen {
					seenEnt[far] = struct{}{}
					next = append(next, far)
				}
			}
		}
		frontier = next
	}
	sort.Slice(edges, func(i, j int) bool {
		a, b := edges[i], edges[j]
		if a.Hops != b.Hops {
			return a.Hops < b.Hops
		}
		return strings.Join([]string{a.Type, string(a.From), string(a.To)}, "\x00") <
			strings.Join([]string{b.Type, string(b.From), string(b.To)}, "\x00")
	})
	return paginate(edges, opt.Paging)
}

// History lists the entity's changes (its own events and events of relations
// touching it) within r, oldest first. Unchanged heartbeats are not changes.
// A deleted entity keeps its history while the engine retains tombstones or
// the log; an ID the log never saw is ErrNotFound.
func (e *engine) History(ctx context.Context, id EntityID, r TimeRange, p Paging) (Page[Change], error) {
	if err := e.ready(); err != nil {
		return Page[Change]{}, err
	}
	if _, err := p.normalize(); err != nil {
		return Page[Change]{}, err
	}
	if err := r.validate(); err != nil {
		return Page[Change]{}, err
	}
	ulid, ok, err := e.ulidOf(id)
	if err != nil {
		return Page[Change]{}, err
	}
	if !ok {
		return Page[Change]{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	evs, err := e.stack.Store.ReadByEntity(ctx, ulid)
	if err != nil {
		return Page[Change]{}, err
	}
	if len(evs) == 0 {
		return Page[Change]{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	fp := e.fingerprinter(ctx)
	var out []Change
	for _, ev := range evs {
		if c, ok := classifyEvent(ev, fp); ok && r.contains(c.ObservedAt) {
			out = append(out, c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ObservedAt.Before(out[j].ObservedAt) })
	return paginate(out, p)
}

// Changes lists changes with observed_at in r matching f, oldest first
// (observed_at, then log order).
func (e *engine) Changes(ctx context.Context, r TimeRange, f ChangeFilter) (Page[Change], error) {
	if err := e.ready(); err != nil {
		return Page[Change]{}, err
	}
	if _, err := f.normalize(); err != nil {
		return Page[Change]{}, err
	}
	if err := r.validate(); err != nil {
		return Page[Change]{}, err
	}
	fp := e.fingerprinter(ctx)
	var out []Change
	err := e.stack.Store.ScanByTimeRange(ctx, r.start(), r.end(), func(ev model.Event) error {
		c, ok := classifyEvent(ev, fp)
		if !ok || (f.Kind != "" && c.Kind != f.Kind) || (f.Subject != "" && c.Subject != f.Subject) {
			return nil
		}
		if f.Entity != "" && c.Entity != f.Entity && c.From != f.Entity && c.To != f.Entity {
			return nil
		}
		out = append(out, c)
		return nil
	})
	if err != nil {
		return Page[Change]{}, err
	}
	return paginate(out, f.Paging)
}

// Diff derives added, changed and removed entities between two observed_at
// instants from the full states at each (the engine's as-of fold), not from
// individual events: an entity created and deleted in between appears nowhere.
func (e *engine) Diff(ctx context.Context, from, to time.Time) (Diff, error) {
	if err := e.ready(); err != nil {
		return Diff{}, err
	}
	from, to = from.UTC(), to.UTC()
	if to.Before(from) {
		return Diff{}, fmt.Errorf("%w: diff end %s is before start %s", ErrValidation, to.Format(time.RFC3339), from.Format(time.RFC3339))
	}
	gFrom, err := projection.At(ctx, e.stack.Store, from)
	if err != nil {
		return Diff{}, err
	}
	gTo, err := projection.At(ctx, e.stack.Store, to)
	if err != nil {
		return Diff{}, err
	}
	index := func(g *projection.Graph) map[string]model.Entity {
		m := map[string]model.Entity{}
		for _, ent := range g.ListEntities("") {
			m[ent.IdentityHash()] = ent
		}
		return m
	}
	before, after := index(gFrom), index(gTo)

	d := Diff{From: from, To: to, Added: []Entity{}, Changed: []Entity{}, Removed: []EntityID{}}
	var added, changed []model.Entity
	for fp, ent := range after {
		old, existed := before[fp]
		switch {
		case !existed:
			added = append(added, ent)
		case !reflect.DeepEqual(render(old, time.Time{}, time.Time{}).Attributes, render(ent, time.Time{}, time.Time{}).Attributes):
			changed = append(changed, ent)
		}
	}
	for fp := range before {
		if _, still := after[fp]; !still {
			d.Removed = append(d.Removed, EntityID(fp))
		}
	}
	byID := func(s []model.Entity) {
		sort.Slice(s, func(i, j int) bool { return s[i].IdentityHash() < s[j].IdentityHash() })
	}
	byID(added)
	byID(changed)
	slices.Sort(d.Removed)

	// Times of the latest entity event in (from, to], or of the state at `to`.
	type pair struct{ obs, rec time.Time }
	latest := map[model.EntityID]pair{}
	if err := e.stack.Store.ScanByTimeRange(ctx, from.Add(time.Nanosecond), to.Add(time.Nanosecond), func(ev model.Event) error {
		if ev.Entity != nil {
			latest[ev.Entity.Entity.ID] = pair{ev.Entity.EventTime, ev.Entity.RecordedAt}
		}
		return nil
	}); err != nil {
		return Diff{}, err
	}
	fill := func(src []model.Entity, dst *[]Entity) error {
		if len(src) > MaxPageSize {
			src, d.Truncated = src[:MaxPageSize], true
		}
		for _, ent := range src {
			t, ok := latest[ent.ID]
			if !ok {
				var err error
				if t.obs, t.rec, err = e.lastTimes(ctx, ent.ID, &to); err != nil {
					return err
				}
			}
			*dst = append(*dst, render(ent, t.obs, t.rec))
		}
		return nil
	}
	if err := fill(added, &d.Added); err != nil {
		return Diff{}, err
	}
	if err := fill(changed, &d.Changed); err != nil {
		return Diff{}, err
	}
	if len(d.Removed) > MaxPageSize {
		d.Removed, d.Truncated = d.Removed[:MaxPageSize], true
	}
	return d, nil
}

// ulidOf maps an Entity_ID to the engine's logical ID. It checks the live
// projection and its tombstones first, then falls back to scanning the log.
func (e *engine) ulidOf(id EntityID) (model.EntityID, bool, error) {
	if ulid, ok := e.stack.Graph.ResolveFingerprint(string(id)); ok {
		return ulid, true, nil
	}
	var found model.EntityID
	err := e.stack.Store.Scan(func(_ uint64, ev model.Event) error {
		if ev.Entity != nil && ev.Entity.Entity.IdentityHash() == string(id) {
			found = ev.Entity.Entity.ID
		}
		return nil
	})
	return found, found != "", err
}

// fingerprinter maps engine ULIDs to Entity_IDs for relation events, falling
// back to the log for entities no longer in the projection.
func (e *engine) fingerprinter(ctx context.Context) func(model.EntityID) EntityID {
	cache := map[model.EntityID]EntityID{}
	return func(ulid model.EntityID) EntityID {
		if v, ok := cache[ulid]; ok {
			return v
		}
		out := EntityID(ulid)
		if ent, ok, _ := e.stack.Graph.GetEntity(ulid); ok {
			out = EntityID(ent.IdentityHash())
		} else if evs, err := e.stack.Store.ReadByEntity(ctx, ulid); err == nil {
			for _, ev := range evs {
				if ev.Entity != nil && ev.Entity.Entity.ID == ulid {
					out = EntityID(ev.Entity.Entity.IdentityHash())
					break
				}
			}
		}
		cache[ulid] = out
		return out
	}
}

// classifyEvent maps an engine event to the wire change taxonomy. Heartbeats
// (entity.unchanged) are not changes.
func classifyEvent(ev model.Event, fp func(model.EntityID) EntityID) (Change, bool) {
	if ev.Entity != nil {
		x := ev.Entity
		var kind ChangeKind
		switch x.ChangeType {
		case model.EntityCreated:
			kind = ChangeAdded
		case model.EntityDeleted:
			kind = ChangeRemoved
		case model.EntityAttributeUpdated, model.EntityStateChanged, model.EntityIdentityChanged:
			kind = ChangeChanged
		default:
			return Change{}, false
		}
		return Change{
			Kind: kind, Subject: SubjectEntity, Entity: EntityID(x.Entity.IdentityHash()),
			ObservedAt: x.EventTime.UTC(), RecordedAt: x.RecordedAt.UTC(),
		}, true
	}
	if ev.Relation == nil {
		return Change{}, false
	}
	x := ev.Relation
	var kind ChangeKind
	switch x.ChangeType {
	case model.RelationAdded:
		kind = ChangeAdded
	case model.RelationRemoved:
		kind = ChangeRemoved
	case model.RelationAttributeChanged:
		kind = ChangeChanged
	default:
		return Change{}, false
	}
	return Change{
		Kind: kind, Subject: SubjectRelation, From: fp(x.Relation.From), To: fp(x.Relation.To),
		RelationType: x.Relation.Type, ObservedAt: x.EventTime.UTC(), RecordedAt: x.RecordedAt.UTC(),
	}, true
}

// --- validation helpers ---

func (r TimeRange) validate() error {
	if !r.From.IsZero() && !r.To.IsZero() && r.To.Before(r.From) {
		return fmt.Errorf("%w: range end %s is before start %s", ErrValidation, r.To.Format(time.RFC3339), r.From.Format(time.RFC3339))
	}
	return nil
}

func (r TimeRange) contains(t time.Time) bool {
	return (r.From.IsZero() || !t.Before(r.From)) && (r.To.IsZero() || !t.After(r.To))
}

func (r TimeRange) start() time.Time {
	if r.From.IsZero() {
		return time.Unix(0, 0)
	}
	return r.From
}

// end is exclusive for the store scan, so it adds a nanosecond to include To.
func (r TimeRange) end() time.Time {
	if r.To.IsZero() {
		return time.Unix(0, math.MaxInt64)
	}
	return r.To.Add(time.Nanosecond)
}
