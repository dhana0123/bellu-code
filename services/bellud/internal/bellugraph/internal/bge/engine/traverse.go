package engine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/query"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/resolve"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/uri"
)

// Traversal defaults.
const (
	DefaultPathDepth   = 6
	DefaultImpactDepth = 3
)

// PathOpts bound a Path search. Zero MaxDepth means DefaultPathDepth. Endpoint
// resolution (derived resolves_to relations) is included unless StoredOnly.
type PathOpts struct {
	MaxDepth   int
	StoredOnly bool
	// At, when set, folds the state as of that Valid_Time instant and
	// traverses that state instead of the live Projection.
	At *time.Time
}

// PathResult is the outcome of Path. When Connected is false, Exhausted and
// DepthSearched explain the negative and SharedNeighbors/SharedAttributes
// (never secret-named keys) describe what the two ends have in common.
type PathResult struct {
	Connected        bool
	Path             []EdgeView
	Exhausted        bool
	DepthSearched    int
	SharedNeighbors  []EntityID
	SharedAttributes map[string]string
}

// ImpactOpts bound an Impact traversal. Zero Depth means DefaultImpactDepth.
// Endpoint resolution is included unless StoredOnly.
type ImpactOpts struct {
	Depth      int
	StoredOnly bool
	// At, when set, traverses the state as of that Valid_Time instant.
	At *time.Time
}

// ImpactedView is an entity impacted by the start entity, with the fewest
// hops and the relation path (Via) that reaches it.
type ImpactedView struct {
	ID   EntityID
	Kind string
	Hops int
	Via  []EdgeView
}

// ImpactResult lists impacted entities ordered by (hops, ID).
type ImpactResult struct {
	Items []ImpactedView
}

func checkDepth(d, def int) (int, error) {
	if d == 0 {
		return def, nil
	}
	if d < 1 || d > query.MaxDepth {
		return 0, fmt.Errorf("%w: depth %d is outside 1 to %d", errs.Validation, d, query.MaxDepth)
	}
	return d, nil
}

// Path finds a shortest undirected path between a and b by hop count.
func (c *Core) Path(ctx context.Context, a, b EntityID, o PathOpts) (PathResult, error) {
	done, err := c.begin(ctx, "path")
	if err != nil {
		return PathResult{}, err
	}
	defer done()
	depth, err := checkDepth(o.MaxDepth, DefaultPathDepth)
	if err != nil {
		return PathResult{}, err
	}
	g, release, err := c.readGraph(ctx, o.At)
	if err != nil {
		return PathResult{}, err
	}
	defer release()
	for _, id := range []EntityID{a, b} {
		if e, ok := g.Entity(id); !ok || !e.Live {
			return PathResult{}, fmt.Errorf("%w: entity %s", errs.NotFound, id)
		}
	}
	var derived query.DerivedFn
	if !o.StoredOnly {
		derived = resolve.DerivedFn(g)
	}
	r := query.ShortestPath(g, a, b, depth, derived)
	out := PathResult{Connected: r.Found, Exhausted: r.Exhausted, DepthSearched: r.DepthSearched}
	if r.Found {
		out.Path = make([]EdgeView, len(r.Path))
		for i, e := range r.Path {
			out.Path[i] = EdgeView(e)
		}
		return out, nil
	}
	out.SharedNeighbors = query.SharedNeighbors(g, a, b, derived)
	out.SharedAttributes = query.SharedAttributes(g, a, b)
	return out, nil
}

// Impact returns the entities reachable from id by following each relation
// type in its declared Impact_Direction (reverse for undeclared types).
func (c *Core) Impact(ctx context.Context, id EntityID, o ImpactOpts) (ImpactResult, error) {
	done, err := c.begin(ctx, "impact")
	if err != nil {
		return ImpactResult{}, err
	}
	defer done()
	depth, err := checkDepth(o.Depth, DefaultImpactDepth)
	if err != nil {
		return ImpactResult{}, err
	}
	g, release, err := c.readGraph(ctx, o.At)
	if err != nil {
		return ImpactResult{}, err
	}
	defer release()
	if e, ok := g.Entity(id); !ok || !e.Live {
		return ImpactResult{}, fmt.Errorf("%w: entity %s", errs.NotFound, id)
	}
	var derived query.DerivedFn
	if !o.StoredOnly {
		derived = resolve.DerivedFn(g)
	}
	dirOf := func(t string) ident.Direction { d, _ := ident.DirectionOf(t); return d }
	items := query.Impact(g, id, depth, dirOf, derived)
	out := ImpactResult{Items: make([]ImpactedView, len(items))}
	for i, it := range items {
		v := ImpactedView{ID: it.ID, Hops: it.Hops, Via: make([]EdgeView, len(it.Via))}
		if e, ok := g.Entity(it.ID); ok {
			v.Kind = e.Kind
		}
		for j, e := range it.Via {
			v.Via[j] = EdgeView(e)
		}
		out.Items[i] = v
	}
	return out, nil
}

// Resolve turns an entity reference into an Entity_ID. It accepts an
// Entity_ID (returned unchanged), a live Local_ID ("@xxxxxx") and an entity
// URI ("bellugraph://kind/hex"). Unknown or retired Local_IDs wrap
// errs.NotFound; malformed or non-entity URIs wrap errs.Validation.
func (c *Core) Resolve(ref string) (EntityID, error) {
	switch {
	case strings.HasPrefix(ref, "@"):
		return c.ids.Lookup(ref)
	case strings.HasPrefix(ref, "bellugraph://"):
		r, err := uri.Parse(ref)
		if err != nil {
			return "", err
		}
		e, ok := r.(uri.Entity)
		if !ok {
			return "", fmt.Errorf("%w: %q is not an entity uri", errs.Validation, ref)
		}
		return e.Kind + ":" + e.Hex, nil
	}
	return ref, nil
}

// LocalID returns the live Local_ID of id, refreshing it, or mints one. The
// sweep that retires idle aliases is started by Open and stopped by Close.
func (c *Core) LocalID(id EntityID) string { return c.ids.For(id) }
