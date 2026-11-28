package lens

import (
	"context"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/facade"
)

// ErrUnavailable is returned when the engine is missing or lacks the
// extended query surface.
var ErrUnavailable = facade.ErrUnavailable

// Source is the read-only view of the graph a lens needs. It has no write
// method.
type Source interface {
	Find(ctx context.Context, q facade.FindQuery) (facade.Page[facade.Entity], error)
	Entity(ctx context.Context, id facade.EntityID) (facade.Entity, error)
	Neighbors(ctx context.Context, id facade.EntityID, o facade.NeighborOpts) (facade.Page[facade.Edge], error)
	Resolve(ctx context.Context, ref string) (facade.EntityID, error)
	Path(ctx context.Context, from, to string, o facade.PathOpts) (facade.PathResult, error)
	Impact(ctx context.Context, ref string, o facade.ImpactOpts) (facade.ImpactResult, error)
}

// facadeSource adapts facade.Engine. The Extended assertion happens once, in
// NewSource.
type facadeSource struct {
	q facade.Query
	x facade.Extended
}

// NewSource wraps eng. It returns ErrUnavailable when eng is nil or does not
// implement facade.Extended.
func NewSource(eng facade.Engine) (Source, error) {
	if eng == nil {
		return nil, ErrUnavailable
	}
	x, ok := facade.ExtendedOf(eng)
	if !ok {
		return nil, ErrUnavailable
	}
	return &facadeSource{q: eng.Query(), x: x}, nil
}

func (s *facadeSource) Find(ctx context.Context, q facade.FindQuery) (facade.Page[facade.Entity], error) {
	return s.q.Find(ctx, q)
}

func (s *facadeSource) Entity(ctx context.Context, id facade.EntityID) (facade.Entity, error) {
	return s.q.Entity(ctx, id, nil)
}

func (s *facadeSource) Neighbors(ctx context.Context, id facade.EntityID, o facade.NeighborOpts) (facade.Page[facade.Edge], error) {
	return s.q.Neighbors(ctx, id, o)
}

func (s *facadeSource) Resolve(ctx context.Context, ref string) (facade.EntityID, error) {
	return s.x.Resolve(ctx, ref)
}

func (s *facadeSource) Path(ctx context.Context, from, to string, o facade.PathOpts) (facade.PathResult, error) {
	return s.x.Path(ctx, from, to, o)
}

func (s *facadeSource) Impact(ctx context.Context, ref string, o facade.ImpactOpts) (facade.ImpactResult, error) {
	return s.x.Impact(ctx, ref, o)
}
