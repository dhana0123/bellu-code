package lens

import (
	"context"
	"sync"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/facade"
)

// Service owns a lens Engine whose graph is bound after the graph opens, so
// it can be created before graph.Open and handed to Config.MCPExtras.
type Service struct {
	mu  sync.RWMutex
	eng *Engine
}

// NewService returns an unbound Service. Until Bind succeeds every slice
// request returns ErrUnavailable.
func NewService() *Service { return &Service{} }

// Bind attaches the graph engine. It returns ErrUnavailable and leaves the
// service unbound when eng lacks facade.Extended.
func (s *Service) Bind(eng facade.Engine) error {
	src, err := NewSource(eng)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.eng = nil
		return err
	}
	s.eng = NewEngine(src)
	return nil
}

// Catalog lists the lens definitions. It does not need the graph.
func (s *Service) Catalog() []Def { return Catalog() }

// Slice builds a slice for lens id. An empty id selects DefaultLens.
func (s *Service) Slice(ctx context.Context, id string, p Params) (Slice, error) {
	if id == "" {
		id = DefaultLens
	}
	if _, ok := lookup(id); !ok {
		return Slice{}, ErrUnknownLens{ID: id}
	}
	s.mu.RLock()
	eng := s.eng
	s.mu.RUnlock()
	if eng == nil {
		return Slice{}, ErrUnavailable
	}
	return eng.Slice(ctx, id, p)
}

// Exposed answers exposed_resources.
func (s *Service) Exposed(ctx context.Context, p Params) (Slice, error) {
	s.mu.RLock()
	eng := s.eng
	s.mu.RUnlock()
	if eng == nil {
		return Slice{}, ErrUnavailable
	}
	return eng.Exposed(ctx, p)
}
