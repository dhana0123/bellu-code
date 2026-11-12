package engine

import (
	"context"
	"fmt"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/resolve"
)

// Dependents returns, sorted, the entities whose depends_on endpoints resolve
// to the live listening port or process id (Endpoint_Resolution, read time).
func (c *Core) Dependents(ctx context.Context, id EntityID) ([]EntityID, error) {
	done, err := c.begin(ctx, "dependents")
	if err != nil {
		return nil, err
	}
	defer done()
	c.mu.RLock()
	defer c.mu.RUnlock()
	if e, ok := c.g.Entity(id); !ok || !e.Live {
		return nil, fmt.Errorf("%w: entity %s", errs.NotFound, id)
	}
	return resolve.Dependents(c.g, id), nil
}
