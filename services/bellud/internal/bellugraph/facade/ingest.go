package facade

import (
	"context"
	"fmt"

	bgeengine "github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/engine"
)

// Apply appends one collector observation as a single atomic log append.
//
// The Batch is a FULL observation of the Collector's scope. Entity_IDs come
// from Hash. Relation From/To are Entity_IDs: each must name an entity in the
// same Batch or one live in the graph. The engine validates everything before
// it appends, so a rejected Batch appends nothing, and it retires entities and
// relations the same Collector asserted earlier and no longer reports (only
// when no other collector still asserts them). observed_at is
// Batch.ObservedAt exactly (now when zero); recorded_at is stamped at append.
func (e *engine) Apply(ctx context.Context, b Batch) (Receipt, error) {
	if err := e.ready(); err != nil {
		return Receipt{}, err
	}
	r, err := e.stack.Apply(ctx, b, bgeengine.ModeFull)
	if err != nil {
		return Receipt{}, err
	}
	return toReceipt(r), nil
}

func (e *engine) ready() error {
	if k := e.State().Kind; k != StateReady {
		return fmt.Errorf("%s: %w: %s", CodeUnavailable, ErrUnavailable, k)
	}
	return nil
}
