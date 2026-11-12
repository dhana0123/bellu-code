//go:build !linux

package host

import (
	"context"

	"github.com/bellu/bellucode/services/bellud/internal/graph"
)

// Collect returns an empty batch: the host collector only observes Linux.
func (c *Collector) Collect(context.Context) (graph.Batch, error) {
	return graph.Batch{Collector: Name}, nil
}
