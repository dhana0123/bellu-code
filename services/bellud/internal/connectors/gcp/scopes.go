package gcp

import (
	"context"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/lifecycle"
)

// ProjectIDs lists the active projects visible to the service account, for the scope step.
func (p *Provider) ProjectIDs(ctx context.Context, c lifecycle.Call) ([]string, error) {
	return p.projects(ctx, c)
}
