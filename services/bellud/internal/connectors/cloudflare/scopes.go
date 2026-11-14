package cloudflare

import (
	"context"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/lifecycle"
)

// Zone is one selectable zone.
type Zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Zones lists the zones the token can read, for the scope step.
func (p *Provider) Zones(ctx context.Context, c lifecycle.Call) ([]Zone, error) {
	var v envelope[[]Zone]
	if err := getJSON(ctx, c.Client, pathZones+"?per_page=50", &v); err != nil {
		return nil, err
	}
	out := make([]Zone, 0, len(v.Result))
	for _, z := range v.Result {
		if z.ID != "" {
			out = append(out, z)
		}
	}
	return out, nil
}
