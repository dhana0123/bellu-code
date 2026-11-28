package kubernetes

import (
	"context"
	"net/http"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/lifecycle"
)

// Namespaces lists the namespace names the token can read, for the scope step.
func (p *Provider) Namespaces(ctx context.Context, c lifecycle.Call) ([]string, error) {
	var out struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := p.do(ctx, c, http.MethodGet, "/api/v1/namespaces", nil, &out); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(out.Items))
	for _, i := range out.Items {
		if i.Metadata.Name != "" {
			names = append(names, i.Metadata.Name)
		}
	}
	return names, nil
}
