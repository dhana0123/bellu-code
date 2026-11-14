package azure

import (
	"context"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/lifecycle"
)

// Subscription is one selectable subscription.
type Subscription struct{ ID, Name string }

// Subscriptions lists the subscriptions visible to the credential, for the scope step.
func (p *Provider) Subscriptions(ctx context.Context, c lifecycle.Call) ([]Subscription, error) {
	subs, err := p.subscriptions(ctx, c.Client)
	if err != nil {
		return nil, mapError(err)
	}
	out := make([]Subscription, 0, len(subs))
	for _, s := range subs {
		if s.ID != "" {
			out = append(out, Subscription{ID: s.ID, Name: s.DisplayName})
		}
	}
	return out, nil
}
