package proxy

import (
	"context"

	"github.com/bellu/bellucode/services/bellud/internal/tschild"
)

type childKey struct{}

func withChild(ctx context.Context, c *tschild.Child) context.Context {
	return context.WithValue(ctx, childKey{}, c)
}

func childFrom(ctx context.Context) *tschild.Child {
	return ctx.Value(childKey{}).(*tschild.Child)
}
