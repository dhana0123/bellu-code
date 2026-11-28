package lifecycle

import (
	"context"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// Feature: github-app-signin, Property 27: Reconnect preserves identity
// Validates: Requirements 9.5
func TestPropertyReconnectVerifiedPreservesIdentity(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		f := newMgrFix(t)
		ctx := context.Background()
		alias := "alias-" + rapid.StringMatching(`[a-z0-9]{4,10}`).Draw(rt, "alias")
		c := f.create(t, alias, "secret-token-old-"+rapid.StringMatching(`[a-z0-9]{6}`).Draw(rt, "old"))
		from := rapid.SampledFrom([]Status{StatusExpired}).Draw(rt, "from")
		if _, err := f.m.transition(ctx, c.ID, from, "401", false); err != nil {
			rt.Fatalf("setup transition: %v", err)
		}
		before, _ := f.st.Connection(c.ID)

		newSecret := "secret-token-new-" + rapid.StringMatching(`[a-z0-9]{6,12}`).Draw(rt, "new")
		exp := time.Now().Add(time.Duration(rapid.IntRange(1, 1000).Draw(rt, "hours")) * time.Hour).UTC()
		if err := f.m.ReconnectVerified(ctx, c.ID, CredentialInput{Secret: []byte(newSecret), ExpiresAt: exp}); err != nil {
			rt.Fatalf("ReconnectVerified: %v", err)
		}

		got, ok := f.st.Connection(c.ID)
		if !ok {
			rt.Fatal("connection missing after reconnect")
		}
		if got.ID != before.ID || got.Alias != before.Alias || got.ConnectorID != before.ConnectorID ||
			got.AuthConfigID != before.AuthConfigID || got.CreatedAt != before.CreatedAt {
			rt.Fatalf("identity changed: before %+v after %+v", before, got)
		}
		if got.Method != MethodDevice {
			rt.Fatalf("method = %q, want %q", got.Method, MethodDevice)
		}
		if got.Status != string(StatusActive) {
			rt.Fatalf("status = %q, want ACTIVE", got.Status)
		}
		if held, _ := f.v.get(credRef(c.ID)); held != newSecret {
			rt.Fatalf("stored token %q, want replaced with new token", held)
		}
		if _, left := f.v.get(candRef(c.ID)); left {
			rt.Fatal("candidate left behind")
		}
	})
}
