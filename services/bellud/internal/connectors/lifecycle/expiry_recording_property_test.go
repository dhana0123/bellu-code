package lifecycle

import (
	"context"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
	"pgregory.net/rapid"
)

// Feature: github-app-signin, Property 25: Expiry is recorded exactly when GitHub sends one
// Validates: Requirements 9.2
//
// The deviceflow Service that turns a token response's expires_in into
// CredentialInput.ExpiresAt does not exist yet, so this test covers the
// lifecycle-level half: the receipt time plus expires_in (or the zero time when
// GitHub sent none) is recorded as CredentialExpiresAt exactly when non-zero.
func TestPropertyExpiryRecordedExactlyWhenSent(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		f := newMgrFix(t)
		ctx := context.Background()

		// expires_in of 0 stands for an absent field.
		expiresIn := rapid.Int64Range(0, 10*365*24*3600).Draw(rt, "expiresIn")
		var exp time.Time
		if expiresIn > 0 {
			receipt := time.Now().UTC().Truncate(time.Second)
			exp = receipt.Add(time.Duration(expiresIn) * time.Second)
		}
		in := CredentialInput{Secret: []byte("secret-token-exp-0001"), ExpiresAt: exp}

		check := func(where string, id string) {
			got, ok := f.st.Connection(id)
			if !ok {
				rt.Fatalf("%s: connection missing", where)
			}
			if exp.IsZero() {
				if got.CredentialExpiresAt != nil {
					rt.Fatalf("%s: expiry %v recorded without expires_in", where, got.CredentialExpiresAt)
				}
				return
			}
			if got.CredentialExpiresAt == nil || !got.CredentialExpiresAt.Equal(exp) {
				rt.Fatalf("%s: expiry = %v, want %v", where, got.CredentialExpiresAt, exp)
			}
		}

		c, err := f.m.Create(ctx, CreateInput{ConnectorID: "ex", Alias: "a", Method: MethodDevice, Credential: in})
		if err != nil {
			rt.Fatalf("create: %v", err)
		}
		check("create", c.ID)

		// ReconnectVerified starts from an EXPIRED connection and must replace the
		// previous expiry with the new response's (or clear it when none is sent).
		if _, err := f.m.transition(ctx, c.ID, StatusExpired, "401", false); err != nil {
			rt.Fatalf("transition: %v", err)
		}
		later := time.Now().UTC().Add(72 * time.Hour).Truncate(time.Second)
		if exp.IsZero() {
			// Seed a stale expiry so clearing is observable.
			if err := f.st.UpdateConnection(c.ID, func(x *store.Connection) error { x.CredentialExpiresAt = &later; return nil }); err != nil {
				rt.Fatalf("seed: %v", err)
			}
		}
		if err := f.m.ReconnectVerified(ctx, c.ID, in); err != nil {
			rt.Fatalf("reconnect: %v", err)
		}
		check("reconnect", c.ID)
	})
}
