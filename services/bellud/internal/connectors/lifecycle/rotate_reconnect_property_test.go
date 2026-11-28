package lifecycle

import (
	"context"
	"errors"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/vault"
	"pgregory.net/rapid"
)

// Feature: cloud-connectors, Property 35: Rotation and reconnect outcomes
// Validates: Requirements 9.8, 9.9, 14.4, 14.5
func TestPropertyRotationAndReconnectOutcomes(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		f := newMgrFix(t)
		ctx := context.Background()
		oldSecret := "secret-token-old-" + rapid.StringMatching(`[a-z0-9]{6}`).Draw(rt, "old")
		c := f.create(t, "alias-"+rapid.StringMatching(`[a-z]{4}`).Draw(rt, "alias"), oldSecret)

		const candSecret = "secret-token-candidate-zz"
		idOK := rapid.Bool().Draw(rt, "identityOK")
		var permWrites []string
		if rapid.Bool().Draw(rt, "hasWrites") {
			permWrites = rapid.SliceOfN(rapid.StringMatching(`[a-z]{3,8}:[A-Z][a-z]{3,8}`), 1, 3).Draw(rt, "writes")
		}
		permErr := rapid.Bool().Draw(rt, "permCheckErrors")
		unverifiable := rapid.Bool().Draw(rt, "unverifiable")
		f.p.verify = func(s string) (Identity, error) {
			if s == candSecret && !idOK {
				return Identity{}, NewError(CodeInvalidCredential, "bad", nil)
			}
			return Identity{AccountLabel: "acct-1"}, nil
		}
		f.p.perms = func(s string) (PermissionReport, error) {
			if s != candSecret {
				return PermissionReport{}, nil
			}
			if permErr {
				return PermissionReport{}, errors.New("boom")
			}
			return PermissionReport{WriteOffenders: permWrites, Unverifiable: unverifiable}, nil
		}
		pass := idOK && !permErr && len(permWrites) == 0

		reconnect := rapid.Bool().Draw(rt, "reconnect")
		var err error
		if reconnect {
			to := rapid.SampledFrom([]Status{StatusError, StatusExpired}).Draw(rt, "from")
			if _, terr := f.m.transition(ctx, c.ID, to, "x", false); terr != nil {
				rt.Fatalf("setup transition: %v", terr)
			}
			err = f.m.Reconnect(ctx, c.ID, CredentialInput{Secret: []byte(candSecret)})
		} else {
			err = f.m.Rotate(ctx, c.ID, CredentialInput{Secret: []byte(candSecret)})
		}

		held, _ := f.v.get(credRef(c.ID))
		if pass {
			if err != nil {
				rt.Fatalf("both checks pass but got error: %v", err)
			}
			if held != candSecret {
				rt.Fatalf("vault holds %q, want candidate", held)
			}
		} else {
			if err == nil {
				rt.Fatal("a check failed but no error returned")
			}
			if held != oldSecret {
				rt.Fatalf("vault holds %q, want old credential", held)
			}
		}
		if _, ok := f.v.get(vault.Ref(candRef(c.ID))); ok {
			rt.Fatal("candidate slot not discarded")
		}

		got, ok := f.st.Connection(c.ID)
		if !ok {
			rt.Fatal("connection missing")
		}
		if got.ID != c.ID || got.Alias != c.Alias || got.ConnectorID != c.ConnectorID ||
			got.Method != c.Method || got.AuthConfigID != c.AuthConfigID ||
			CollectorName(got.ConnectorID, got.ID) != CollectorName(c.ConnectorID, c.ID) {
			rt.Fatalf("identity changed: before %+v after %+v", c, got)
		}
		if n := len(f.st.Snapshot().Connections); n != 1 {
			rt.Fatalf("connection count = %d", n)
		}
	})
}
