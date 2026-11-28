package lifecycle

import (
	"context"
	"reflect"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/audit"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker"
)

// Feature: github-app-signin, Property 28: A failed reconnect changes nothing
// **Validates: Requirements 9.8**
func TestPropertyFailedReconnectChangesNothing(t *testing.T) {
	kinds := []string{"401", "403", "429", "network", "timeout", "expired", "excess", "audit", "empty"}
	rapid.Check(t, func(rt *rapid.T) {
		kind := rapid.SampledFrom(kinds).Draw(rt, "failure")
		f := newMgrFix(t)
		ctx := context.Background()
		oldSecret := "secret-token-old-" + rapid.StringMatching(`[a-z0-9]{6,12}`).Draw(rt, "old")
		newSecret := "secret-token-new-" + rapid.StringMatching(`[a-z0-9]{6,12}`).Draw(rt, "new")
		c := f.create(t, "alias-"+rapid.StringMatching(`[a-z0-9]{4,8}`).Draw(rt, "alias"), oldSecret)
		if _, err := f.m.transition(ctx, c.ID, StatusExpired, "401", false); err != nil {
			rt.Fatalf("setup transition: %v", err)
		}
		before, _ := f.st.Connection(c.ID)
		successBefore := successConnects(f.a)

		in := CredentialInput{Secret: []byte(newSecret), ExpiresAt: time.Now().Add(time.Hour).UTC()}
		verifyErr := map[string]error{
			"401":     NewError(CodeInvalidCredential, "unauthorized", nil),
			"403":     NewError(CodeInsufficientPermission, "forbidden", nil),
			"429":     &broker.RateLimitedError{},
			"network": &broker.NetworkError{},
			"timeout": context.DeadlineExceeded,
			"expired": NewError(CodeExpired, "expired", nil),
		}[kind]
		if verifyErr != nil {
			f.p.verify = func(s string) (Identity, error) {
				if s == newSecret {
					return Identity{}, verifyErr
				}
				return Identity{AccountLabel: "acct-1"}, nil
			}
		}
		switch kind {
		case "excess":
			f.p.perms = func(string) (PermissionReport, error) {
				return PermissionReport{WriteOffenders: []string{"write"}}, nil
			}
		case "audit":
			f.a.fail = true
		case "empty":
			in.Secret = nil
		}

		err := f.m.ReconnectVerified(ctx, c.ID, in)
		if err == nil {
			rt.Fatalf("%s: reconnect succeeded, want failure", kind)
		}

		after, ok := f.st.Connection(c.ID)
		if !ok {
			rt.Fatalf("%s: connection missing", kind)
		}
		if !reflect.DeepEqual(before, after) {
			rt.Fatalf("%s: connection changed\nbefore %+v\nafter  %+v", kind, before, after)
		}
		if after.Status != string(StatusExpired) {
			rt.Fatalf("%s: status = %s, want EXPIRED", kind, after.Status)
		}
		if held, ok := f.v.get(credRef(c.ID)); !ok || held != oldSecret {
			rt.Fatalf("%s: stored token = %q (present %v), want old token", kind, held, ok)
		}
		if _, left := f.v.get(candRef(c.ID)); left {
			rt.Fatalf("%s: candidate left behind", kind)
		}
		if successConnects(f.a) != successBefore {
			rt.Fatalf("%s: success audit recorded for a failed reconnect", kind)
		}
	})
}

func successConnects(a *mgrAudit) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, e := range a.entries {
		if e.Event == audit.EventConnect && e.Outcome == audit.OutcomeSuccess {
			n++
		}
	}
	return n
}
