package lifecycle

import (
	"context"
	"testing"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker"
)

// Feature: github-app-signin, Property 19: A failed verification leaves no token
// **Validates: Requirements 6.4, 6.5**
func TestPropertyDeviceFailedVerificationLeavesNoToken(t *testing.T) {
	type failure struct {
		err  error
		want Code
	}
	failures := map[string]failure{
		"401":     {NewError(CodeInvalidCredential, "unauthorized", nil), CodeInvalidCredential},
		"403":     {NewError(CodeInsufficientPermission, "forbidden", nil), CodeInsufficientPermission},
		"429":     {&broker.RateLimitedError{}, CodeRateLimited},
		"5xx":     {NewError(CodeNetwork, "server error", nil), CodeNetwork},
		"network": {&broker.NetworkError{}, CodeNetwork},
		"timeout": {context.DeadlineExceeded, CodeNetwork},
		"expired": {NewError(CodeExpired, "expired", nil), CodeExpired},
		"excess":  {NewError(CodeExcessPermission, "excess", nil), CodeExcessPermission},
	}
	names := make([]string, 0, len(failures))
	for k := range failures {
		names = append(names, k)
	}
	secretGen := rapid.StringMatching(`tok_[a-z0-9]{16,40}`)
	rapid.Check(t, func(rt *rapid.T) {
		kind := rapid.SampledFrom(names).Draw(rt, "failure")
		secret := secretGen.Draw(rt, "secret")
		fl := failures[kind]

		f := newMgrFix(t)
		calls := 0
		f.p.verify = func(s string) (Identity, error) {
			calls++
			if s != secret {
				rt.Fatalf("verified %q, want the submitted token", s)
			}
			return Identity{}, fl.err
		}
		c, err := f.createMethod(t, "a", secret, MethodDevice)
		if got := codeOf(t, err); got != fl.want {
			rt.Fatalf("%s: code = %s, want %s", kind, got, fl.want)
		}
		if c.Status != string(StatusError) {
			rt.Fatalf("%s: status = %s", kind, c.Status)
		}
		if st, _ := f.st.Connection(c.ID); st.Status != string(StatusError) {
			rt.Fatalf("%s: stored status = %s", kind, st.Status)
		}
		if _, ok := f.v.get(credRef(c.ID)); ok {
			rt.Fatalf("%s: token still in vault", kind)
		}
		if _, ok := f.v.get(candRef(c.ID)); ok {
			rt.Fatalf("%s: candidate token still in vault", kind)
		}
		if calls != 1 {
			rt.Fatalf("%s: verification attempts = %d, want 1", kind, calls)
		}
	})
}
