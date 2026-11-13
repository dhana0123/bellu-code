package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker"
)

// Feature: cloud-connectors, Property 34: Typed verification errors
// **Validates: Requirements 10.1**
func TestPropertyTypedVerificationErrors(t *testing.T) {
	secretGen := rapid.StringMatching(`tok_[a-z0-9]{16,40}`)
	kinds := []string{"typed", "typedWrapped", "network", "rate", "deadline", "canceled", "plain", "excess", "permNetwork"}
	rapid.Check(t, func(rt *rapid.T) {
		secret := secretGen.Draw(rt, "secret")
		kind := rapid.SampledFrom(kinds).Draw(rt, "kind")
		code := rapid.SampledFrom(VerificationCodes).Draw(rt, "code")
		pad := rapid.StringN(0, 400, -1).Draw(rt, "pad")
		msg := pad + " " + secret + " " + pad
		useTest := rapid.Bool().Draw(rt, "useTest")

		f := newMgrFix(t)
		c := f.create(t, "a", secret)
		before, _ := f.st.Connection(c.ID)

		provErr := func() error {
			switch kind {
			case "typed":
				return NewError(code, msg, nil)
			case "typedWrapped":
				return fmt.Errorf("wrap: %w", NewError(code, msg, nil))
			case "network":
				return &broker.NetworkError{}
			case "rate":
				return &broker.RateLimitedError{}
			case "deadline":
				return fmt.Errorf("%s: %w", msg, context.DeadlineExceeded)
			case "canceled":
				return fmt.Errorf("%s: %w", msg, context.Canceled)
			case "plain":
				return errors.New(msg)
			}
			return nil
		}
		switch kind {
		case "excess":
			f.p.perms = func(string) (PermissionReport, error) {
				return PermissionReport{WriteOffenders: []string{pad + secret, "x:Write"}}, nil
			}
		case "permNetwork":
			f.p.perms = func(string) (PermissionReport, error) { return PermissionReport{}, &broker.NetworkError{} }
		default:
			f.p.verify = func(string) (Identity, error) { return Identity{}, provErr() }
		}

		var err error
		if useTest {
			_, err = f.m.Test(context.Background(), c.ID)
		} else {
			// A new connection whose verification fails.
			_, err = f.m.Create(context.Background(), CreateInput{
				ConnectorID: "ex", Alias: "b", Credential: CredentialInput{Secret: []byte(secret)},
			})
		}

		var te *Error
		if !errors.As(err, &te) {
			rt.Fatalf("want *Error, got %T %v", err, err)
		}
		if !IsVerificationCode(te.Code) {
			rt.Fatalf("code %s is not a verification code", te.Code)
		}
		if n := utf8.RuneCountInString(te.Message); n > MaxMessage {
			rt.Fatalf("message length %d > %d", n, MaxMessage)
		}
		if strings.Contains(te.Message, secret) || strings.Contains(err.Error(), secret) {
			rt.Fatalf("credential leaked in error: %q", te.Message)
		}
		for _, o := range te.Offenders {
			if strings.Contains(o, secret) || utf8.RuneCountInString(o) > MaxMessage {
				rt.Fatalf("offender leaked or too long: %q", o)
			}
		}
		for _, k := range f.st.Snapshot().Connections {
			if strings.Contains(k.StatusReason, secret) {
				rt.Fatalf("status reason leaked credential")
			}
		}
		if useTest {
			after, _ := f.st.Connection(c.ID)
			if after.Status != before.Status || after.StatusReason != before.StatusReason ||
				after.PermissionCheck != before.PermissionCheck {
				rt.Fatalf("connection changed: %+v -> %+v", before, after)
			}
			if s, _ := f.v.get(credRef(c.ID)); s != secret {
				rt.Fatalf("stored credential changed")
			}
		}
	})
}
