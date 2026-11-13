package lifecycle

import (
	"errors"
	"strings"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/redactor"
)

func TestNextTable(t *testing.T) {
	allowed := map[[2]Status]bool{
		{StatusInitiated, StatusVerifying}: true,
		{StatusVerifying, StatusActive}:    true, {StatusVerifying, StatusError}: true,
		{StatusActive, StatusExpired}: true, {StatusActive, StatusPaused}: true, {StatusActive, StatusError}: true,
		{StatusPaused, StatusActive}: true, {StatusPaused, StatusError}: true,
		{StatusExpired, StatusVerifying}: true,
		{StatusError, StatusVerifying}:   true,
	}
	for _, f := range Statuses {
		for _, to := range Statuses {
			err := Next(f, to)
			if allowed[[2]Status{f, to}] {
				if err != nil {
					t.Errorf("%s->%s should be allowed: %v", f, to, err)
				}
			} else if !errors.Is(err, ErrTransition) {
				t.Errorf("%s->%s should be rejected, got %v", f, to, err)
			}
		}
	}
	if !errors.Is(Next("BOGUS", StatusActive), ErrTransition) {
		t.Error("unknown status must be rejected")
	}
}

func TestErrorRedactedAndBounded(t *testing.T) {
	r := redactor.New()
	rel := r.Register([]byte("super-secret-value-123"))
	defer rel()
	e := NewError(CodeInvalidCredential, "bad key super-secret-value-123 "+strings.Repeat("x", 500), r)
	if strings.Contains(e.Message, "super-secret-value-123") {
		t.Error("credential leaked")
	}
	if n := len([]rune(e.Message)); n > MaxMessage {
		t.Errorf("message %d runes", n)
	}
	if !errors.Is(error(e), &Error{Code: CodeInvalidCredential}) {
		t.Error("errors.Is by code failed")
	}
	if errors.Is(error(e), &Error{Code: CodeNetwork}) {
		t.Error("different code matched")
	}
	e.WithOffenders([]string{"s3:PutObject", "super-secret-value-123"}, r)
	if strings.Contains(strings.Join(e.Offenders, ","), "super-secret") {
		t.Error("offender leaked")
	}
}

func TestCodeSets(t *testing.T) {
	if len(VerificationCodes) != 6 || len(AllCodes) != 18 {
		t.Fatalf("got %d/%d codes", len(VerificationCodes), len(AllCodes))
	}
	if !IsVerificationCode(CodeExpired) || IsVerificationCode(CodeForbidden) {
		t.Error("IsVerificationCode wrong")
	}
}
