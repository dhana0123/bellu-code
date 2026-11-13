package lifecycle

// Code is a typed error code (Req 10.1 plus the non-credential codes).
type Code string

const (
	CodeInvalidCredential      Code = "invalid_credential"
	CodeInsufficientPermission Code = "insufficient_permission"
	CodeExcessPermission       Code = "excess_permission"
	CodeNetwork                Code = "network"
	CodeRateLimited            Code = "rate_limited"
	CodeExpired                Code = "expired"

	CodeAliasInvalid       Code = "alias_invalid"
	CodeAliasTaken         Code = "alias_taken"
	CodeBlockedByPolicy    Code = "blocked_by_policy"
	CodeScopeDenied        Code = "scope_denied"
	CodeRunInProgress      Code = "run_in_progress"
	CodeVaultUnavailable   Code = "vault_unavailable"
	CodeAuditFailed        Code = "audit_failed"
	CodeDecryptFailed      Code = "decrypt_failed"
	CodeTransitionRejected Code = "transition_rejected"
	CodeValidationFailed   Code = "validation_failed"
	CodePayloadTooLarge    Code = "payload_too_large"
	CodeForbidden          Code = "forbidden"
)

// VerificationCodes is the set from which verification returns exactly one.
var VerificationCodes = []Code{
	CodeInvalidCredential, CodeInsufficientPermission, CodeExcessPermission,
	CodeNetwork, CodeRateLimited, CodeExpired,
}

// AllCodes lists every typed code.
var AllCodes = append(append([]Code{}, VerificationCodes...),
	CodeAliasInvalid, CodeAliasTaken, CodeBlockedByPolicy, CodeScopeDenied,
	CodeRunInProgress, CodeVaultUnavailable, CodeAuditFailed, CodeDecryptFailed,
	CodeTransitionRejected, CodeValidationFailed, CodePayloadTooLarge, CodeForbidden)

// MaxMessage is the maximum message length in characters.
const MaxMessage = 200

// Redactor scrubs credential values from text (satisfied by *redactor.Redactor).
type Redactor interface{ String(string) string }

// Error is a typed, credential-free error. Message is at most MaxMessage runes.
// Offenders names excess-permission offenders (permission names, not values).
type Error struct {
	Code      Code     `json:"code"`
	Message   string   `json:"message"`
	Offenders []string `json:"offenders,omitempty"`
	// InUse is the number of connections using an Auth_Config being deleted.
	InUse int `json:"inUse,omitempty"`
}

func (e *Error) Error() string { return string(e.Code) + ": " + e.Message }

// Is matches any *Error with the same code, so errors.Is(err, &Error{Code: c}) works.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

// NewError builds a typed error; msg passes through r (if non-nil) and is
// truncated to MaxMessage runes after redaction.
func NewError(code Code, msg string, r Redactor) *Error {
	if r != nil {
		msg = r.String(msg)
	}
	return &Error{Code: code, Message: truncate(msg, MaxMessage)}
}

// WithOffenders returns e with offender names redacted and bounded.
func (e *Error) WithOffenders(names []string, r Redactor) *Error {
	out := make([]string, len(names))
	for i, n := range names {
		if r != nil {
			n = r.String(n)
		}
		out[i] = truncate(n, MaxMessage)
	}
	e.Offenders = out
	return e
}

func truncate(s string, n int) string {
	rs := []rune(s)
	if len(rs) <= n {
		return s
	}
	return string(rs[:n])
}

// IsVerificationCode reports whether c is one of the six Req 10.1 codes.
func IsVerificationCode(c Code) bool {
	for _, v := range VerificationCodes {
		if v == c {
			return true
		}
	}
	return false
}
