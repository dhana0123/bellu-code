package secretscan

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"
)

// Verification results recorded in the finding and in secret_verify_audit.
const (
	VerifyLive       = "live"
	VerifyNotLive    = "not_live"
	VerifyUnverified = "unverified"
)

// VerifyTimeout bounds the single request made per credential.
const VerifyTimeout = 10 * time.Second

// Doer is the outbound HTTP client. secretscan never builds one: the caller
// supplies a client from an archtest-allowed package.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// VerifyAudit is one secret_verify_audit row. It never holds the secret.
type VerifyAudit struct {
	WorkspaceID string
	Provider    string
	Fingerprint string
	At          time.Time
	Result      string
}

// AuditSink persists a VerifyAudit row and its copy in `audit`.
type AuditSink interface {
	RecordVerify(ctx context.Context, a VerifyAudit) error
}

// Endpoint describes the minimal read-only request for one provider.
type Endpoint struct {
	URL    string
	Header func(secret []byte) (name, value string)
}

// DefaultEndpoints are the providers that verify with a single bearer-style
// request. Providers that need request signing (aws) have no entry and stay
// unverified until a signer is added.
var DefaultEndpoints = map[string]Endpoint{
	"github": {URL: "https://api.github.com/user", Header: func(s []byte) (string, string) {
		return "Authorization", "Bearer " + string(s)
	}},
}

// Verifier checks whether a detected credential is still active. The zero
// value verifies nothing: every provider is off until Enabled says otherwise.
type Verifier struct {
	WorkspaceID string
	// Enabled reports the setting secrets.verify.<provider>; nil means off.
	Enabled   func(provider string) bool
	HTTP      Doer
	Audit     AuditSink
	Endpoints map[string]Endpoint // nil uses DefaultEndpoints
	Timeout   time.Duration       // zero uses VerifyTimeout
	Now       func() time.Time
}

var errVerifyAudit = errors.New("secretscan: verification audit write failed")

// Verify returns live, not_live or unverified. It sends at most one request,
// without retry. When the provider is disabled it returns "" and does nothing
// (no request, no audit row). The secret slice is zeroed before return.
func (v *Verifier) Verify(ctx context.Context, provider, fingerprint string, secret []byte) (string, error) {
	defer clear(secret)
	if v.Enabled == nil || !v.Enabled(provider) {
		return "", nil
	}
	result := v.check(ctx, provider, secret)
	if v.Audit == nil {
		return result, errVerifyAudit
	}
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	if err := v.Audit.RecordVerify(ctx, VerifyAudit{
		WorkspaceID: v.WorkspaceID, Provider: provider, Fingerprint: fingerprint,
		At: now().UTC(), Result: result,
	}); err != nil {
		return result, errVerifyAudit
	}
	return result, nil
}

func (v *Verifier) check(ctx context.Context, provider string, secret []byte) string {
	eps := v.Endpoints
	if eps == nil {
		eps = DefaultEndpoints
	}
	ep, ok := eps[provider]
	if !ok || v.HTTP == nil {
		return VerifyUnverified
	}
	timeout := v.Timeout
	if timeout <= 0 {
		timeout = VerifyTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep.URL, nil)
	if err != nil {
		return VerifyUnverified
	}
	name, value := ep.Header(secret)
	req.Header.Set(name, value)
	// The error is dropped on purpose: it can echo request details.
	resp, err := v.HTTP.Do(req)
	if err != nil {
		return VerifyUnverified
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return VerifyLive
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return VerifyNotLive
	}
	return VerifyUnverified
}
