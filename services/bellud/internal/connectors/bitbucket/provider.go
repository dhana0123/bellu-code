package bitbucket

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/lifecycle"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
)

const (
	maxBody  = 1 << 20
	maxField = 512
)

// Provider is the Bitbucket lifecycle.Provider (email plus API token).
type Provider struct{}

var (
	_ lifecycle.Provider                  = (*Provider)(nil)
	_ lifecycle.MethodCredentialValidator = (*Provider)(nil)
	_ lifecycle.NonRefreshable            = (*Provider)(nil)
)

// NewProvider returns the Bitbucket provider.
func NewProvider() *Provider { return &Provider{} }

// ValidateCredentialFor checks the "user\nsecret" format: an email-like user
// and a non-empty token, without further newlines or whitespace in the token.
// Messages name the field, never the value.
func (p *Provider) ValidateCredentialFor(method string, secret []byte) error {
	if method != MethodAPIToken {
		return lifecycle.NewError(lifecycle.CodeValidationFailed, "unsupported authentication method", nil)
	}
	user, token, ok := strings.Cut(string(secret), "\n")
	user = strings.TrimSpace(user)
	if !ok || user == "" {
		return lifecycle.NewError(lifecycle.CodeValidationFailed, "email is required", nil)
	}
	at := strings.IndexByte(user, '@')
	if at <= 0 || at == len(user)-1 || strings.ContainsAny(user, " \t\r:") {
		return lifecycle.NewError(lifecycle.CodeValidationFailed, "email must be a valid address", nil)
	}
	if token == "" || strings.ContainsAny(token, "\r\n") || strings.TrimSpace(token) != token {
		return lifecycle.NewError(lifecycle.CodeValidationFailed, "API token is required and must not contain whitespace", nil)
	}
	return nil
}

// Verify calls GET /2.0/user and labels the account by username or name.
func (p *Provider) Verify(ctx context.Context, c lifecycle.Call) (lifecycle.Identity, error) {
	u, _, err := getUser(ctx, c.Client)
	if err != nil {
		return lifecycle.Identity{}, mapError(err)
	}
	label := firstNonEmpty(u.Username, u.Nickname, u.DisplayName, u.AccountID)
	return lifecycle.Identity{AccountLabel: label}, nil
}

// CheckPermissions reads the granted scopes from the response header and
// reports write, admin and delete scopes. A response without the header is
// Unverifiable; writes stay blocked by the allowlist.
func (p *Provider) CheckPermissions(ctx context.Context, c lifecycle.Call) (lifecycle.PermissionReport, error) {
	_, h, err := getUser(ctx, c.Client)
	if err != nil {
		return lifecycle.PermissionReport{}, mapError(err)
	}
	scopes, ok := ParseScopes(h)
	if !ok {
		return lifecycle.PermissionReport{Unverifiable: true}, nil
	}
	return lifecycle.PermissionReport{WriteOffenders: WriteScopes(scopes)}, nil
}

// Refreshable implements lifecycle.NonRefreshable: an API token cannot be renewed.
func (p *Provider) Refreshable(store.Connection) bool { return false }

// Refresh is a no-op that returns the known expiry.
func (p *Provider) Refresh(_ context.Context, c lifecycle.Call) (time.Time, error) {
	if e := c.Connection.CredentialExpiresAt; e != nil {
		return *e, nil
	}
	return time.Time{}, nil
}

// Collector is nil in v1: Bitbucket only verifies and connects.
func (p *Provider) Collector(store.Connection, broker.ConnectionRef) collectors.Collector {
	return nil
}

// Describe routes the connection to api.bitbucket.org with Basic auth.
func (p *Provider) Describe(store.Connection) lifecycle.Descriptor {
	return lifecycle.Descriptor{Auth: broker.AuthBasic, APIHost: APIHost, Host: APIHost}
}

// ParseScopes reads the granted scopes from X-OAuth-Scopes (or
// X-Credential-Scopes). ok is false when neither header is present.
func ParseScopes(h http.Header) (scopes []string, ok bool) {
	var v string
	for _, k := range []string{"X-OAuth-Scopes", "X-Credential-Scopes"} {
		if vals := h.Values(k); len(vals) > 0 {
			v = strings.Join(vals, ",")
			ok = true
			break
		}
	}
	if !ok {
		return nil, false
	}
	for _, s := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
		scopes = append(scopes, s)
	}
	return scopes, true
}

// WriteScopes returns the scopes that grant write, admin or delete access.
// A scope matches when any ":"-separated segment is write, admin or delete
// (for example repository:write, delete:repository:bitbucket).
func WriteScopes(scopes []string) []string {
	out := []string{}
	for _, s := range scopes {
		for _, seg := range strings.Split(strings.ToLower(s), ":") {
			if seg == "write" || seg == "admin" || seg == "delete" {
				out = append(out, s)
				break
			}
		}
	}
	return out
}

type user struct {
	Username    string `json:"username"`
	Nickname    string `json:"nickname"`
	DisplayName string `json:"display_name"`
	AccountID   string `json:"account_id"`
}

// statusError is a non-2xx response; it never carries the body.
type statusError struct{ status int }

func (e *statusError) Error() string {
	return "bitbucket: unexpected status " + http.StatusText(e.status)
}

func getUser(ctx context.Context, hc *http.Client) (user, http.Header, error) {
	var u user
	if hc == nil {
		return u, nil, errors.New("bitbucket: no http client")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+APIHost+"/2.0/user", nil)
	if err != nil {
		return u, nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return u, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))
		return u, nil, &statusError{status: resp.StatusCode}
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&u); err != nil {
		return u, nil, errors.New("bitbucket: unreadable response")
	}
	u.Username, u.Nickname = clip(u.Username), clip(u.Nickname)
	u.DisplayName, u.AccountID = clip(u.DisplayName), clip(u.AccountID)
	return u, resp.Header, nil
}

func clip(s string) string {
	if len(s) > maxField {
		return s[:maxField]
	}
	return s
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// mapError turns Bitbucket status errors into typed lifecycle errors. Other
// errors pass through for the manager to classify.
func mapError(err error) error {
	var se *statusError
	if !errors.As(err, &se) {
		return err
	}
	switch se.status {
	case http.StatusUnauthorized:
		return lifecycle.NewError(lifecycle.CodeInvalidCredential, "email or API token is invalid, revoked or expired", nil)
	case http.StatusForbidden:
		return lifecycle.NewError(lifecycle.CodeInsufficientPermission, "token lacks the required read scopes", nil)
	case http.StatusTooManyRequests:
		return lifecycle.NewError(lifecycle.CodeRateLimited, "provider rate limit reached", nil)
	}
	return err
}
