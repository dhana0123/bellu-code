package gitlab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/deviceflow"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/lifecycle"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/redactor"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
)

// maxBody bounds one decoded response.
const maxBody = 4 << 20

// ProviderConfig wires a Provider.
type ProviderConfig struct {
	// ClientID is the effective OAuth client ID, used to refresh device tokens.
	ClientID string
	// Vault and Redactor are used to renew device tokens. Redactor is optional.
	Vault    deviceflow.RefreshVault
	Redactor *redactor.Redactor
	// HostFor returns the self-managed GitLab host of a connection, or "" for
	// gitlab.com. A non-empty value must pass ValidateHost.
	HostFor func(store.Connection) string
	// Now overrides the clock (tests).
	Now func() time.Time
}

// Provider is the GitLab lifecycle.Provider.
type Provider struct{ cfg ProviderConfig }

var (
	_ lifecycle.Provider                  = (*Provider)(nil)
	_ lifecycle.MethodCredentialValidator = (*Provider)(nil)
	_ lifecycle.NonRefreshable            = (*Provider)(nil)
)

// NewProvider returns the GitLab provider.
func NewProvider(cfg ProviderConfig) *Provider { return &Provider{cfg: cfg} }

// ValidateCredentialFor rejects malformed pasted input before it reaches the
// vault. Messages name the field and never the value.
func (p *Provider) ValidateCredentialFor(method string, secret []byte) error {
	switch method {
	case MethodPAT, MethodDevice:
		if len(secret) == 0 || len(secret) > 512 || bytes.ContainsFunc(secret, unicode.IsSpace) {
			return lifecycle.NewError(lifecycle.CodeValidationFailed,
				"GitLab token must be non-empty, at most 512 characters and contain no whitespace", nil)
		}
		return nil
	}
	return lifecycle.NewError(lifecycle.CodeValidationFailed, "unsupported authentication method", nil)
}

type user struct {
	Username string `json:"username"`
}

// Verify calls GET /api/v4/user; the account label is the username.
func (p *Provider) Verify(ctx context.Context, c lifecycle.Call) (lifecycle.Identity, error) {
	var u user
	if err := p.get(ctx, c, "/api/v4/user", &u); err != nil {
		return lifecycle.Identity{}, mapError(err)
	}
	id := lifecycle.Identity{AccountLabel: u.Username}
	if c.Connection.Method == MethodPAT {
		var t struct {
			ExpiresAt string `json:"expires_at"`
		}
		if err := p.get(ctx, c, "/api/v4/personal_access_tokens/self", &t); err == nil && t.ExpiresAt != "" {
			if d, err := time.Parse("2006-01-02", t.ExpiresAt); err == nil {
				id.ExpiresAt = d.Add(24*time.Hour - time.Second)
			}
		}
	}
	return id, nil
}

// readOnlyScopes are the PAT scopes that allow no writes.
var readOnlyScopes = map[string]bool{"read_api": true, "read_user": true, "read_repository": true, "read_registry": true,
	"read_virtual_registry": true, "read_observability": true}

// WriteScopes returns the scopes that are not read-only, in input order.
func WriteScopes(scopes []string) []string {
	out := []string{}
	for _, s := range scopes {
		if !readOnlyScopes[s] {
			out = append(out, s)
		}
	}
	return out
}

// CheckPermissions lists the write-capable scopes of a PAT. Device tokens only
// carry read_api. If the token cannot read its own record the report is
// Unverifiable; the allowlist still blocks writes.
func (p *Provider) CheckPermissions(ctx context.Context, c lifecycle.Call) (lifecycle.PermissionReport, error) {
	if c.Connection.Method == MethodDevice {
		return lifecycle.PermissionReport{WriteOffenders: []string{}}, nil
	}
	var t struct {
		Scopes []string `json:"scopes"`
	}
	if err := p.get(ctx, c, "/api/v4/personal_access_tokens/self", &t); err != nil {
		var se *statusError
		if errors.As(err, &se) {
			return lifecycle.PermissionReport{Unverifiable: true, WriteOffenders: []string{}}, nil
		}
		return lifecycle.PermissionReport{}, err
	}
	return lifecycle.PermissionReport{WriteOffenders: WriteScopes(t.Scopes)}, nil
}

// Refreshable is false for PATs, which cannot be renewed.
func (p *Provider) Refreshable(conn store.Connection) bool { return conn.Method == MethodDevice }

// Refresh renews a device token with its refresh token (no client secret). A
// PAT returns its known expiry.
func (p *Provider) Refresh(ctx context.Context, c lifecycle.Call) (time.Time, error) {
	if c.Connection.Method != MethodDevice {
		if e := c.Connection.CredentialExpiresAt; e != nil {
			return *e, nil
		}
		return time.Time{}, nil
	}
	if p.cfg.Vault == nil || p.cfg.ClientID == "" {
		return time.Time{}, lifecycle.NewError(lifecycle.CodeValidationFailed, "GitLab sign-in is not configured", nil)
	}
	return deviceflow.Refresh(ctx, deviceflow.RefreshInput{
		Client: c.Client, Vault: p.cfg.Vault, Redactor: p.cfg.Redactor, Now: p.cfg.Now,
		TokenURL: &url.URL{Scheme: "https", Host: GitLabHost, Path: "/oauth/token"},
		ClientID: p.cfg.ClientID,
	}, c.Connection)
}

// Collector is nil: version 1 verifies and connects only.
func (p *Provider) Collector(store.Connection, broker.ConnectionRef) collectors.Collector { return nil }

// Describe routes the connection to gitlab.com or its self-managed host.
func (p *Provider) Describe(conn store.Connection) lifecycle.Descriptor {
	h := p.host(conn)
	return lifecycle.Descriptor{Auth: broker.AuthBearer, APIHost: h, Host: h}
}

func (p *Provider) host(conn store.Connection) string {
	if p.cfg.HostFor != nil {
		if h := strings.ToLower(p.cfg.HostFor(conn)); h != "" && ValidateHost(h) == nil {
			return h
		}
	}
	return GitLabHost
}

// ProjectScope is one selectable project.
type ProjectScope struct {
	ID       int64  `json:"id"`
	FullPath string `json:"path_with_namespace"`
}

// Projects lists the projects the credential is a member of, for the scope step.
func (p *Provider) Projects(ctx context.Context, c lifecycle.Call) ([]ProjectScope, error) {
	var out []ProjectScope
	if err := p.get(ctx, c, "/api/v4/projects?membership=true&simple=true&per_page=100", &out); err != nil {
		return nil, mapError(err)
	}
	return out, nil
}

type statusError struct{ status int }

func (e *statusError) Error() string { return fmt.Sprintf("gitlab: unexpected status %d", e.status) }

func (p *Provider) get(ctx context.Context, c lifecycle.Call, path string, out any) error {
	u := url.URL{Scheme: "https", Host: p.host(c.Connection)}
	parsed, err := url.Parse(path)
	if err != nil {
		return err
	}
	u.Path, u.RawQuery = parsed.Path, parsed.RawQuery
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.Client.Do(req)
	if err != nil {
		return err // typed broker errors stay reachable through errors.As
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &statusError{status: resp.StatusCode}
	}
	if err := json.Unmarshal(body, out); err != nil {
		return errors.New("gitlab: malformed response")
	}
	return nil
}

// mapError turns GitLab status errors into typed lifecycle errors.
func mapError(err error) error {
	var se *statusError
	if !errors.As(err, &se) {
		return err
	}
	switch se.status {
	case http.StatusUnauthorized:
		return lifecycle.NewError(lifecycle.CodeInvalidCredential, "token is invalid, revoked or expired", nil)
	case http.StatusForbidden:
		return lifecycle.NewError(lifecycle.CodeInsufficientPermission, "token lacks the required read permissions", nil)
	case http.StatusTooManyRequests:
		return lifecycle.NewError(lifecycle.CodeRateLimited, "provider rate limit reached", nil)
	}
	return err
}

var hostLabelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidateHost accepts a bare DNS name for a self-managed GitLab: no scheme,
// port, path, IP literal, placeholder or single label.
func ValidateHost(h string) error {
	bad := errors.New("gitlab: invalid host")
	if h == "" || len(h) > 253 || h != strings.ToLower(h) || net.ParseIP(h) != nil {
		return bad
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return bad
	}
	for _, l := range labels {
		if !hostLabelRe.MatchString(l) {
			return bad
		}
	}
	return nil
}
