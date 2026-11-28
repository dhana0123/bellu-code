package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/lifecycle"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
)

const maxBody = 1 << 20

// Provider is the Cloudflare lifecycle.Provider (API token only).
type Provider struct{}

var (
	_ lifecycle.Provider                  = (*Provider)(nil)
	_ lifecycle.MethodCredentialValidator = (*Provider)(nil)
	_ lifecycle.NonRefreshable            = (*Provider)(nil)
)

// NewProvider returns the Cloudflare provider.
func NewProvider() *Provider { return &Provider{} }

// ValidateCredentialFor requires a non-empty token without whitespace.
func (p *Provider) ValidateCredentialFor(method string, secret []byte) error {
	if method != MethodToken {
		return lifecycle.NewError(lifecycle.CodeValidationFailed, "unsupported authentication method", nil)
	}
	if len(secret) == 0 || bytes.ContainsFunc(secret, unicode.IsSpace) {
		return lifecycle.NewError(lifecycle.CodeValidationFailed, "API token must be non-empty and contain no whitespace", nil)
	}
	return nil
}

type envelope[T any] struct {
	Success bool `json:"success"`
	Result  T    `json:"result"`
}

type tokenInfo struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	ExpiresOn string `json:"expires_on"`
}

// Verify calls GET /user/tokens/verify and requires an active token. The label
// is the first accessible account name, else the token id.
func (p *Provider) Verify(ctx context.Context, c lifecycle.Call) (lifecycle.Identity, error) {
	var v envelope[tokenInfo]
	if err := getJSON(ctx, c.Client, pathVerify, &v); err != nil {
		return lifecycle.Identity{}, err
	}
	if !v.Success || v.Result.Status != "active" {
		return lifecycle.Identity{}, lifecycle.NewError(lifecycle.CodeInvalidCredential, "token is not active", nil)
	}
	id := lifecycle.Identity{AccountLabel: v.Result.ID}
	if t, err := time.Parse(time.RFC3339, v.Result.ExpiresOn); err == nil {
		id.ExpiresAt = t
	}
	var accts envelope[[]struct {
		Name string `json:"name"`
	}]
	if err := getJSON(ctx, c.Client, pathAccounts, &accts); err != nil {
		return lifecycle.Identity{}, err
	}
	if len(accts.Result) > 0 && accts.Result[0].Name != "" {
		id.AccountLabel = accts.Result[0].Name
	}
	if err := getJSON(ctx, c.Client, pathZones, &envelope[json.RawMessage]{}); err != nil {
		return lifecycle.Identity{}, err
	}
	return id, nil
}

// CheckPermissions lists permission groups whose name contains Edit or Write.
// A token that cannot read its own policy is reported as Unverifiable.
func (p *Provider) CheckPermissions(ctx context.Context, c lifecycle.Call) (lifecycle.PermissionReport, error) {
	var v envelope[tokenInfo]
	if err := getJSON(ctx, c.Client, pathVerify, &v); err != nil {
		return lifecycle.PermissionReport{}, err
	}
	if v.Result.ID == "" {
		return lifecycle.PermissionReport{Unverifiable: true}, nil
	}
	var t envelope[struct {
		Policies []struct {
			Effect           string `json:"effect"`
			PermissionGroups []struct {
				Name string `json:"name"`
			} `json:"permission_groups"`
		} `json:"policies"`
	}]
	err := getJSON(ctx, c.Client, "/client/v4/user/tokens/"+v.Result.ID, &t)
	if err != nil {
		if le, ok := err.(*lifecycle.Error); ok && le.Code == lifecycle.CodeInsufficientPermission {
			return lifecycle.PermissionReport{Unverifiable: true}, nil
		}
		return lifecycle.PermissionReport{}, err
	}
	var offenders []string
	for _, pol := range t.Result.Policies {
		if pol.Effect != "" && pol.Effect != "allow" {
			continue
		}
		for _, g := range pol.PermissionGroups {
			n := strings.ToLower(g.Name)
			if (strings.Contains(n, "edit") || strings.Contains(n, "write")) && !slices.Contains(offenders, g.Name) {
				offenders = append(offenders, g.Name)
			}
		}
	}
	return lifecycle.PermissionReport{WriteOffenders: offenders}, nil
}

// Refreshable is always false: an API token cannot be renewed.
func (p *Provider) Refreshable(store.Connection) bool { return false }

// Refresh is a no-op that returns the known expiry.
func (p *Provider) Refresh(_ context.Context, c lifecycle.Call) (time.Time, error) {
	if e := c.Connection.CredentialExpiresAt; e != nil {
		return *e, nil
	}
	return time.Time{}, nil
}

// Collector returns nil: Cloudflare has no collector.
func (p *Provider) Collector(store.Connection, broker.ConnectionRef) collectors.Collector { return nil }

// Describe routes the connection to api.cloudflare.com with bearer auth.
func (p *Provider) Describe(store.Connection) lifecycle.Descriptor {
	return lifecycle.Descriptor{Auth: broker.AuthBearer, APIHost: APIHost, Host: APIHost}
}

func getJSON(ctx context.Context, hc *http.Client, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+APIHost+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return lifecycle.NewError(lifecycle.CodeInvalidCredential, "token is invalid, revoked or expired", nil)
	case http.StatusForbidden:
		return lifecycle.NewError(lifecycle.CodeInsufficientPermission, "token lacks the required read permissions", nil)
	case http.StatusTooManyRequests:
		return lifecycle.NewError(lifecycle.CodeRateLimited, "provider rate limit reached", nil)
	default:
		return lifecycle.NewError(lifecycle.CodeValidationFailed, "unexpected response from Cloudflare", nil)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(out)
}
