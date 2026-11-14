package deviceflow

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/lifecycle"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/redactor"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/vault"
)

// RefreshVault is the vault surface refresh needs (satisfied by the lifecycle
// manager's vault).
type RefreshVault interface {
	Use(ctx context.Context, ref vault.Ref, fn func(secret []byte) error) error
	Put(ctx context.Context, ref vault.Ref, connectorID string, secret []byte, exp time.Time) error
}

// RefreshInput describes one refresh-token renewal.
type RefreshInput struct {
	// Client is the policy-enforcing client of the connection (lifecycle.Call.Client).
	Client *http.Client
	Vault  RefreshVault
	// Redactor is optional; when set the new tokens are registered while in use.
	Redactor *redactor.Redactor
	// TokenURL has any tenant placeholder already resolved.
	TokenURL *url.URL
	ClientID string
	Scopes   []string
	Now      func() time.Time
}

// Refresh exchanges the stored refresh token for a new access token with
// grant_type=refresh_token, the client ID and no client secret. On success the
// new access token (and a rotated refresh token, if sent) replace the vault
// slots and the new expiry is returned, zero when the provider sent none. The
// refresh token never leaves the vault except in the request body.
//
// Providers whose credentials cannot be renewed (PATs, API tokens) implement
// lifecycle.NonRefreshable instead of calling this.
func Refresh(ctx context.Context, in RefreshInput, conn store.Connection) (time.Time, error) {
	now := time.Now
	if in.Now != nil {
		now = in.Now
	}
	var body []byte
	var status int
	err := in.Vault.Use(ctx, lifecycle.RefreshRef(conn.ID), func(rt []byte) error {
		form := url.Values{"client_id": {in.ClientID}, "grant_type": {"refresh_token"}, "refresh_token": {string(rt)}}
		if len(in.Scopes) > 0 {
			form.Set("scope", strings.Join(in.Scopes, " "))
		}
		var perr error
		body, status, perr = postForm(ctx, in.Client, in.TokenURL, form)
		return perr
	})
	if err != nil {
		return time.Time{}, err
	}
	defer clear(body)

	var red lifecycle.Redactor
	if in.Redactor != nil {
		red = in.Redactor
	}
	var r struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		Error        string `json:"error"`
	}
	if json.Unmarshal(body, &r) != nil || status >= 500 {
		return time.Time{}, lifecycle.NewError(lifecycle.CodeNetwork, "provider returned an unexpected response", red)
	}
	if r.AccessToken == "" {
		if r.Error == "invalid_grant" || r.Error == "invalid_client" || r.Error == "unauthorized_client" {
			return time.Time{}, lifecycle.NewError(lifecycle.CodeInvalidCredential, "refresh token is invalid, revoked or expired", red)
		}
		return time.Time{}, lifecycle.NewError(lifecycle.CodeNetwork, "provider returned an unexpected response", red)
	}

	access, refresh := []byte(r.AccessToken), []byte(r.RefreshToken)
	if in.Redactor != nil {
		defer in.Redactor.Register(access)()
		if len(refresh) > 0 {
			defer in.Redactor.Register(refresh)()
		}
	}
	var exp time.Time
	if r.ExpiresIn > 0 {
		exp = now().Add(time.Duration(r.ExpiresIn) * time.Second)
	}
	// The refresh token is stored first: with rotation the old one is spent, so
	// losing the new one would end the session even if the access token landed.
	if len(refresh) > 0 {
		if err := in.Vault.Put(ctx, lifecycle.RefreshRef(conn.ID), conn.ConnectorID, refresh, time.Time{}); err != nil {
			clear(access)
			return time.Time{}, err
		}
	}
	if err := in.Vault.Put(ctx, lifecycle.CredentialRef(conn.ID), conn.ConnectorID, access, exp); err != nil {
		return time.Time{}, err
	}
	return exp, nil
}

var errNilRequest = errors.New("deviceflow: nil client")

func postForm(ctx context.Context, client *http.Client, u *url.URL, form url.Values) ([]byte, int, error) {
	if client == nil || u == nil {
		return nil, 0, errNilRequest
	}
	return (&Service{}).post(ctx, client, u, form)
}
