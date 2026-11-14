package gcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/lifecycle"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/vault"
)

// WriteProbes is the fixed set of write permissions tested on a project.
var WriteProbes = []string{
	"resourcemanager.projects.setIamPolicy",
	"compute.instances.delete",
	"storage.buckets.delete",
}

const maxBody = 1 << 20

// fallbackLabel is used when the key cannot be read for its client_email.
const fallbackLabel = "Google Cloud"

// ProviderConfig wires a Provider.
type ProviderConfig struct {
	// Opener reads the service-account key from the vault to take its
	// client_email as account label. Nil falls back to a generic label.
	Opener vault.Opener
}

// Provider is the Google Cloud lifecycle.Provider.
type Provider struct{ cfg ProviderConfig }

var (
	_ lifecycle.Provider                  = (*Provider)(nil)
	_ lifecycle.MethodCredentialValidator = (*Provider)(nil)
	_ lifecycle.NonRefreshable            = (*Provider)(nil)
)

// NewProvider returns the Google Cloud provider.
func NewProvider(cfg ProviderConfig) *Provider { return &Provider{cfg: cfg} }

type keyDoc struct {
	Type        string `json:"type"`
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
}

func invalid(msg string) error {
	return lifecycle.NewError(lifecycle.CodeValidationFailed, msg, nil)
}

// ValidateCredentialFor checks the pasted key document. Errors name fields
// only, never values.
func (p *Provider) ValidateCredentialFor(method string, secret []byte) error {
	if method != MethodServiceAccount {
		return invalid("unsupported authentication method")
	}
	var k keyDoc
	if err := json.Unmarshal(secret, &k); err != nil {
		return invalid("service account key must be a JSON object")
	}
	if k.Type != "service_account" {
		return invalid("service account key: field type must be service_account")
	}
	if k.ClientEmail == "" {
		return invalid("service account key: field client_email is required")
	}
	if k.PrivateKey == "" {
		return invalid("service account key: field private_key is required")
	}
	return nil
}

// Verify lists projects through the broker, which also proves the key signs
// and exchanges. The label is the key's client_email.
func (p *Provider) Verify(ctx context.Context, c lifecycle.Call) (lifecycle.Identity, error) {
	if _, err := p.projects(ctx, c); err != nil {
		return lifecycle.Identity{}, err
	}
	return lifecycle.Identity{AccountLabel: p.label(ctx, c)}, nil
}

// label reads client_email from the vault. The key never leaves the callback.
func (p *Provider) label(ctx context.Context, c lifecycle.Call) string {
	if p.cfg.Opener == nil {
		return fallbackLabel
	}
	label := ""
	err := p.cfg.Opener.Use(ctx, c.Ref.Credential, func(secret []byte) error {
		var k keyDoc
		if json.Unmarshal(secret, &k) == nil {
			label = k.ClientEmail
		}
		return nil
	})
	if err != nil || label == "" {
		return fallbackLabel
	}
	return label
}

// CheckPermissions tests the write probe set on the first active project and
// reports every granted permission. With no project to test it is unverifiable.
func (p *Provider) CheckPermissions(ctx context.Context, c lifecycle.Call) (lifecycle.PermissionReport, error) {
	ids, err := p.projects(ctx, c)
	if err != nil {
		return lifecycle.PermissionReport{}, err
	}
	if len(ids) == 0 {
		return lifecycle.PermissionReport{Unverifiable: true}, nil
	}
	body, _ := json.Marshal(map[string][]string{"permissions": WriteProbes})
	u := "https://" + ResourceManagerHost + "/v1/projects/" + url.PathEscape(ids[0]) + ":testIamPermissions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return lifecycle.PermissionReport{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	var out struct {
		Permissions []string `json:"permissions"`
	}
	if err := p.do(c, req, &out); err != nil {
		var se *statusError
		if errors.As(err, &se) && se.status == http.StatusForbidden {
			return lifecycle.PermissionReport{Unverifiable: true}, nil
		}
		return lifecycle.PermissionReport{}, err
	}
	granted := map[string]bool{}
	for _, g := range out.Permissions {
		granted[g] = true
	}
	offenders := []string{}
	for _, w := range WriteProbes {
		if granted[w] {
			offenders = append(offenders, w)
		}
	}
	return lifecycle.PermissionReport{WriteOffenders: offenders}, nil
}

// Refreshable is false: the broker refreshes the access token itself.
func (p *Provider) Refreshable(store.Connection) bool { return false }

// Refresh is a no-op and returns the known expiry.
func (p *Provider) Refresh(_ context.Context, c lifecycle.Call) (time.Time, error) {
	if e := c.Connection.CredentialExpiresAt; e != nil {
		return *e, nil
	}
	return time.Time{}, nil
}

// Collector is nil: version 1 collects no data.
func (p *Provider) Collector(store.Connection, broker.ConnectionRef) collectors.Collector {
	return nil
}

// Describe routes the connection to Cloud Resource Manager with gcp-sa auth.
func (p *Provider) Describe(store.Connection) lifecycle.Descriptor {
	return lifecycle.Descriptor{
		Auth: broker.AuthGCPServiceAccount, APIHost: ResourceManagerHost, Host: ResourceManagerHost,
	}
}

type statusError struct{ status int }

func (e *statusError) Error() string { return fmt.Sprintf("gcp: unexpected status %d", e.status) }

// projects returns the ids of the active projects visible to the account.
func (p *Provider) projects(ctx context.Context, c lifecycle.Call) ([]string, error) {
	u := "https://" + ResourceManagerHost + "/v3/projects:search?pageSize=50"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	var out struct {
		Projects []struct {
			ProjectID string `json:"projectId"`
			State     string `json:"state"`
		} `json:"projects"`
	}
	if err := p.do(c, req, &out); err != nil {
		var se *statusError
		if errors.As(err, &se) && se.status == http.StatusForbidden {
			return nil, lifecycle.NewError(lifecycle.CodeInsufficientPermission, "service account lacks permission to list projects", nil)
		}
		return nil, err
	}
	ids := []string{}
	for _, pr := range out.Projects {
		if pr.ProjectID != "" && (pr.State == "" || pr.State == "ACTIVE") {
			ids = append(ids, pr.ProjectID)
		}
	}
	return ids, nil
}

// do sends req through the broker client and decodes a JSON 200 response.
func (p *Provider) do(c lifecycle.Call, req *http.Request, out any) error {
	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return mapStatus(resp.StatusCode)
	}
	if json.Unmarshal(body, out) != nil {
		return errors.New("gcp: invalid response")
	}
	return nil
}

func mapStatus(status int) error {
	switch status {
	case http.StatusUnauthorized:
		return lifecycle.NewError(lifecycle.CodeInvalidCredential, "service account key is invalid or revoked", nil)
	case http.StatusForbidden:
		return &statusError{status: status}
	case http.StatusTooManyRequests:
		return lifecycle.NewError(lifecycle.CodeRateLimited, "provider rate limit reached", nil)
	}
	return &statusError{status: status}
}
