package azure

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/deviceflow"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/lifecycle"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/manifest"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/policy"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/redactor"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
)

// maxBody bounds one decoded response.
const maxBody = 4 << 20

// maxCheckedSubscriptions bounds the subscriptions inspected by CheckPermissions.
const maxCheckedSubscriptions = 10

// ProviderConfig wires a Provider.
type ProviderConfig struct {
	// ClientID is the Entra application ID used to refresh device tokens.
	ClientID string
	// Vault is the vault used to renew device tokens (the lifecycle manager's vault).
	Vault deviceflow.RefreshVault
	// Redactor is optional; it hides renewed tokens while in use.
	Redactor *redactor.Redactor
	// Now overrides time.Now.
	Now func() time.Time
	// Broker supplies the policy-checked HTTP client of the collector. Without
	// it Provider.Collector returns nil.
	Broker interface {
		HTTPClient(ref broker.ConnectionRef, caller string) *http.Client
	}
}

// Provider is the Azure lifecycle.Provider.
type Provider struct{ cfg ProviderConfig }

var (
	_ lifecycle.Provider                  = (*Provider)(nil)
	_ lifecycle.MethodCredentialValidator = (*Provider)(nil)
	_ lifecycle.NonRefreshable            = (*Provider)(nil)
)

// NewProvider returns the Azure provider.
func NewProvider(cfg ProviderConfig) *Provider { return &Provider{cfg: cfg} }

var guidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// ServicePrincipal is the pasted service principal credential.
type ServicePrincipal struct{ TenantID, ClientID, ClientSecret string }

// EncodeServicePrincipal serializes the credential as "tenant\nclient\nsecret".
func EncodeServicePrincipal(sp ServicePrincipal) []byte {
	return []byte(sp.TenantID + "\n" + sp.ClientID + "\n" + sp.ClientSecret)
}

// ParseServicePrincipal parses the stored form. The tenant is a tenant id or
// domain, the client id a GUID and the secret a non-empty string without
// whitespace.
func ParseServicePrincipal(secret []byte) (ServicePrincipal, error) {
	parts := strings.Split(string(secret), "\n")
	if len(parts) != 3 {
		return ServicePrincipal{}, errors.New("azure: invalid service principal")
	}
	sp := ServicePrincipal{TenantID: parts[0], ClientID: parts[1], ClientSecret: parts[2]}
	if !manifest.ValidTenant(sp.TenantID) || !guidRe.MatchString(sp.ClientID) ||
		sp.ClientSecret == "" || strings.ContainsAny(sp.ClientSecret, " \t\r\n") {
		return ServicePrincipal{}, errors.New("azure: invalid service principal")
	}
	return sp, nil
}

// ValidateCredentialFor applies the credential rule of the method: device
// requires an access token without whitespace, service-principal requires
// tenant id, client id (GUID) and client secret.
func (p *Provider) ValidateCredentialFor(method string, secret []byte) error {
	switch method {
	case MethodDevice:
		if len(secret) > 0 && !bytes.ContainsAny(secret, " \t\r\n") {
			return nil
		}
		return lifecycle.NewError(lifecycle.CodeValidationFailed, "Azure access token must not be empty or contain whitespace", nil)
	case MethodServicePrincipal:
		if _, err := ParseServicePrincipal(secret); err != nil {
			return lifecycle.NewError(lifecycle.CodeValidationFailed,
				"service principal needs a tenant id, a client id (GUID) and a client secret", nil)
		}
		return nil
	}
	return lifecycle.NewError(lifecycle.CodeValidationFailed, "unsupported authentication method", nil)
}

type subscription struct {
	ID          string `json:"subscriptionId"`
	DisplayName string `json:"displayName"`
	TenantID    string `json:"tenantId"`
}

// Verify lists the subscriptions with GET /subscriptions. The label is the
// first subscription name, else its tenant id.
//
// TODO(broker): the service-principal method needs a broker auth kind that
// reads "tenant\nclient\nsecret" from the vault and runs the client_credentials
// exchange (scope ServicePrincipalScope) as the auth operation SPTokenOperation,
// as AuthGCPServiceAccount does for Google. Until then Describe routes it with
// bearer auth, which would send the raw secret, so Verify fails closed for it.
func (p *Provider) Verify(ctx context.Context, c lifecycle.Call) (lifecycle.Identity, error) {
	if c.Connection.Method == MethodServicePrincipal {
		return lifecycle.Identity{}, lifecycle.NewError(lifecycle.CodeValidationFailed,
			"service principal sign-in is not available yet", nil)
	}
	subs, err := p.subscriptions(ctx, c.Client)
	if err != nil {
		return lifecycle.Identity{}, err
	}
	label := "Azure account"
	if len(subs) > 0 {
		switch {
		case subs[0].DisplayName != "":
			label = subs[0].DisplayName
		case subs[0].TenantID != "":
			label = subs[0].TenantID
		}
	}
	return lifecycle.Identity{AccountLabel: label}, nil
}

// CheckPermissions reads the effective permissions of the caller on up to ten
// subscriptions and reports every write-capable action (for example "*" of
// Owner and Contributor). Reader and Security Reader grant read actions only.
func (p *Provider) CheckPermissions(ctx context.Context, c lifecycle.Call) (lifecycle.PermissionReport, error) {
	subs, err := p.subscriptions(ctx, c.Client)
	if err != nil {
		return lifecycle.PermissionReport{}, err
	}
	if len(subs) > maxCheckedSubscriptions {
		subs = subs[:maxCheckedSubscriptions]
	}
	var rep lifecycle.PermissionReport
	for _, s := range subs {
		if s.ID == "" || strings.ContainsAny(s.ID, "/?#") {
			continue
		}
		var out struct {
			Value []struct {
				Actions    []string `json:"actions"`
				NotActions []string `json:"notActions"`
			} `json:"value"`
		}
		path := "/subscriptions/" + url.PathEscape(s.ID) + "/providers/Microsoft.Authorization/permissions?api-version=" + AuthorizationAPIVersion
		if err := p.get(ctx, c.Client, path, &out); err != nil {
			if errors.Is(err, &lifecycle.Error{Code: lifecycle.CodeInsufficientPermission}) {
				rep.Unverifiable = true
				continue
			}
			return lifecycle.PermissionReport{}, err
		}
		for _, perm := range out.Value {
			for _, a := range perm.Actions {
				if isWriteAction(a) && !slices.Contains(perm.NotActions, a) && !slices.Contains(rep.WriteOffenders, a) {
					rep.WriteOffenders = append(rep.WriteOffenders, a)
				}
			}
		}
	}
	slices.Sort(rep.WriteOffenders)
	return rep, nil
}

// isWriteAction reports whether an Azure RBAC action string allows more than
// reading. Support ticket actions are not treated as writes to resources.
func isWriteAction(a string) bool {
	a = strings.ToLower(strings.TrimSpace(a))
	if a == "" || strings.HasPrefix(a, "microsoft.support/") {
		return false
	}
	if a == "*" {
		return true
	}
	if strings.HasSuffix(a, "/read") {
		return false
	}
	// "*", "x/*", "x/write", "x/delete", "x/action" and similar.
	return true
}

// Refreshable implements lifecycle.NonRefreshable: only device tokens carry a
// refresh token. A service principal is exchanged by the broker.
func (p *Provider) Refreshable(conn store.Connection) bool { return conn.Method == MethodDevice }

// Refresh renews a device access token with its refresh token.
func (p *Provider) Refresh(ctx context.Context, c lifecycle.Call) (time.Time, error) {
	if c.Connection.Method != MethodDevice {
		if e := c.Connection.CredentialExpiresAt; e != nil {
			return *e, nil
		}
		return time.Time{}, nil
	}
	if p.cfg.Vault == nil {
		return time.Time{}, lifecycle.NewError(lifecycle.CodeVaultUnavailable, "vault is not configured", nil)
	}
	tu, err := url.Parse(strings.ReplaceAll(TokenURL, manifest.TenantPlaceholder, manifest.DefaultTenant))
	if err != nil {
		return time.Time{}, err
	}
	return deviceflow.Refresh(ctx, deviceflow.RefreshInput{
		Client: c.Client, Vault: p.cfg.Vault, Redactor: p.cfg.Redactor,
		TokenURL: tu, ClientID: p.cfg.ClientID,
		Scopes: []string{DeviceScope, OfflineScope}, Now: p.cfg.Now,
	}, c.Connection)
}

// Collector builds the collector of an ACTIVE connection. It returns nil when
// no broker is configured.
func (p *Provider) Collector(conn store.Connection, ref broker.ConnectionRef) collectors.Collector {
	if p.cfg.Broker == nil {
		return nil
	}
	return NewCollector(p.cfg.Broker.HTTPClient(ref, policy.CallerCollector), conn)
}

// Describe routes the connection to Azure Resource Manager with bearer auth.
func (p *Provider) Describe(store.Connection) lifecycle.Descriptor {
	return lifecycle.Descriptor{Auth: broker.AuthBearer, APIHost: ARMHost, Host: ARMHost}
}

func (p *Provider) subscriptions(ctx context.Context, hc *http.Client) ([]subscription, error) {
	var out struct {
		Value []subscription `json:"value"`
	}
	if err := p.get(ctx, hc, "/subscriptions?api-version="+SubscriptionsAPIVersion, &out); err != nil {
		return nil, err
	}
	return out.Value, nil
}

// statusError is a non-2xx response without its body.
type statusError struct{ Status int }

func (e *statusError) Error() string { return "azure: unexpected status " + http.StatusText(e.Status) }

func (p *Provider) get(ctx context.Context, hc *http.Client, path string, out any) error {
	if hc == nil {
		return errors.New("azure: nil client")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+ARMHost+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return mapError(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return mapError(&statusError{Status: resp.StatusCode})
	}
	if err := json.Unmarshal(body, out); err != nil {
		return lifecycle.NewError(lifecycle.CodeNetwork, "provider returned an unexpected response", nil)
	}
	return nil
}

// mapError turns Azure status errors into typed lifecycle errors. Other
// errors (broker errors) pass through for the manager to classify.
func mapError(err error) error {
	var se *statusError
	if !errors.As(err, &se) {
		return err
	}
	switch se.Status {
	case http.StatusUnauthorized:
		return lifecycle.NewError(lifecycle.CodeInvalidCredential, "token is invalid, revoked or expired", nil)
	case http.StatusForbidden:
		return lifecycle.NewError(lifecycle.CodeInsufficientPermission, "token lacks the required read permissions", nil)
	case http.StatusTooManyRequests:
		return lifecycle.NewError(lifecycle.CodeRateLimited, "provider rate limit reached", nil)
	}
	return err
}
