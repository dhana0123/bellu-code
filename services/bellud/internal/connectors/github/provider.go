package github

import (
	"context"
	"errors"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/lifecycle"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/policy"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
)

// Clients builds policy-enforcing HTTP clients (satisfied by *broker.Broker).
type Clients interface {
	HTTPClient(ref broker.ConnectionRef, caller string) *http.Client
}

// ProviderConfig wires a Provider.
type ProviderConfig struct {
	// Clients builds the collector's HTTP client. Verify and CheckPermissions
	// use the client in lifecycle.Call.
	Clients Clients
	// HostFor returns the GitHub Enterprise Server host of a connection, or ""
	// for github.com. A non-empty value must pass ValidateHost.
	HostFor func(store.Connection) string
}

// Provider is the GitHub lifecycle.Provider (fine-grained PAT only).
type Provider struct{ cfg ProviderConfig }

var _ lifecycle.Provider = (*Provider)(nil)

// NewProvider returns the GitHub provider.
func NewProvider(cfg ProviderConfig) *Provider { return &Provider{cfg: cfg} }

// ValidateCredential enforces the github_pat_ prefix. The manager must call it
// before the secret reaches the vault; nothing is stored or changed on error.
func (p *Provider) ValidateCredential(secret []byte) error {
	if err := ValidateToken(secret); err != nil {
		return lifecycle.NewError(lifecycle.CodeValidationFailed, ClassicTokenMessage, nil)
	}
	return nil
}

// Verify calls GET /user and lists the accessible repositories. The token
// expiry from the response header is reported when present.
func (p *Provider) Verify(ctx context.Context, c lifecycle.Call) (lifecycle.Identity, error) {
	cl := p.client(c.Connection, c.Client)
	u, expiry, ok, err := cl.Verify(ctx)
	if err != nil {
		return lifecycle.Identity{}, mapError(err)
	}
	if _, err := cl.Repositories(ctx); err != nil {
		return lifecycle.Identity{}, mapError(err)
	}
	id := lifecycle.Identity{AccountLabel: u.Login}
	if ok {
		id.ExpiresAt = expiry
	}
	return id, nil
}

// CheckPermissions reports the PAT as unverifiable: GitHub has no endpoint
// listing the permissions of a fine-grained PAT. Writes stay blocked by the
// allowlist.
func (p *Provider) CheckPermissions(context.Context, lifecycle.Call) (lifecycle.PermissionReport, error) {
	return lifecycle.PermissionReport{Unverifiable: true}, nil
}

// Refresh is a no-op: a PAT cannot be renewed. It returns the known expiry.
func (p *Provider) Refresh(_ context.Context, c lifecycle.Call) (time.Time, error) {
	if e := c.Connection.CredentialExpiresAt; e != nil {
		return *e, nil
	}
	return time.Time{}, nil
}

// Repositories lists the repositories the token can access, for the picker.
func (p *Provider) Repositories(ctx context.Context, c lifecycle.Call) ([]Repo, error) {
	repos, err := p.client(c.Connection, c.Client).Repositories(ctx)
	return repos, mapError(err)
}

// Collector builds the collector for the connection's selected repositories.
func (p *Provider) Collector(conn store.Connection, ref broker.ConnectionRef) collectors.Collector {
	var hc *http.Client
	if p.cfg.Clients != nil {
		hc = p.cfg.Clients.HTTPClient(ref, policy.CallerCollector)
	}
	host, base := p.endpoint(conn)
	return NewCollector(conn.ID, NewClient(hc, host, base), conn.Selection.Repos,
		time.Duration(conn.IntervalSec)*time.Second)
}

// Describe routes the connection to api.github.com or its GHES host.
func (p *Provider) Describe(conn store.Connection) lifecycle.Descriptor {
	host, base := p.endpoint(conn)
	return lifecycle.Descriptor{Auth: broker.AuthGitHubToken, APIHost: host, BasePath: base, Host: host}
}

func (p *Provider) endpoint(conn store.Connection) (host, basePath string) {
	if p.cfg.HostFor != nil {
		if h := strings.ToLower(p.cfg.HostFor(conn)); h != "" && ValidateHost(h) == nil {
			return h, GHESBasePath
		}
	}
	return DefaultAPIHost, ""
}

func (p *Provider) client(conn store.Connection, hc *http.Client) *Client {
	host, base := p.endpoint(conn)
	return NewClient(hc, host, base)
}

// mapError turns GitHub status errors into typed lifecycle errors. Other
// errors (broker errors) pass through for the manager to classify.
func mapError(err error) error {
	var se *StatusError
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

var hostLabelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidateHost accepts a bare DNS name for a GitHub Enterprise Server: no
// scheme, port, path, IP literal, placeholder or single label. Requests to it
// are always https.
func ValidateHost(h string) error {
	bad := errors.New("github: invalid enterprise host")
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

// ValidateSelection requires at least one valid "owner/name" repository after
// a selection event.
func ValidateSelection(repos []string) error {
	if len(repos) == 0 {
		return lifecycle.NewError(lifecycle.CodeValidationFailed, "select at least one repository", nil)
	}
	for _, r := range repos {
		owner, name, ok := strings.Cut(r, "/")
		if !ok || !namePattern.MatchString(owner) || !namePattern.MatchString(name) {
			return lifecycle.NewError(lifecycle.CodeValidationFailed, "repository must be owner/name", nil)
		}
	}
	return nil
}
