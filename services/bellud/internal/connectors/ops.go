package connectors

import (
	"context"
	"errors"
	"os"
	"regexp"
	"strings"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/aws"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/azure"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/bitbucket"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/cloudflare"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/gcp"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/github"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/gitlab"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/keysource"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/kubernetes"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/lifecycle"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/policy"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
)

// takePassphrase returns the passphrase Unlock handed over, else asks prompt.
func (s *Service) takePassphrase(ctx context.Context, prompt func(context.Context) ([]byte, error)) ([]byte, error) {
	s.pwMu.Lock()
	p := s.pending
	s.pending = nil
	s.pwMu.Unlock()
	if p != nil {
		return p, nil
	}
	return prompt(ctx)
}

// TestResult is a verification report with the informational warnings.
type TestResult struct {
	Report   lifecycle.TestReport
	Warnings []string
}

// TestDetail verifies a connection and adds the provider warnings: the AWS
// data-read actions the principal holds, or the GitHub "unverifiable" note.
// Warning lookups are best effort and never fail the test.
func (s *Service) TestDetail(ctx context.Context, id string) (TestResult, error) {
	rep, err := s.Test(ctx, id)
	if err != nil {
		return TestResult{}, err
	}
	out := TestResult{Report: rep, Warnings: []string{}}
	conn, ok := s.Connection(id)
	if !ok {
		return out, nil
	}
	switch conn.ConnectorID {
	case aws.ConnectorID:
		if call, err := s.lifecycleCall(conn); err == nil {
			if w, err := s.awsProv.DataReadWarnings(ctx, call); err == nil {
				out.Warnings = append(out.Warnings, w...)
			}
		}
	case github.ConnectorID:
		if rep.Permission == "unverifiable" {
			out.Warnings = append(out.Warnings, github.UnverifiableMessage)
		}
	}
	return out, nil
}

func (s *Service) lifecycleCall(conn store.Connection) (lifecycle.Call, error) {
	ref, err := s.BrokerRef(conn.ID)
	if err != nil {
		return lifecycle.Call{}, err
	}
	return lifecycle.Call{Connection: conn, Ref: ref, Client: s.broker.HTTPClient(ref, policy.CallerLifecycle)}, nil
}

// GithubRepoList is the repository picker data of a GitHub connection.
type GithubRepoList struct {
	Repos []github.Repo
	// Installations and InstallURL are set for device Connections only.
	Installations int
	InstallURL    string
}

// GithubRepos lists the repositories a GitHub connection can access.
func (s *Service) GithubRepos(ctx context.Context, id string) ([]github.Repo, error) {
	l, err := s.GithubRepoList(ctx, id)
	return l.Repos, err
}

// GithubRepoList lists the repositories a GitHub connection can access. For a
// device Connection it also reports the installation count and the install URL.
func (s *Service) GithubRepoList(ctx context.Context, id string) (GithubRepoList, error) {
	if !s.Enabled() {
		return GithubRepoList{}, ErrDisabled
	}
	conn, ok := s.Connection(id)
	if !ok {
		return GithubRepoList{}, s.invalid("connection not found", "id")
	}
	if conn.ConnectorID != github.ConnectorID {
		return GithubRepoList{}, s.invalid("connection is not a GitHub connection", "id")
	}
	call, err := s.lifecycleCall(conn)
	if err != nil {
		return GithubRepoList{}, err
	}
	var out GithubRepoList
	if conn.Method == github.MethodDevice {
		var l github.RepoList
		l, err = s.githubPrv.RepoList(ctx, call)
		out = GithubRepoList{Repos: l.Repos, Installations: l.Installations,
			InstallURL: github.InstallURL(github.EffectiveAppSlug(s.getenv))}
	} else {
		out.Repos, err = s.githubPrv.Repositories(ctx, call)
	}
	if err != nil {
		var le *lifecycle.Error
		if errors.As(err, &le) {
			return GithubRepoList{}, err
		}
		return GithubRepoList{}, lifecycle.NewError(lifecycle.CodeNetwork, "repositories could not be listed", s.red)
	}
	return out, nil
}

// ScopeOption is one selectable item of a connection's scope step.
type ScopeOption struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ScopeOptions lists what the connection's credential can reach, using the
// provider's own listing: GitLab projects, Azure subscriptions, Google Cloud
// projects, Bitbucket workspaces, Cloudflare zones or Kubernetes namespaces.
// The user's pick is stored in store.Selection.Items through Update.
func (s *Service) ScopeOptions(ctx context.Context, id string) ([]ScopeOption, error) {
	if !s.Enabled() {
		return nil, ErrDisabled
	}
	conn, ok := s.Connection(id)
	if !ok {
		return nil, s.invalid("connection not found", "id")
	}
	call, err := s.lifecycleCall(conn)
	if err != nil {
		return nil, err
	}
	out := []ScopeOption{}
	switch conn.ConnectorID {
	case gitlab.ConnectorID:
		var ps []gitlab.ProjectScope
		if ps, err = s.gitlabPrv.Projects(ctx, call); err == nil {
			for _, p := range ps {
				out = append(out, ScopeOption{ID: p.FullPath, Name: p.FullPath})
			}
		}
	case azure.ConnectorID:
		var subs []azure.Subscription
		if subs, err = s.azurePrv.Subscriptions(ctx, call); err == nil {
			for _, x := range subs {
				out = append(out, ScopeOption{ID: x.ID, Name: first(x.Name, x.ID)})
			}
		}
	case gcp.ConnectorID:
		var ids []string
		if ids, err = s.gcpPrv.ProjectIDs(ctx, call); err == nil {
			for _, x := range ids {
				out = append(out, ScopeOption{ID: x, Name: x})
			}
		}
	case bitbucket.ConnectorID:
		var ws []bitbucket.Workspace
		if ws, err = s.bitbktPrv.Workspaces(ctx, call); err == nil {
			for _, w := range ws {
				out = append(out, ScopeOption{ID: w.Slug, Name: first(w.Name, w.Slug)})
			}
		}
	case cloudflare.ConnectorID:
		var zs []cloudflare.Zone
		if zs, err = s.cfPrv.Zones(ctx, call); err == nil {
			for _, z := range zs {
				out = append(out, ScopeOption{ID: z.ID, Name: first(z.Name, z.ID)})
			}
		}
	case kubernetes.ConnectorID:
		var ns []string
		if ns, err = s.k8sPrv.Namespaces(ctx, call); err == nil {
			for _, n := range ns {
				out = append(out, ScopeOption{ID: n, Name: n})
			}
		}
	default:
		return nil, s.invalid("connector has no scope options", "id")
	}
	if err != nil {
		var le *lifecycle.Error
		if errors.As(err, &le) {
			return nil, err
		}
		return nil, lifecycle.NewError(lifecycle.CodeNetwork, "scope options could not be listed", s.red)
	}
	return out, nil
}

// AWSSetup is the assume-role onboarding material.
type AWSSetup struct {
	ExternalID     string
	CloudFormation string
	Terraform      string
	Principal      string // empty when no ambient principal was detected
	QuickCreateURL string // empty unless a template URL is configured and a principal is known
}

// placeholderPrincipal keeps the templates valid when no ambient principal can
// be detected. Account 000000000000 does not exist; the user replaces it.
const placeholderPrincipal = "arn:aws:iam::000000000000:root"

var roleNameUnsafe = regexp.MustCompile(`[^A-Za-z0-9+=,.@_-]+`)

// AWSSetup generates an external ID, both templates and the detected principal.
func (s *Service) AWSSetup(ctx context.Context, alias string) (AWSSetup, error) {
	if !s.Enabled() {
		return AWSSetup{}, ErrDisabled
	}
	id, err := aws.GenerateExternalID()
	if err != nil {
		return AWSSetup{}, lifecycle.NewError(lifecycle.CodeValidationFailed, "external id could not be generated", s.red)
	}
	principal := s.detectPrincipal(ctx)
	trust := principal
	if trust == "" {
		trust = placeholderPrincipal
	}
	role := "bellu-read"
	if a := strings.Trim(roleNameUnsafe.ReplaceAllString(alias, "-"), "-"); a != "" {
		role = "bellu-" + a
		if len(role) > 64 {
			role = role[:64]
		}
	}
	tp := aws.TrustParams{RoleName: role, Principal: trust, ExternalID: id}
	cfn, err := aws.CloudFormationTemplate(tp)
	if err != nil {
		return AWSSetup{}, s.invalid("setup template could not be rendered", "alias")
	}
	tf, err := aws.TerraformSnippet(tp)
	if err != nil {
		return AWSSetup{}, s.invalid("setup template could not be rendered", "alias")
	}
	quick := ""
	if principal != "" {
		quick = aws.QuickCreateURL(aws.EffectiveRegion(os.Getenv), aws.EffectiveTemplateURL(os.Getenv), principal, id)
	}
	return AWSSetup{ExternalID: id, CloudFormation: cfn, Terraform: tf, Principal: principal, QuickCreateURL: quick}, nil
}

// detectPrincipal returns the ARN of the ambient AWS identity, or "".
func (s *Service) detectPrincipal(ctx context.Context) string {
	e, ok := s.registry.Get(aws.ConnectorID)
	if !ok {
		return ""
	}
	pol, err := policy.Compile(e.Manifest, policy.Selection{Regions: []string{"us-east-1"}})
	if err != nil {
		return ""
	}
	ref := broker.ConnectionRef{ConnectorID: aws.ConnectorID, Manifest: e.Manifest, Policy: pol, Auth: broker.AuthAWSAmbient}
	id, err := s.awsProv.AmbientIdentity(ctx, s.broker.IMDSClient(ref), s.broker.HTTPClient(ref, policy.CallerLifecycle), "us-east-1")
	if err != nil {
		return ""
	}
	return id.PrincipalARN
}

// Unlock supplies the passphrase of a passphrase-protected vault.
func (s *Service) Unlock(ctx context.Context, passphrase []byte) error {
	defer clear(passphrase)
	if !s.Enabled() {
		return ErrDisabled
	}
	st := s.vault.Status()
	if st.KeySource != keysource.NamePassphrase {
		return s.invalid("the vault does not use a passphrase", "passphrase")
	}
	if !st.Locked {
		return nil
	}
	pw := append([]byte(nil), passphrase...)
	s.pwMu.Lock()
	s.pending = pw
	s.pwMu.Unlock()
	err := s.vault.Unlock(ctx)
	s.pwMu.Lock()
	clear(s.pending)
	s.pending = nil
	s.pwMu.Unlock()
	switch {
	case err == nil:
		return nil
	case errors.Is(err, keysource.ErrPassphraseTooShort):
		return s.invalid("passphrase is too short", "passphrase")
	case isKeyMismatch(err):
		return lifecycle.NewError(lifecycle.CodeInvalidCredential, "passphrase is incorrect", s.red)
	}
	return vaultError(err, s.red)
}

// RotateMasterKey re-wraps every credential under a new Master_Key.
func (s *Service) RotateMasterKey(ctx context.Context) error {
	if !s.Enabled() {
		return ErrDisabled
	}
	if err := s.vault.RotateMasterKey(ctx); err != nil {
		if isRotationUnsupported(err) {
			return s.invalid("the active key source cannot rotate the master key")
		}
		return vaultError(err, s.red)
	}
	return nil
}

// ForgetAll disconnects every connection and deletes every stored credential.
func (s *Service) ForgetAll(ctx context.Context) error {
	if !s.Enabled() {
		return ErrDisabled
	}
	var first error
	for _, c := range s.Connections() {
		if err := s.Disconnect(ctx, c.ID); err != nil && first == nil {
			first = err
		}
	}
	if err := s.vault.ForgetAll(ctx); err != nil {
		return vaultError(err, s.red)
	}
	return first
}
