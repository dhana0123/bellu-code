package aws

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/lifecycle"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/policy"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
)

// WriteActions is the fixed list of write actions simulated against the
// principal. Any allowed action blocks activation (strict rule: there is no
// override; acknowledging the warning only precedes fixing the role and
// reconnecting).
var WriteActions = []string{
	"ec2:RunInstances", "ec2:TerminateInstances",
	"s3:PutObject", "s3:DeleteObject", "s3:DeleteBucket",
	"iam:CreateUser", "iam:CreateAccessKey", "iam:AttachRolePolicy", "iam:PutRolePolicy",
	"lambda:CreateFunction", "lambda:UpdateFunctionCode",
	"rds:CreateDBInstance", "rds:DeleteDBInstance",
}

// DataReadActions are reads of customer data. They are reported as a warning
// (DataReadWarnings) and never block activation, because the broker allowlist
// does not include them.
var DataReadActions = []string{
	"s3:GetObject", "secretsmanager:GetSecretValue", "ssm:GetParameter", "dynamodb:Scan",
}

// Params are the per-connection settings the provider cannot read from the
// store: the auth config's role and source and the external ID from the vault.
type Params struct {
	// RoleARN is the role to assume (assume_role only).
	RoleARN string
	// ExternalID is sent in every AssumeRole call (assume_role only).
	ExternalID string
	// Source names where the base credentials of AssumeRole come from:
	// SourceVault (the connection's vault slot) or SourceAmbient.
	Source string
}

// Broker is the part of *broker.Broker the provider uses.
type Broker interface {
	HTTPClient(ref broker.ConnectionRef, caller string) *http.Client
	AWSCredentials(ref broker.ConnectionRef, caller string) awssdk.CredentialsProvider
	IMDSClient(ref broker.ConnectionRef) *http.Client
}

// ProviderConfig wires a Provider.
type ProviderConfig struct {
	Broker Broker
	// Params resolves the settings of a connection. It is called per
	// operation; nothing it returns is retained beyond the in-memory session.
	Params func(ctx context.Context, conn store.Connection) (Params, error)
	// Getenv reads the ambient AWS_* variables (default: none).
	Getenv func(string) string
	// Register adds a secret to the redactor and returns its release.
	Register func(secret []byte) func()
	// NewClient builds the typed client (default NewClient); tests replace it.
	NewClient func(Config) (Client, error)
	// Backoff and Sleep tune the session refresh retries (tests).
	Backoff time.Duration
	Sleep   func(ctx context.Context, d time.Duration) error
}

// Provider implements lifecycle.Provider and lifecycle.SessionDropper for AWS.
type Provider struct {
	cfg ProviderConfig

	mu       sync.Mutex
	sessions map[string]*session
}

var (
	_ lifecycle.Provider       = (*Provider)(nil)
	_ lifecycle.SessionDropper = (*Provider)(nil)
)

type sessionKey struct {
	params     Params
	credential string
	region     string
}

// session is the in-memory assumed-role session of one connection.
type session struct {
	key sessionKey
	rp  *RoleProvider
}

// NewProvider returns a Provider.
func NewProvider(cfg ProviderConfig) (*Provider, error) {
	if cfg.Broker == nil || cfg.Params == nil {
		return nil, errors.New("aws: provider requires a broker and a params resolver")
	}
	if cfg.NewClient == nil {
		cfg.NewClient = NewClient
	}
	return &Provider{cfg: cfg, sessions: map[string]*session{}}, nil
}

// Describe routes every AWS request through the SDK-signing transport. The
// ambient source is restricted to STS by a separate, per-session client.
func (p *Provider) Describe(store.Connection) lifecycle.Descriptor {
	return lifecycle.Descriptor{Auth: broker.AuthAWSVault}
}

// Verify checks the caller identity. The root user is rejected and any
// session built from the credential is discarded; the caller deletes the
// staged credential on error.
func (p *Provider) Verify(ctx context.Context, c lifecycle.Call) (lifecycle.Identity, error) {
	cl, err := p.verifyClient(ctx, c)
	if err != nil {
		return lifecycle.Identity{}, err
	}
	id, err := cl.Identity(ctx)
	if err != nil {
		p.dropIfExpired(c.Connection.ID)
		return lifecycle.Identity{}, mapFailure(err, lifecycle.CodeInvalidCredential)
	}
	if IsRootARN(id.ARN) {
		p.DropSession(c.Connection.ID)
		return lifecycle.Identity{}, lifecycle.NewError(lifecycle.CodeInvalidCredential,
			"root credentials are not allowed; use an IAM role or user", nil)
	}
	return lifecycle.Identity{AccountLabel: id.Account}, nil
}

// CheckPermissions simulates WriteActions against the principal. Every
// allowed action is an offender. A denied simulation is
// insufficient_permission.
func (p *Provider) CheckPermissions(ctx context.Context, c lifecycle.Call) (lifecycle.PermissionReport, error) {
	allowed, err := p.simulate(ctx, c, WriteActions)
	if err != nil {
		return lifecycle.PermissionReport{}, err
	}
	return lifecycle.PermissionReport{WriteOffenders: allowed}, nil
}

// DataReadWarnings lists the DataReadActions the principal is allowed. It is
// informational and never blocks activation.
func (p *Provider) DataReadWarnings(ctx context.Context, c lifecycle.Call) ([]string, error) {
	return p.simulate(ctx, c, DataReadActions)
}

func (p *Provider) simulate(ctx context.Context, c lifecycle.Call, actions []string) ([]string, error) {
	cl, err := p.verifyClient(ctx, c)
	if err != nil {
		return nil, err
	}
	id, err := cl.Identity(ctx)
	if err != nil {
		p.dropIfExpired(c.Connection.ID)
		return nil, mapFailure(err, lifecycle.CodeInvalidCredential)
	}
	res, err := cl.SimulateWrites(ctx, id.PrincipalARN, actions)
	if err != nil {
		if errors.Is(err, ErrAccessDenied) && !isPassthrough(err) {
			return nil, lifecycle.NewError(lifecycle.CodeInsufficientPermission,
				"the policy simulation was denied; allow iam:SimulatePrincipalPolicy on the role", nil)
		}
		return nil, mapFailure(err, lifecycle.CodeInsufficientPermission)
	}
	var out []string
	for _, a := range res {
		if slices.Contains(actions, a.Action) && !slices.Contains(out, a.Action) {
			out = append(out, a.Action)
		}
	}
	slices.Sort(out)
	return out, nil
}

// Refresh renews the assumed-role session and returns its expiry. Static keys
// have no session, so it returns the zero time. When the retries are
// exhausted the session is dropped and the error is lifecycle.CodeExpired.
func (p *Provider) Refresh(ctx context.Context, c lifecycle.Call) (time.Time, error) {
	conn := c.Connection
	if conn.Method != MethodAssumeRole {
		return time.Time{}, nil
	}
	params, err := p.cfg.Params(ctx, conn)
	if err != nil {
		return time.Time{}, err
	}
	p.DropSession(conn.ID) // force a new AssumeRole call
	s, err := p.session(conn, c.Ref, params)
	if err != nil {
		return time.Time{}, err
	}
	creds, err := s.rp.Retrieve(ctx)
	if err != nil {
		p.dropIfExpired(conn.ID)
		if errors.Is(err, ErrExpired) && !isPassthrough(err) {
			return time.Time{}, lifecycle.NewError(lifecycle.CodeExpired,
				"session credentials could not be refreshed; reconnect", nil)
		}
		return time.Time{}, mapFailure(err, lifecycle.CodeInvalidCredential)
	}
	// The credentials cache reports the refresh time (expiry − RefreshWindow).
	return creds.Expires.Add(RefreshWindow), nil
}

// Collector builds the collector of an ACTIVE connection. When its client
// cannot be built, the collector's runs fail with that error.
func (p *Provider) Collector(conn store.Connection, ref broker.ConnectionRef) collectors.Collector {
	cl, err := p.collectClient(conn, ref)
	if err != nil {
		return failedCollector{Collector: NewCollector(nil, conn, conn.Selection), err: err}
	}
	return NewCollector(statusClient{Client: cl}, conn, conn.Selection)
}

// DropSession forgets the in-memory session of a connection and releases its
// redaction registrations.
func (p *Provider) DropSession(connectionID string) {
	p.mu.Lock()
	s := p.sessions[connectionID]
	delete(p.sessions, connectionID)
	p.mu.Unlock()
	if s != nil {
		s.rp.expire(nil)
	}
}

func (p *Provider) dropIfExpired(connectionID string) {
	p.mu.Lock()
	s := p.sessions[connectionID]
	p.mu.Unlock()
	if s != nil && s.rp.Expired() {
		p.DropSession(connectionID)
	}
}

// verifyClient builds the client for lifecycle calls on the broker client the
// manager supplied.
func (p *Provider) verifyClient(ctx context.Context, c lifecycle.Call) (Client, error) {
	creds, region, err := p.credentials(ctx, c.Connection, c.Ref, policy.CallerLifecycle)
	if err != nil {
		return nil, err
	}
	return p.newClient(c.Client, creds, region)
}

func (p *Provider) collectClient(conn store.Connection, ref broker.ConnectionRef) (Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	creds, region, err := p.credentials(ctx, conn, ref, policy.CallerCollector)
	if err != nil {
		return nil, err
	}
	return p.newClient(p.cfg.Broker.HTTPClient(ref, policy.CallerCollector), creds, region)
}

func (p *Provider) newClient(h *http.Client, creds awssdk.CredentialsProvider, region string) (Client, error) {
	cl, err := p.cfg.NewClient(Config{HTTPClient: h, Credentials: creds, HomeRegion: region})
	if err != nil {
		return nil, lifecycle.NewError(lifecycle.CodeValidationFailed, "aws client could not be configured", nil)
	}
	return cl, nil
}

// credentials returns the signing credentials for caller and the home region.
// Static keys come from the vault on every signing. AssumeRole sessions are
// shared by lifecycle and collector callers; AssumeRole itself always uses a
// lifecycle client because its operation is class auth.
func (p *Provider) credentials(ctx context.Context, conn store.Connection, ref broker.ConnectionRef, caller string) (awssdk.CredentialsProvider, string, error) {
	if len(conn.Selection.Regions) == 0 {
		return nil, "", lifecycle.NewError(lifecycle.CodeValidationFailed, "select at least one region", nil)
	}
	region := conn.Selection.Regions[0]
	switch conn.Method {
	case MethodStaticKeys:
		return p.cfg.Broker.AWSCredentials(ref, caller), region, nil
	case MethodAssumeRole:
		params, err := p.cfg.Params(ctx, conn)
		if err != nil {
			return nil, "", err
		}
		s, err := p.session(conn, ref, params)
		if err != nil {
			return nil, "", err
		}
		return s.rp, region, nil
	}
	return nil, "", lifecycle.NewError(lifecycle.CodeValidationFailed, "unsupported auth method", nil)
}

// session returns the connection's assumed-role session, building a new one
// when settings or the credential slot changed or the old one expired.
func (p *Provider) session(conn store.Connection, ref broker.ConnectionRef, params Params) (*session, error) {
	key := sessionKey{params: params, credential: ref.Credential.Slot, region: conn.Selection.Regions[0]}
	p.mu.Lock()
	defer p.mu.Unlock()
	if s := p.sessions[conn.ID]; s != nil {
		if s.key == key && !s.rp.Expired() {
			return s, nil
		}
		s.rp.expire(nil)
		delete(p.sessions, conn.ID)
	}
	cfg := AssumeRoleConfig{
		RoleARN: params.RoleARN, ExternalID: params.ExternalID, SessionName: "bellu",
		Region: key.region, Backoff: p.cfg.Backoff, Sleep: p.cfg.Sleep, Register: p.cfg.Register,
	}
	switch params.Source {
	case SourceVault:
		cfg.Base = p.cfg.Broker.AWSCredentials(ref, policy.CallerLifecycle)
		cfg.HTTPClient = p.cfg.Broker.HTTPClient(ref, policy.CallerLifecycle)
	case SourceAmbient:
		// Ambient credentials may reach only STS and the metadata service.
		amb := ref
		amb.Auth = broker.AuthAWSAmbient
		cfg.Base = AmbientCredentials(p.cfg.Broker.IMDSClient(amb), p.cfg.Getenv)
		cfg.HTTPClient = p.cfg.Broker.HTTPClient(amb, policy.CallerLifecycle)
	default:
		return nil, lifecycle.NewError(lifecycle.CodeValidationFailed, "unknown credential source", nil)
	}
	rp, err := NewAssumeRoleProvider(cfg)
	if err != nil {
		return nil, lifecycle.NewError(lifecycle.CodeValidationFailed, "role settings are invalid", nil)
	}
	s := &session{key: key, rp: rp}
	p.sessions[conn.ID] = s
	return s, nil
}

// isPassthrough reports errors the manager classifies itself (policy blocks,
// vault failures, rate limits, network). They must not be recoded here.
func isPassthrough(err error) bool {
	var be *broker.BlockedError
	var ce *broker.CredentialError
	var rl *broker.RateLimitedError
	var ne *broker.NetworkError
	return errors.As(err, &be) || errors.As(err, &ce) || errors.As(err, &rl) || errors.As(err, &ne) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}

// mapFailure converts the typed AWS errors to *lifecycle.Error. denied is the
// code for AccessDenied in the step at hand. Other errors are returned as is.
func mapFailure(err error, denied lifecycle.Code) error {
	if isPassthrough(err) {
		return err
	}
	switch {
	case errors.Is(err, ErrInvalidCredential), errors.Is(err, ErrNoAmbientCredentials):
		return lifecycle.NewError(lifecycle.CodeInvalidCredential, "AWS rejected the credential", nil)
	case errors.Is(err, ErrAccessDenied):
		return lifecycle.NewError(denied, "AWS denied the request", nil)
	case errors.Is(err, ErrThrottled):
		return lifecycle.NewError(lifecycle.CodeRateLimited, "AWS rate limit reached", nil)
	case errors.Is(err, ErrExpired):
		return lifecycle.NewError(lifecycle.CodeExpired, "AWS credentials expired", nil)
	}
	return err
}

// failedCollector keeps the name, interval and timeout of the real collector
// but fails every run with the error that prevented building its client.
type failedCollector struct {
	collectors.Collector
	err error
}

func (f failedCollector) Collect(context.Context) (graph.Batch, error) {
	return graph.Batch{}, mapFailure(f.err, lifecycle.CodeInsufficientPermission)
}

func (failedCollector) Timeout() time.Duration { return collectors.ConnectorTimeout }

// statusClient tags credential and permission failures with the HTTP status
// the supervisor acts on: 401 sets EXPIRED, 403 sets ERROR.
type statusClient struct{ Client }

func httpStatus(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrExpired), errors.Is(err, ErrInvalidCredential):
		return fmt.Errorf("%w: %w", &lifecycle.HTTPStatusError{Code: http.StatusUnauthorized}, err)
	case errors.Is(err, ErrAccessDenied):
		return fmt.Errorf("%w: %w", &lifecycle.HTTPStatusError{Code: http.StatusForbidden}, err)
	}
	return err
}

func (s statusClient) Instances(ctx context.Context, r string) (Listing[Instance], error) {
	v, err := s.Client.Instances(ctx, r)
	return v, httpStatus(err)
}

func (s statusClient) Buckets(ctx context.Context) ([]Bucket, error) {
	v, err := s.Client.Buckets(ctx)
	return v, httpStatus(err)
}

func (s statusClient) SecurityGroups(ctx context.Context, r string) (Listing[SecurityGroup], error) {
	v, err := s.Client.SecurityGroups(ctx, r)
	return v, httpStatus(err)
}

func (s statusClient) VPCs(ctx context.Context, r string) (Listing[VPC], error) {
	v, err := s.Client.VPCs(ctx, r)
	return v, httpStatus(err)
}

func (s statusClient) Roles(ctx context.Context) ([]Role, error) {
	v, err := s.Client.Roles(ctx)
	return v, httpStatus(err)
}

func (s statusClient) Functions(ctx context.Context, r string) ([]Function, error) {
	v, err := s.Client.Functions(ctx, r)
	return v, httpStatus(err)
}

func (s statusClient) DBInstances(ctx context.Context, r string) ([]DBInstance, error) {
	v, err := s.Client.DBInstances(ctx, r)
	return v, httpStatus(err)
}

func (s statusClient) Identity(ctx context.Context) (Identity, error) {
	v, err := s.Client.Identity(ctx)
	return v, httpStatus(err)
}
func (s statusClient) Subnets(ctx context.Context, r string) (Listing[Subnet], error) {
	v, err := s.Client.Subnets(ctx, r)
	return v, httpStatus(err)
}
func (s statusClient) ENIs(ctx context.Context, r string) (Listing[ENI], error) {
	v, err := s.Client.ENIs(ctx, r)
	return v, httpStatus(err)
}
func (s statusClient) RouteTables(ctx context.Context, r string) (Listing[RouteTable], error) {
	v, err := s.Client.RouteTables(ctx, r)
	return v, httpStatus(err)
}
func (s statusClient) InternetGateways(ctx context.Context, r string) (Listing[InternetGateway], error) {
	v, err := s.Client.InternetGateways(ctx, r)
	return v, httpStatus(err)
}
func (s statusClient) NATGateways(ctx context.Context, r string) (Listing[NATGateway], error) {
	v, err := s.Client.NATGateways(ctx, r)
	return v, httpStatus(err)
}
func (s statusClient) SGRules(ctx context.Context, r string) (Listing[SGRule], error) {
	v, err := s.Client.SGRules(ctx, r)
	return v, httpStatus(err)
}
func (s statusClient) NetworkACLs(ctx context.Context, r string) (Listing[NetworkACL], error) {
	v, err := s.Client.NetworkACLs(ctx, r)
	return v, httpStatus(err)
}
func (s statusClient) VPCEndpoints(ctx context.Context, r string) (Listing[VPCEndpoint], error) {
	v, err := s.Client.VPCEndpoints(ctx, r)
	return v, httpStatus(err)
}
func (s statusClient) PeeringConnections(ctx context.Context, r string) (Listing[PeeringConnection], error) {
	v, err := s.Client.PeeringConnections(ctx, r)
	return v, httpStatus(err)
}
func (s statusClient) ElasticIPs(ctx context.Context, r string) (Listing[ElasticIP], error) {
	v, err := s.Client.ElasticIPs(ctx, r)
	return v, httpStatus(err)
}
func (s statusClient) TransitGateways(ctx context.Context, r string) (Listing[TransitGateway], error) {
	v, err := s.Client.TransitGateways(ctx, r)
	return v, httpStatus(err)
}
func (s statusClient) TGWAttachments(ctx context.Context, r string) (Listing[TGWAttachment], error) {
	v, err := s.Client.TGWAttachments(ctx, r)
	return v, httpStatus(err)
}
func (s statusClient) LoadBalancers(ctx context.Context, r string) (Listing[LoadBalancer], error) {
	v, err := s.Client.LoadBalancers(ctx, r)
	return v, httpStatus(err)
}
func (s statusClient) TargetGroups(ctx context.Context, r string) (Listing[TargetGroup], error) {
	v, err := s.Client.TargetGroups(ctx, r)
	return v, httpStatus(err)
}
func (s statusClient) Listeners(ctx context.Context, r, arn string) ([]Listener, error) {
	v, err := s.Client.Listeners(ctx, r, arn)
	return v, httpStatus(err)
}
func (s statusClient) TargetHealth(ctx context.Context, r, arn string) ([]TargetHealth, error) {
	v, err := s.Client.TargetHealth(ctx, r, arn)
	return v, httpStatus(err)
}
