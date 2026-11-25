package connectors

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/audit"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/aws"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/azure"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/bitbucket"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/cloudflare"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/deviceflow"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/gcp"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/github"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/gitlab"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/keysource"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/kubernetes"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/lifecycle"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/manifest"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/policy"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/redactor"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/registry"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/scope"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/vault"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/redact"
)

// ErrDisabled is returned by every operation while the connectors flag is off.
var ErrDisabled = errors.New("connectors: disabled")

// Vault slots owned by a connection besides its credential. They hold the AWS
// external ID (a secret value, it guards against the confused deputy) and the
// non-secret per-connection params (role ARN, credential source, GHES host).
const (
	slotExternalID = "external-id"
	slotParams     = "params"
	slotCA         = kubernetes.CASlot

	// DefaultPageSize is the audit page size.
	DefaultPageSize = 50

	keyFileWarning    = "The master key is stored in a file. Any process running as the bellud user can read it. Keep the file outside the data directory with mode 0400."
	passphraseWarning = "The master key is derived from a passphrase and kept only in memory. Credentials are unavailable after a restart until the passphrase is entered again."
)

// Options configures New. Only Dir and Engine are required when the flag is on.
type Options struct {
	// Dir is the connectors data directory (0700): state.json, audit/ and vault/.
	Dir string
	// Engine is the graph engine collectors write to.
	Engine graph.Engine
	// Getenv reads the environment (default os.Getenv). The flag and the ambient
	// AWS_* variables come from it.
	Getenv func(string) string
	// KeyFile and Passphrase feed the default key source order.
	KeyFile    string
	Passphrase func(ctx context.Context) ([]byte, error)
	// Order replaces the default key source order (tests).
	Order []keysource.Source
	// Transport replaces the broker's guarded dialer transport (tests).
	Transport http.RoundTripper
	Logger    collectors.Logger
	Now       func() time.Time
	// GapSink persists the gaps of each collector run (collector_gap writer).
	GapSink collectors.GapSink
	// GapsFor reads the persisted gaps of a connection's collector for the
	// status route. Nil falls back to the gaps of the last sync.
	GapsFor func(ctx context.Context, collector string) ([]store.Gap, error)
}

// Service owns every connector component. It is safe for concurrent use.
type Service struct {
	enabled bool

	dir    string
	getenv func(string) string
	now    func() time.Time

	red       *redactor.Redactor
	auditLog  *audit.FileLog
	vault     *vault.Store
	store     *store.Store
	registry  registry.Registry
	scope     *scope.Service
	broker    *broker.Broker
	runner    *collectors.Runner
	sup       *lifecycle.CollectorSupervisor
	mgr       *lifecycle.Manager
	authCfgs  *lifecycle.AuthConfigService
	awsProv   *aws.Provider
	githubPrv *github.Provider
	gitlabPrv *gitlab.Provider
	azurePrv  *azure.Provider
	gcpPrv    *gcp.Provider
	bitbktPrv *bitbucket.Provider
	cfPrv     *cloudflare.Provider
	k8sPrv    *kubernetes.Provider
	device    *deviceflow.Service
	gapsFor   func(ctx context.Context, collector string) ([]store.Gap, error)

	pwMu    sync.Mutex
	pending []byte // passphrase handed over by Unlock, consumed by the key source prompt

	createMu sync.Mutex // serializes Create: nextID is handed to the manager
	nextID   string

	mu       sync.Mutex
	params   map[string]*cachedParams
	started  bool
	closed   bool
	cancel   context.CancelFunc
	auditEnd chan struct{}
}

// connParams are the per-connection settings the providers need.
type connParams struct {
	RoleARN string `json:"roleArn,omitempty"`
	Source  string `json:"source,omitempty"`
	Host    string `json:"host,omitempty"`
	// Server is the Kubernetes API server URL (not secret; the token and CA
	// live in the credential and "ca" slots).
	Server     string `json:"server,omitempty"`
	ExternalID string `json:"-"`
}

type cachedParams struct {
	p       connParams
	release func()
}

// New builds the service. With the flag off it returns a disabled Service and
// constructs nothing: no vault is opened, no file is touched and no goroutine
// starts.
func New(ctx context.Context, opt Options) (*Service, error) {
	if opt.Getenv == nil {
		opt.Getenv = os.Getenv
	}
	if !Enabled(opt.Getenv) {
		return &Service{}, nil
	}
	if opt.Dir == "" {
		return nil, errors.New("connectors: data directory is required")
	}
	if opt.Engine == nil {
		return nil, errors.New("connectors: graph engine is required")
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Logger == nil {
		opt.Logger = nopLogger{}
	}
	s := &Service{enabled: true, dir: opt.Dir, getenv: opt.Getenv, now: opt.Now, params: map[string]*cachedParams{}, gapsFor: opt.GapsFor}
	if err := os.MkdirAll(opt.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("connectors: create data directory: %w", err)
	}
	s.red = redactor.New()

	vaultDir := filepath.Join(opt.Dir, "vault")
	if err := os.MkdirAll(vaultDir, 0o700); err != nil {
		return nil, fmt.Errorf("connectors: create vault directory: %w", err)
	}
	order := opt.Order
	if order == nil {
		var prompt func(context.Context) ([]byte, error)
		if opt.Passphrase != nil {
			// Unlock hands a passphrase over through s.pending; otherwise the
			// configured prompt answers.
			prompt = func(ctx context.Context) ([]byte, error) { return s.takePassphrase(ctx, opt.Passphrase) }
		}
		order = keysource.DefaultOrder(keysource.Config{DataDir: vaultDir, KeyFile: opt.KeyFile, Passphrase: prompt})
	}
	// A missing source is not an error: the vault runs memory-only.
	var picked []keysource.Source
	src, err := keysource.Select(ctx, order)
	switch {
	case err == nil:
		picked = []keysource.Source{src}
	case errors.Is(err, keysource.ErrNoSource):
	default:
		return nil, fmt.Errorf("connectors: key source: %w", err)
	}

	s.auditLog, err = audit.Open(filepath.Join(opt.Dir, "audit"), audit.Options{Now: opt.Now, Sanitize: s.red.String})
	if err != nil {
		return nil, fmt.Errorf("connectors: open audit log: %w", err)
	}
	s.vault, err = vault.Open(ctx, vault.Options{Dir: vaultDir, Order: picked, Audit: s.auditLog, Now: opt.Now})
	if err != nil {
		return nil, fmt.Errorf("connectors: open vault: %w", err)
	}
	if s.store, err = store.Open(opt.Dir); err != nil {
		_ = s.vault.Close()
		return nil, fmt.Errorf("connectors: open state: %w", err)
	}
	if s.auditLog != nil {
		if days := s.store.Snapshot().Settings.AuditRetentionDays; days != 0 {
			_ = s.auditLog.SetRetention(days)
		}
	}

	s.registry = registry.New()
	if err := aws.Register(s.registry); err != nil {
		return nil, err
	}
	if err := s.registry.Register(github.Manifest(github.EffectiveClientID(opt.Getenv))); err != nil {
		return nil, err
	}
	for _, m := range []manifest.Manifest{
		gitlab.Manifest(gitlab.EffectiveClientID(opt.Getenv)),
		azure.Manifest(azure.EffectiveClientID(opt.Getenv)),
		gcp.Manifest(), bitbucket.Manifest(), cloudflare.Manifest(), kubernetes.Manifest(),
	} {
		if err := s.registry.Register(m); err != nil {
			return nil, err
		}
	}

	// Session_Scope gates every agent call; nil clock means time.Now.
	s.scope = scope.New(s.store, s.registry, nil)
	s.broker = broker.New(broker.Config{
		AgentGate: s.scope,
		Opener:    s.vault, Audit: s.auditLog, Redactor: s.red, Inner: opt.Transport, Now: opt.Now,
		QueryValidators: map[string]func([]byte) bool{
			github.ConnectorID:     github.IsGraphQLRequestBody,
			gcp.ConnectorID:        gcp.IsTestIAMPermissionsBody,
			kubernetes.ConnectorID: kubernetes.IsSelfSubjectRulesReviewBody,
		},
	})
	runnerOpts := []collectors.Option{collectors.WithLogger(opt.Logger), collectors.WithGuard(s.red.Guard(redact.New()))}
	if opt.GapSink != nil {
		runnerOpts = append(runnerOpts, collectors.WithGapSink(opt.GapSink))
	}
	s.runner = collectors.New(opt.Engine, nil, runnerOpts...)
	s.sup = lifecycle.NewCollectorSupervisor(lifecycle.SupervisorConfig{
		Store: s.store, Runner: s.runner, Now: opt.Now, Redactor: s.red,
	})
	s.mgr = lifecycle.NewManager(lifecycle.Config{
		Store: s.store, Vault: s.vault, Audit: s.auditLog, Registry: s.registry, Clients: s.broker,
		Engine: opt.Engine, Runner: s.runner, Supervisor: s.sup, Redactor: s.red, Now: opt.Now,
		NewID: s.newConnectionID,
	})
	s.sup.Attach(s.mgr.Host())
	s.authCfgs = lifecycle.NewAuthConfigService(lifecycle.AuthConfigServiceConfig{
		Store: s.store, Vault: s.vault, Audit: s.auditLog, Registry: s.registry, Redactor: s.red, Now: opt.Now,
	})
	// Creates the defaults and resumes tombstoned deletes.
	if err := s.authCfgs.EnsureDefaults(); err != nil {
		return nil, fmt.Errorf("connectors: auth configs: %w", err)
	}

	s.awsProv, err = aws.NewProvider(aws.ProviderConfig{
		Broker: s.broker, Params: s.awsParams, Getenv: opt.Getenv, Register: s.red.Register,
	})
	if err != nil {
		return nil, err
	}
	s.githubPrv = github.NewProvider(github.ProviderConfig{Clients: s.broker, HostFor: s.githubHost})
	s.mgr.RegisterProvider(aws.ConnectorID, s.awsProv)
	s.mgr.RegisterProvider(github.ConnectorID, s.githubPrv)
	s.gitlabPrv = gitlab.NewProvider(gitlab.ProviderConfig{
		ClientID: gitlab.EffectiveClientID(opt.Getenv), Vault: s.vault, Redactor: s.red, HostFor: s.githubHost,
	})
	s.azurePrv = azure.NewProvider(azure.ProviderConfig{
		ClientID: azure.EffectiveClientID(opt.Getenv), Vault: s.vault, Redactor: s.red, Broker: s.broker,
	})
	s.gcpPrv = gcp.NewProvider(gcp.ProviderConfig{Opener: s.vault, Broker: s.broker})
	s.bitbktPrv = bitbucket.NewProvider()
	s.cfPrv = cloudflare.NewProvider()
	s.k8sPrv = kubernetes.NewProvider(kubernetes.ProviderConfig{
		ServerFor: s.kubernetesServer,
		HTTPClientFor: func(ref broker.ConnectionRef) *http.Client {
			return s.broker.HTTPClient(ref, policy.CallerCollector)
		},
	})
	s.mgr.RegisterProvider(gitlab.ConnectorID, s.gitlabPrv)
	s.mgr.RegisterProvider(azure.ConnectorID, s.azurePrv)
	s.mgr.RegisterProvider(gcp.ConnectorID, s.gcpPrv)
	s.mgr.RegisterProvider(bitbucket.ConnectorID, s.bitbktPrv)
	s.mgr.RegisterProvider(cloudflare.ConnectorID, s.cfPrv)
	s.mgr.RegisterProvider(kubernetes.ConnectorID, s.k8sPrv)
	s.device = s.newDeviceFlow()
	return s, nil
}

type nopLogger struct{}

func (nopLogger) Println(...any) {}

// Enabled reports whether the service was built (flag on).
func (s *Service) Enabled() bool { return s != nil && s.enabled }

// Start launches the audit pruning loop and a supervisor for every persisted
// ACTIVE connection. It is idempotent.
func (s *Service) Start(ctx context.Context) error {
	if !s.Enabled() {
		return nil
	}
	s.mu.Lock()
	if s.started || s.closed {
		s.mu.Unlock()
		return nil
	}
	s.started = true
	rctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.auditEnd = make(chan struct{})
	end := s.auditEnd
	s.mu.Unlock()

	go func() { defer close(end); s.auditLog.Run(rctx) }()
	s.reconcileMissingCredentials()
	for _, c := range s.store.Snapshot().Connections {
		if !c.Removed && lifecycle.Status(c.Status) == lifecycle.StatusActive {
			s.sup.Start(c)
		}
	}
	return nil
}

// reconcileMissingCredentials marks EXPIRED every non-removed GitHub
// Connection whose method stores a credential (pat, device) but whose vault
// slot is empty, for example after the vault was lost. It runs synchronously
// before any collector starts (Requirement 14.3). Connections already EXPIRED
// are left untouched.
func (s *Service) reconcileMissingCredentials() {
	for _, c := range s.store.Snapshot().Connections {
		if c.Removed || c.ConnectorID != github.ConnectorID ||
			(c.Method != github.MethodPAT && c.Method != github.MethodDevice) ||
			lifecycle.Status(c.Status) == lifecycle.StatusExpired {
			continue
		}
		if _, ok := s.vault.Meta(slotRef(c.ID, "credential")); ok {
			continue
		}
		_ = s.store.UpdateConnection(c.ID, func(x *store.Connection) error {
			x.Status = string(lifecycle.StatusExpired)
			x.StatusReason = "credential missing"
			return nil
		})
	}
}

// Close stops every supervisor (each bounded by lifecycle.StopTimeout), drops
// in-memory sessions, secrets and the cached Master_Key. It is idempotent.
func (s *Service) Close(ctx context.Context) error {
	if !s.Enabled() {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	cancel, end := s.cancel, s.auditEnd
	s.mu.Unlock()

	var errs []error
	// Cancels every poll first so no token becomes a Connection mid-shutdown.
	if s.device != nil {
		errs = append(errs, s.device.Close(ctx))
	}
	for _, c := range s.store.Snapshot().Connections {
		sctx, stop := context.WithTimeout(ctx, lifecycle.StopTimeout)
		if err := s.sup.Stop(sctx, c.ID); err != nil {
			errs = append(errs, err)
		}
		stop()
		s.awsProv.DropSession(c.ID)
	}
	if cancel != nil {
		cancel()
		<-end
	}
	s.runner.Stop()
	s.mu.Lock()
	for id, c := range s.params {
		c.release()
		delete(s.params, id)
	}
	s.mu.Unlock()
	errs = append(errs, s.vault.Close(), s.auditLog.Close())
	return errors.Join(errs...)
}

// Hooks for sibling packages (Session_Scope, the MCP endpoint, the HTTP layer).

// Broker returns the policy-enforcing broker (the only way to call a provider).
func (s *Service) Broker() *broker.Broker { return s.broker }

// Scope returns the Session_Scope service (the broker's agent gate).
func (s *Service) Scope() *scope.Service { return s.scope }

// Store returns the non-secret state store (connections, scopes, settings).
func (s *Service) Store() *store.Store { return s.store }

// Audit returns the audit log.
func (s *Service) Audit() audit.Log {
	if !s.Enabled() {
		return nil
	}
	return s.auditLog
}

// Redactor returns the secret redactor.
func (s *Service) Redactor() *redactor.Redactor { return s.red }

// Registry returns the connector registry.
func (s *Service) Registry() registry.Registry { return s.registry }

// Vault returns the vault, for master key rotation, forget-all and unlock.
func (s *Service) Vault() *vault.Store { return s.vault }

// Manager returns the lifecycle manager.
func (s *Service) Manager() *lifecycle.Manager { return s.mgr }

// Runner returns the dedicated collector runner.
func (s *Service) Runner() *collectors.Runner { return s.runner }

// AWSProvider returns the AWS provider (principal detection, setup helpers).
func (s *Service) AWSProvider() *aws.Provider { return s.awsProv }

// BrokerRef builds the broker reference of a live connection, for operations
// outside the lifecycle (agent reads, repository listing).
func (s *Service) BrokerRef(connectionID string) (broker.ConnectionRef, error) {
	if !s.Enabled() {
		return broker.ConnectionRef{}, ErrDisabled
	}
	conn, ok := s.Connection(connectionID)
	if !ok {
		return broker.ConnectionRef{}, lifecycle.NewError(lifecycle.CodeValidationFailed, "connection not found", s.red)
	}
	e, ok := s.registry.Get(conn.ConnectorID)
	if !ok {
		return broker.ConnectionRef{}, lifecycle.NewError(lifecycle.CodeValidationFailed, "unknown connector", s.red)
	}
	var d lifecycle.Descriptor
	switch conn.ConnectorID {
	case aws.ConnectorID:
		d = s.awsProv.Describe(conn)
	case github.ConnectorID:
		d = s.githubPrv.Describe(conn)
	case gitlab.ConnectorID:
		d = s.gitlabPrv.Describe(conn)
	case azure.ConnectorID:
		d = s.azurePrv.Describe(conn)
	case gcp.ConnectorID:
		d = s.gcpPrv.Describe(conn)
	case bitbucket.ConnectorID:
		d = s.bitbktPrv.Describe(conn)
	case cloudflare.ConnectorID:
		d = s.cfPrv.Describe(conn)
	case kubernetes.ConnectorID:
		d = s.k8sPrv.Describe(conn)
	default:
		return broker.ConnectionRef{}, lifecycle.NewError(lifecycle.CodeValidationFailed, "unknown connector", s.red)
	}
	pol, err := policy.Compile(e.Manifest, policy.Selection{Regions: conn.Selection.Regions, Host: d.Host})
	if err != nil {
		return broker.ConnectionRef{}, lifecycle.NewError(lifecycle.CodeValidationFailed, "connection policy is invalid", s.red)
	}
	return broker.ConnectionRef{
		ID: conn.ID, ConnectorID: conn.ConnectorID, Manifest: e.Manifest, Policy: pol, Auth: d.Auth,
		Credential: vault.Ref{Owner: vault.OwnerConnection, OwnerID: conn.ID, Slot: "credential"},
		APIHost:    d.APIHost, BasePath: d.BasePath, AllowPrivate: d.AllowPrivate,
		CACredential: caRef(conn.ID, d.CASlot),
	}, nil
}

// Status is the flag and vault probe returned by the status route.
type Status struct {
	Enabled    bool     `json:"enabled"`
	Offline    bool     `json:"offline"`
	KeySource  string   `json:"keySource"`
	Persistent bool     `json:"persistent"`
	Locked     bool     `json:"locked"`
	CanRotate  bool     `json:"-"`
	Warnings   []string `json:"warnings"`
	// Connections reports, per connection, whether the connector collects data
	// and the gaps its last run left.
	Connections []ConnectionStatus `json:"connections"`
}

// Collection values of ConnectionStatus.
const (
	CollectionAvailable    = "available"
	CollectionNotAvailable = "not_available"
)

// ConnectionStatus is the collection state of one connection.
type ConnectionStatus struct {
	ID          string      `json:"id"`
	ConnectorID string      `json:"connectorId"`
	Collection  string      `json:"collection"`
	Gaps        []store.Gap `json:"gaps"`
}

// connectOnly lists the connectors that connect but keep no collector.
var connectOnly = map[string]bool{gitlab.ConnectorID: true, bitbucket.ConnectorID: true, cloudflare.ConnectorID: true}

func (s *Service) connectionStatuses() []ConnectionStatus {
	out := []ConnectionStatus{}
	for _, c := range s.Connections() {
		cs := ConnectionStatus{ID: c.ID, ConnectorID: c.ConnectorID, Collection: CollectionAvailable, Gaps: []store.Gap{}}
		if connectOnly[c.ConnectorID] {
			cs.Collection = CollectionNotAvailable
			out = append(out, cs)
			continue
		}
		if c.LastSync != nil {
			cs.Gaps = append(cs.Gaps, c.LastSync.Gaps...)
		}
		if s.gapsFor != nil {
			if g, err := s.gapsFor(context.Background(), "connector:"+c.ConnectorID+":"+c.ID); err == nil {
				cs.Gaps = append([]store.Gap{}, g...)
			}
		}
		out = append(out, cs)
	}
	return out
}

// Status reports the key source, persistence and warnings. Offline is a
// client-side observation and is always false here.
func (s *Service) Status() Status {
	if !s.Enabled() {
		return Status{Warnings: []string{}, Connections: []ConnectionStatus{}}
	}
	v := s.vault.Status()
	st := Status{Enabled: true, KeySource: v.KeySource, Persistent: v.Persistent, CanRotate: v.CanRotate, Locked: v.Locked, Warnings: []string{}, Connections: s.connectionStatuses()}
	if v.Notice != "" {
		st.Warnings = append(st.Warnings, v.Notice)
	}
	switch v.KeySource {
	case keysource.NameKeyFile:
		st.Warnings = append(st.Warnings, keyFileWarning)
	case keysource.NamePassphrase:
		st.Warnings = append(st.Warnings, passphraseWarning)
	}
	return st
}

// Catalog lists the registered connector manifests, sorted by id.
func (s *Service) Catalog() []manifest.Manifest {
	if !s.Enabled() {
		return []manifest.Manifest{}
	}
	entries := s.registry.List()
	out := make([]manifest.Manifest, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Manifest)
	}
	return out
}

// Connections lists the non-removed connections, oldest first. The values are
// masked metadata: no credential is ever part of store.Connection.
func (s *Service) Connections() []store.Connection {
	out := []store.Connection{}
	if !s.Enabled() {
		return out
	}
	for _, c := range s.store.Snapshot().Connections {
		if !c.Removed {
			out = append(out, c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// Connection returns one non-removed connection.
func (s *Service) Connection(id string) (store.Connection, bool) {
	if !s.Enabled() {
		return store.Connection{}, false
	}
	c, ok := s.store.Connection(id)
	if !ok || c.Removed {
		return store.Connection{}, false
	}
	return c, true
}

// CreateInput is a new connection request. Credential and the external ID in
// Params are write-only.
type CreateInput struct {
	ConnectorID  string
	Alias        string
	AuthConfigID string // empty selects the connector's default Auth_Config
	Method       string
	// Params: roleArn, source (ambient|vault), externalId, host (GHES),
	// regions and repos (comma separated).
	Params map[string]string
	// Credential holds the method's fields: access_key_id, secret_access_key,
	// session_token (AWS keys) or token (GitHub).
	Credential  map[string]string
	IntervalSec int
}

// Create adds and verifies a connection. As in lifecycle.Manager.Create, a
// failed verification returns the stored (ERROR) connection with one typed error.
func (s *Service) Create(ctx context.Context, in CreateInput) (store.Connection, error) {
	if !s.Enabled() {
		return store.Connection{}, ErrDisabled
	}
	if _, ok := s.registry.Get(in.ConnectorID); !ok {
		return store.Connection{}, s.invalid("unknown connector", "connectorId")
	}
	acID := in.AuthConfigID
	if acID == "" {
		acID = lifecycle.DefaultAuthConfigID(in.ConnectorID)
	}
	ac, ok := s.authConfig(acID)
	if !ok || ac.ConnectorID != in.ConnectorID || ac.Deleting {
		return store.Connection{}, s.invalid("unknown auth config", "authConfigId")
	}
	p, sel, err := s.buildParams(in.ConnectorID, in.Method, in.Params, ac)
	if err != nil {
		return store.Connection{}, err
	}
	secret, err := credentialSecret(in.ConnectorID, in.Method, p.Source, in.Credential)
	if err != nil {
		return store.Connection{}, err
	}
	secret, ca, err := splitCredential(in.ConnectorID, secret, &p)
	if err != nil {
		return store.Connection{}, err
	}

	s.createMu.Lock()
	defer s.createMu.Unlock()
	id := randomID()
	s.nextID = id
	defer func() { s.nextID = "" }()

	cmin := lifecycle.CreateInput{
		ConnectorID: in.ConnectorID, Alias: in.Alias, AuthConfigID: acID, Method: in.Method,
		Selection: sel, IntervalSec: in.IntervalSec, Credential: lifecycle.CredentialInput{Secret: secret},
	}
	// The external ID and params are staged before the connection exists so the
	// verification (which needs them) can read them.
	staged, err := s.stageSlots(ctx, id, in.ConnectorID, p)
	if err != nil {
		clear(secret)
		return store.Connection{}, err
	}
	if len(ca) > 0 {
		if err := s.vault.Put(ctx, slotRef(id, slotCA), in.ConnectorID, ca, time.Time{}); err != nil {
			s.dropSlots(ctx, id, staged)
			clear(secret)
			return store.Connection{}, vaultError(err, s.red)
		}
	}
	if p.ExternalID != "" {
		cmin.ExternalIDRef = externalIDRef(id)
	}
	conn, err := s.mgr.Create(ctx, cmin)
	if c, ok := s.store.Connection(id); !ok || c.Removed {
		s.dropSlots(ctx, id, staged)
	}
	return conn, err
}

// stageSlots writes the params and external ID slots and primes the cache.
func (s *Service) stageSlots(ctx context.Context, id, connectorID string, p connParams) (staged bool, err error) {
	if p.ExternalID == "" && p.RoleARN == "" && p.Source == "" && p.Host == "" && p.Server == "" {
		return false, nil
	}
	if doc, _ := json.Marshal(p); string(doc) != "{}" {
		if err := s.vault.Put(ctx, slotRef(id, slotParams), connectorID, doc, time.Time{}); err != nil {
			return false, vaultError(err, s.red)
		}
	}
	if p.ExternalID != "" {
		if err := s.vault.Put(ctx, slotRef(id, slotExternalID), connectorID, []byte(p.ExternalID), time.Time{}); err != nil {
			s.dropSlots(ctx, id, true)
			return false, vaultError(err, s.red)
		}
	}
	s.setCache(id, p)
	return true, nil
}

func (s *Service) dropSlots(ctx context.Context, id string, _ bool) {
	_ = s.vault.Delete(ctx, slotRef(id, slotParams))
	_ = s.vault.Delete(ctx, slotRef(id, slotExternalID))
	_ = s.vault.Delete(ctx, slotRef(id, slotCA))
	s.mu.Lock()
	if c := s.params[id]; c != nil {
		c.release()
		delete(s.params, id)
	}
	s.mu.Unlock()
}

// Test verifies a connection without changing it.
func (s *Service) Test(ctx context.Context, id string) (lifecycle.TestReport, error) {
	if !s.Enabled() {
		return lifecycle.TestReport{}, ErrDisabled
	}
	return s.mgr.Test(ctx, id)
}

// Rotate replaces the credential after verifying the candidate.
func (s *Service) Rotate(ctx context.Context, id string, credential map[string]string) error {
	return s.replace(ctx, id, credential, s.mgr.Rotate)
}

// Reconnect replaces the credential of an ERROR or EXPIRED connection.
func (s *Service) Reconnect(ctx context.Context, id string, credential map[string]string) error {
	return s.replace(ctx, id, credential, s.mgr.Reconnect)
}

func (s *Service) replace(ctx context.Context, id string, cred map[string]string,
	fn func(context.Context, string, lifecycle.CredentialInput) error) error {
	if !s.Enabled() {
		return ErrDisabled
	}
	conn, ok := s.Connection(id)
	if !ok {
		return s.invalid("connection not found", "id")
	}
	p, err := s.paramsOf(ctx, conn)
	if err != nil {
		return err
	}
	secret, err := credentialSecret(conn.ConnectorID, conn.Method, p.Source, cred)
	if err != nil {
		return err
	}
	old := p
	secret, ca, err := splitCredential(conn.ConnectorID, secret, &p)
	if err != nil {
		return err
	}
	if len(ca) == 0 {
		return fn(ctx, id, lifecycle.CredentialInput{Secret: secret})
	}
	// The candidate is verified against the new CA and server, so they are
	// written first and restored when verification fails.
	oldCA := s.readSlot(ctx, id, slotCA)
	if err := s.writeKubernetesSlots(ctx, conn, p, ca); err != nil {
		return err
	}
	if err := fn(ctx, id, lifecycle.CredentialInput{Secret: secret}); err != nil {
		if oldCA != nil {
			_ = s.writeKubernetesSlots(ctx, conn, old, oldCA)
		}
		return err
	}
	return nil
}

// readSlot returns a copy of a vault slot, or nil when it is empty or unreadable.
func (s *Service) readSlot(ctx context.Context, id, slot string) []byte {
	var out []byte
	err := s.vault.Use(ctx, slotRef(id, slot), func(b []byte) error { out = append([]byte(nil), b...); return nil })
	if err != nil {
		return nil
	}
	return out
}

// writeKubernetesSlots stores the CA and the params (server) of a connection.
func (s *Service) writeKubernetesSlots(ctx context.Context, conn store.Connection, p connParams, ca []byte) error {
	if err := s.vault.Put(ctx, slotRef(conn.ID, slotCA), conn.ConnectorID, bytes.Clone(ca), time.Time{}); err != nil {
		return vaultError(err, s.red)
	}
	doc, _ := json.Marshal(p)
	if err := s.vault.Put(ctx, slotRef(conn.ID, slotParams), conn.ConnectorID, doc, time.Time{}); err != nil {
		return vaultError(err, s.red)
	}
	s.setCache(conn.ID, p)
	return nil
}

// splitCredential turns the encoded Kubernetes credential (canonical JSON from
// encodeKubernetesCredential) into the token for the credential slot and the
// CA for the "ca" slot, and records the server in p. Other connectors pass
// through unchanged with a nil CA.
func splitCredential(connectorID string, secret []byte, p *connParams) ([]byte, []byte, error) {
	if connectorID != kubernetes.ConnectorID {
		return secret, nil, nil
	}
	defer clear(secret)
	c, err := kubernetes.Normalize(kubernetes.MethodToken, secret)
	if err != nil {
		return nil, nil, err
	}
	p.Server = c.Server
	return []byte(c.Token), []byte(c.CA), nil
}

// Disconnect removes a connection, its credential and its extra vault slots.
func (s *Service) Disconnect(ctx context.Context, id string) error {
	if !s.Enabled() {
		return ErrDisabled
	}
	if err := s.mgr.Disconnect(ctx, id); err != nil {
		return err
	}
	s.awsProv.DropSession(id)
	s.dropSlots(ctx, id, true)
	s.scope.Invalidate()
	return nil
}

// Pause stops collection of an ACTIVE connection.
func (s *Service) Pause(ctx context.Context, id string) error {
	if !s.Enabled() {
		return ErrDisabled
	}
	return s.mgr.Pause(ctx, id)
}

// Resume restarts a PAUSED connection.
func (s *Service) Resume(ctx context.Context, id string) error {
	if !s.Enabled() {
		return ErrDisabled
	}
	return s.mgr.Resume(ctx, id)
}

// SyncNow runs one collection now; a concurrent run yields run_in_progress.
func (s *Service) SyncNow(ctx context.Context, id string) error {
	if !s.Enabled() {
		return ErrDisabled
	}
	return s.mgr.SyncNow(ctx, id)
}

// Update changes alias, interval, live reads, rotation interval or selection.
func (s *Service) Update(ctx context.Context, id string, p lifecycle.ConnectionPatch) error {
	if !s.Enabled() {
		return ErrDisabled
	}
	if p.Selection != nil {
		if conn, ok := s.Connection(id); ok && conn.ConnectorID == github.ConnectorID {
			if err := github.ValidateSelection(p.Selection.Repos); err != nil {
				return err
			}
		}
	}
	err := s.mgr.Update(ctx, id, p)
	// A live-read toggle or selection change must reach the agent gate at once.
	s.scope.Invalidate()
	return err
}

// AuthConfigs lists a connector's Auth_Configs (never any secret).
func (s *Service) AuthConfigs(connectorID string) ([]store.AuthConfig, error) {
	if !s.Enabled() {
		return nil, ErrDisabled
	}
	return s.authCfgs.List(connectorID)
}

// CreateAuthConfig stores a custom Auth_Config; app secrets go to the vault.
func (s *Service) CreateAuthConfig(ctx context.Context, in lifecycle.CreateAuthConfigInput) (store.AuthConfig, error) {
	if !s.Enabled() {
		return store.AuthConfig{}, ErrDisabled
	}
	return s.authCfgs.Create(ctx, in)
}

// DeleteAuthConfig deletes a custom Auth_Config that no connection uses.
func (s *Service) DeleteAuthConfig(ctx context.Context, id string) error {
	if !s.Enabled() {
		return ErrDisabled
	}
	return s.authCfgs.Delete(ctx, id)
}

// ListAudit returns one page of audit entries, newest first. connectionID may
// be empty for all connections. A limit outside 1..DefaultPageSize is clamped.
func (s *Service) ListAudit(connectionID, cursor string, limit int) (audit.Page, error) {
	if !s.Enabled() {
		return audit.Page{}, ErrDisabled
	}
	if limit <= 0 || limit > DefaultPageSize {
		limit = DefaultPageSize
	}
	return s.auditLog.List(connectionID, cursor, limit)
}

// ---- provider parameter resolution ----

var (
	roleARNRe    = regexp.MustCompile(`^arn:aws[a-z-]*:iam::\d{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$`)
	externalIDRe = regexp.MustCompile(`^[A-Za-z0-9+=,.@:/_-]{32,1000}$`)
)

// buildParams validates the create params for the connector and method.
func (s *Service) buildParams(connectorID, method string, in map[string]string, ac store.AuthConfig) (connParams, store.Selection, error) {
	var p connParams
	sel := store.Selection{Regions: []string{}, Repos: []string{}}
	if v := split(in["regions"]); len(v) > 0 {
		sel.Regions = v
	}
	if v := split(in["repos"]); len(v) > 0 {
		sel.Repos = v
	}
	if v := split(in["items"]); len(v) > 0 {
		sel.Items = v
	}
	switch connectorID {
	case aws.ConnectorID:
		switch method {
		case aws.MethodStaticKeys:
		case aws.MethodAssumeRole:
			p.RoleARN = first(in["roleArn"], ac.Settings["roleArn"])
			p.Source = first(in["source"], ac.Settings["source"], aws.SourceAmbient)
			if !roleARNRe.MatchString(p.RoleARN) {
				return p, sel, s.invalid("role ARN is invalid", "params.roleArn")
			}
			if p.Source != aws.SourceAmbient && p.Source != aws.SourceVault {
				return p, sel, s.invalid("source must be ambient or vault", "params.source")
			}
			p.ExternalID = in["externalId"]
			if p.ExternalID == "" {
				id, err := aws.GenerateExternalID()
				if err != nil {
					return p, sel, lifecycle.NewError(lifecycle.CodeValidationFailed, "could not generate an external id", nil)
				}
				p.ExternalID = id
			} else if !externalIDRe.MatchString(p.ExternalID) {
				return p, sel, s.invalid("external id is invalid", "params.externalId")
			}
		default:
			return p, sel, s.invalid("unsupported auth method", "method")
		}
	case gitlab.ConnectorID:
		if method != gitlab.MethodPAT {
			return p, sel, s.invalid("unsupported auth method", "method")
		}
		if h := in["host"]; h != "" {
			if err := gitlab.ValidateHost(h); err != nil {
				return p, sel, s.invalid("GitLab host is invalid", "params.host")
			}
			p.Host = h
		}
	case azure.ConnectorID:
		// The service-principal method is declared but disabled in the manifest.
		return p, sel, s.invalid("unsupported auth method", "method")
	case gcp.ConnectorID:
		if method != gcp.MethodServiceAccount {
			return p, sel, s.invalid("unsupported auth method", "method")
		}
	case bitbucket.ConnectorID:
		if method != bitbucket.MethodAPIToken {
			return p, sel, s.invalid("unsupported auth method", "method")
		}
	case cloudflare.ConnectorID:
		if method != cloudflare.MethodToken {
			return p, sel, s.invalid("unsupported auth method", "method")
		}
	case kubernetes.ConnectorID:
		if method != kubernetes.MethodToken && method != kubernetes.MethodKubeconfig {
			return p, sel, s.invalid("unsupported auth method", "method")
		}
	case github.ConnectorID:
		if method != github.MethodPAT {
			return p, sel, s.invalid("unsupported auth method", "method")
		}
		if h := in["host"]; h != "" {
			if err := github.ValidateHost(h); err != nil {
				return p, sel, s.invalid("enterprise host is invalid", "params.host")
			}
			p.Host = h
		}
		if len(sel.Repos) > 0 {
			if err := github.ValidateSelection(sel.Repos); err != nil {
				return p, sel, err
			}
		}
	}
	return p, sel, nil
}

// credentialEncoder turns the pasted credential fields of one connector into
// the secret bytes its provider expects. Errors name fields, never values.
type credentialEncoder func(method, source string, f map[string]string) ([]byte, error)

// credentialEncoders maps connector IDs to their encoders. Provider tasks add
// an entry per connector.
var credentialEncoders = map[string]credentialEncoder{
	github.ConnectorID: encodeGithubCredential,
	aws.ConnectorID:    encodeAWSCredential,

	gitlab.ConnectorID:     encodeTokenCredential,
	cloudflare.ConnectorID: encodeTokenCredential,
	azure.ConnectorID:      encodeAzureCredential,
	gcp.ConnectorID:        encodeGCPCredential,
	bitbucket.ConnectorID:  encodeBitbucketCredential,
	kubernetes.ConnectorID: encodeKubernetesCredential,
}

// missingFields returns a validation error naming each blank credential field.
func missingFields(f map[string]string, names ...string) error {
	var bad []string
	for _, n := range names {
		if strings.TrimSpace(f[n]) == "" {
			bad = append(bad, "credential."+n)
		}
	}
	if len(bad) == 0 {
		return nil
	}
	return lifecycle.NewError(lifecycle.CodeValidationFailed, "required: "+strings.Join(bad, ", "), nil).WithOffenders(bad, nil)
}

// credentialSecret encodes the credential fields as the provider expects them.
// Errors name fields, never values.
func credentialSecret(connectorID, method, source string, f map[string]string) ([]byte, error) {
	enc, ok := credentialEncoders[connectorID]
	if !ok {
		return nil, lifecycle.NewError(lifecycle.CodeValidationFailed, "unknown connector", nil)
	}
	return enc(method, source, f)
}
func encodeGithubCredential(_, _ string, f map[string]string) ([]byte, error) {
	if err := missingFields(f, "token"); err != nil {
		return nil, err
	}
	return []byte(f["token"]), nil
}
func encodeTokenCredential(_, _ string, f map[string]string) ([]byte, error) {
	if err := missingFields(f, "token"); err != nil {
		return nil, err
	}
	return []byte(f["token"]), nil
}
func encodeAzureCredential(_, _ string, f map[string]string) ([]byte, error) {
	if err := missingFields(f, "tenant_id", "client_id", "client_secret"); err != nil {
		return nil, err
	}
	return azure.EncodeServicePrincipal(azure.ServicePrincipal{
		TenantID: f["tenant_id"], ClientID: f["client_id"], ClientSecret: f["client_secret"],
	}), nil
}
func encodeGCPCredential(_, _ string, f map[string]string) ([]byte, error) {
	if err := missingFields(f, "key_json"); err != nil {
		return nil, err
	}
	return []byte(f["key_json"]), nil
}
func encodeBitbucketCredential(_, _ string, f map[string]string) ([]byte, error) {
	if err := missingFields(f, "email", "api_token"); err != nil {
		return nil, err
	}
	return []byte(strings.TrimSpace(f["email"]) + "\n" + f["api_token"]), nil
}

// encodeKubernetesCredential validates the pasted fields (server, token, ca or
// kubeconfig) and returns the canonical JSON; splitCredential separates it
// into the token, the CA and the server.
func encodeKubernetesCredential(method, _ string, f map[string]string) ([]byte, error) {
	var raw []byte
	switch method {
	case kubernetes.MethodKubeconfig:
		if err := missingFields(f, "kubeconfig"); err != nil {
			return nil, err
		}
		raw = []byte(f["kubeconfig"])
	default:
		if err := missingFields(f, "server", "token", "ca"); err != nil {
			return nil, err
		}
		raw, _ = json.Marshal(kubernetes.Credential{Server: f["server"], Token: f["token"], CA: f["ca"]})
	}
	c, err := kubernetes.Normalize(method, raw)
	clear(raw)
	if err != nil {
		return nil, err
	}
	return json.Marshal(c)
}
func encodeAWSCredential(method, source string, f map[string]string) ([]byte, error) {
	if method == aws.MethodAssumeRole && source == aws.SourceAmbient {
		// The ambient source needs no secret; the vault requires a non-empty
		// slot, so a marker is stored.
		return []byte(`{"source":"ambient"}`), nil
	}
	if err := missingFields(f, "access_key_id", "secret_access_key"); err != nil {
		return nil, err
	}
	doc := map[string]string{"access_key_id": f["access_key_id"], "secret_access_key": f["secret_access_key"]}
	if f["session_token"] != "" {
		doc["session_token"] = f["session_token"]
	}
	return json.Marshal(doc)
}
func (s *Service) awsParams(ctx context.Context, conn store.Connection) (aws.Params, error) {
	p, err := s.paramsOf(ctx, conn)
	if err != nil {
		return aws.Params{}, err
	}
	return aws.Params{RoleARN: p.RoleARN, ExternalID: p.ExternalID, Source: p.Source}, nil
}

// githubHost never fails: an unreadable host falls back to github.com, which
// the provider also does for an invalid host.
func (s *Service) githubHost(conn store.Connection) string {
	p, err := s.paramsOf(context.Background(), conn)
	if err != nil {
		return ""
	}
	return p.Host
}

// kubernetesServer returns the persisted API server URL of a connection.
func (s *Service) kubernetesServer(conn store.Connection) string {
	p, err := s.paramsOf(context.Background(), conn)
	if err != nil {
		return ""
	}
	return p.Server
}

// paramsOf resolves a connection's params: the vault params slot, then the
// Auth_Config settings. The external ID is registered with the redactor for as
// long as the connection exists.
func (s *Service) paramsOf(ctx context.Context, conn store.Connection) (connParams, error) {
	s.mu.Lock()
	if c := s.params[conn.ID]; c != nil {
		p := c.p
		s.mu.Unlock()
		return p, nil
	}
	s.mu.Unlock()

	var p connParams
	err := s.vault.Use(ctx, slotRef(conn.ID, slotParams), func(b []byte) error { return json.Unmarshal(b, &p) })
	if err != nil && !errors.Is(err, vault.ErrNotFound) {
		return connParams{}, vaultError(err, s.red)
	}
	if conn.ExternalIDRef != "" {
		if conn.ExternalIDRef != externalIDRef(conn.ID) {
			return connParams{}, s.invalid("invalid external id reference", "externalIdRef")
		}
		err := s.vault.Use(ctx, slotRef(conn.ID, slotExternalID), func(b []byte) error { p.ExternalID = string(b); return nil })
		if err != nil {
			return connParams{}, vaultError(err, s.red)
		}
	}
	if conn.ConnectorID == aws.ConnectorID && conn.Method == aws.MethodAssumeRole {
		if ac, ok := s.authConfig(conn.AuthConfigID); ok {
			p.RoleARN = first(p.RoleARN, ac.Settings["roleArn"])
			p.Source = first(p.Source, ac.Settings["source"])
		}
		p.Source = first(p.Source, aws.SourceAmbient)
	}
	s.setCache(conn.ID, p)
	return p, nil
}

func (s *Service) setCache(id string, p connParams) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	if old := s.params[id]; old != nil {
		old.release()
	}
	release := func() {}
	if p.ExternalID != "" {
		release = s.red.Register([]byte(p.ExternalID))
	}
	s.params[id] = &cachedParams{p: p, release: release}
}

func (s *Service) authConfig(id string) (store.AuthConfig, bool) {
	for _, a := range s.store.Snapshot().AuthConfigs {
		if a.ID == id {
			return a, true
		}
	}
	return store.AuthConfig{}, false
}

// newConnectionID hands the manager the id Create pre-allocated for staging
// the connection's extra vault slots. Create holds createMu throughout.
func (s *Service) newConnectionID() string {
	if s.nextID != "" {
		return s.nextID
	}
	return randomID()
}

func (s *Service) invalid(msg string, fields ...string) error {
	return lifecycle.NewError(lifecycle.CodeValidationFailed, msg, s.red).WithOffenders(fields, s.red)
}

func vaultError(err error, r lifecycle.Redactor) error {
	switch {
	case errors.Is(err, vault.ErrAuditFailed):
		return lifecycle.NewError(lifecycle.CodeAuditFailed, "audit log is unavailable", r)
	case errors.Is(err, vault.ErrDecrypt):
		return lifecycle.NewError(lifecycle.CodeDecryptFailed, "credential cannot be decrypted", r)
	}
	return lifecycle.NewError(lifecycle.CodeVaultUnavailable, "credential is unavailable", r)
}

func isKeyMismatch(err error) bool         { return errors.Is(err, vault.ErrKeyMismatch) }
func isRotationUnsupported(err error) bool { return errors.Is(err, vault.ErrRotationUnsupported) }

func randomID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "conn_" + hex.EncodeToString(b)
}

func slotRef(id, slot string) vault.Ref {
	return vault.Ref{Owner: vault.OwnerConnection, OwnerID: id, Slot: slot}
}

func externalIDRef(id string) string { return "vault:" + id + "/" + slotExternalID }

func first(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

func split(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// caRef is the vault slot of a connection's CA bundle, or the zero Ref.
func caRef(connectionID, slot string) vault.Ref {
	if slot == "" {
		return vault.Ref{}
	}
	return vault.Ref{Owner: vault.OwnerConnection, OwnerID: connectionID, Slot: slot}
}
