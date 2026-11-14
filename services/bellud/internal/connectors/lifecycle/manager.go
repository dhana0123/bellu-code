package lifecycle

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/audit"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/policy"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/redactor"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/registry"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/vault"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

const (
	// VerifyTimeout bounds one identity plus permission verification.
	VerifyTimeout = 30 * time.Second
	// StopTimeout bounds stopping a connection's collector.
	StopTimeout = 5 * time.Second

	// MethodDevice is the auth method of a GitHub App user token obtained
	// through the device authorization flow. Its verification failures drop the
	// stored credential.
	MethodDevice = "device"

	slotCredential = "credential"
	slotCandidate  = "candidate"
	slotRefresh    = "refresh"
)

// ErrRunInProgress is returned by Supervisor.SyncNow when a run is active.
var ErrRunInProgress = errors.New("run_in_progress")

// Supervisor starts and stops the collector of an ACTIVE connection (task 5.5).
type Supervisor interface {
	Start(conn store.Connection)
	// Stop returns once the collector has stopped or ctx expires. Stopping an
	// unknown id is not an error.
	Stop(ctx context.Context, id string) error
	SyncNow(ctx context.Context, id string) error
}

// Clients builds policy-enforcing HTTP clients (satisfied by *broker.Broker).
type Clients interface {
	HTTPClient(ref broker.ConnectionRef, caller string) *http.Client
}

// Forgetter drops a collector's status entity (satisfied by *collectors.Runner).
type Forgetter interface{ Forget(name string) }

// Vault is the vault surface the manager uses.
type Vault interface {
	Put(ctx context.Context, ref vault.Ref, connectorID string, secret []byte, exp time.Time) error
	Delete(ctx context.Context, ref vault.Ref) error
	// Use exposes the plaintext only inside fn (vault.Opener).
	Use(ctx context.Context, ref vault.Ref, fn func(secret []byte) error) error
}

// Config wires a Manager.
type Config struct {
	Store      *store.Store
	Vault      Vault
	Audit      audit.Log
	Registry   registry.Registry
	Clients    Clients
	Engine     graph.Engine
	Runner     Forgetter
	Supervisor Supervisor // optional until task 5.5
	Redactor   *redactor.Redactor
	Now        func() time.Time
	NewID      func() string
}

// Manager runs connection lifecycle operations. It is safe for concurrent use.
type Manager struct {
	cfg       Config
	red       *redactor.Redactor
	now       func() time.Time
	mu        sync.Mutex // serializes status changes
	providers map[string]Provider
}

// NewManager returns a Manager with no providers registered.
func NewManager(cfg Config) *Manager {
	m := &Manager{cfg: cfg, red: cfg.Redactor, now: cfg.Now, providers: map[string]Provider{}}
	if m.red == nil {
		m.red = redactor.New()
	}
	if m.now == nil {
		m.now = time.Now
	}
	if cfg.NewID == nil {
		m.cfg.NewID = newID
	}
	return m
}

// RegisterProvider registers the provider for a connector id.
func (m *Manager) RegisterProvider(connectorID string, p Provider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.providers[connectorID] = p
}

// CollectorName is the Runner name of a connection's collector.
func CollectorName(connectorID, connectionID string) string {
	return "connector:" + connectorID + ":" + connectionID
}

// CreateInput is a new connection request.
type CreateInput struct {
	ConnectorID   string
	Alias         string
	AuthConfigID  string
	Method        string
	Selection     store.Selection
	IntervalSec   int // 0 uses the default setting
	ExternalIDRef string
	Credential    CredentialInput
}

// CredentialInput carries a secret. The manager zeroes Secret when done.
type CredentialInput struct {
	Secret    []byte
	ExpiresAt time.Time
	// RefreshToken is stored in its own vault slot beside the credential. Empty
	// for credentials that cannot be renewed.
	RefreshToken []byte
}

// TestReport is the outcome of a successful verification.
type TestReport struct {
	AccountLabel string
	Permission   string
	CheckedAt    time.Time
}

// ConnectionPatch lists optional connection settings to change.
type ConnectionPatch struct {
	Alias                *string
	IntervalSec          *int
	AllowAgentLiveReads  *bool
	RotationIntervalDays *int
	Selection            *store.Selection
}

type verified struct {
	identity Identity
	check    string
}

// Create adds a connection: INITIATED, audit, vault.Put, VERIFYING, identity
// and permission checks, then ACTIVE or ERROR. Verification failures return
// the stored connection together with exactly one typed error.
func (m *Manager) Create(ctx context.Context, in CreateInput) (store.Connection, error) {
	defer clear(in.Credential.Secret)
	if _, ok := m.provider(in.ConnectorID); !ok {
		return store.Connection{}, NewError(CodeValidationFailed, "unknown connector", m.red)
	}
	snap := m.cfg.Store.Snapshot()
	if err := store.ValidateAlias(in.Alias, in.ConnectorID, "", snap.Connections); err != nil {
		return store.Connection{}, aliasError(in.Alias, err, m.red)
	}
	if slices.ContainsFunc(snap.AuthConfigs, func(a store.AuthConfig) bool { return a.ID == in.AuthConfigID && a.Deleting }) {
		return store.Connection{}, NewError(CodeValidationFailed, "auth config is being deleted", m.red)
	}
	if len(in.Credential.Secret) == 0 {
		return store.Connection{}, NewError(CodeValidationFailed, "credential is required", m.red)
	}
	method := in.Method
	if method == "" {
		method = createMethod(snap, in.AuthConfigID)
	}
	if err := m.validateCredential(in.ConnectorID, method, in.Credential.Secret); err != nil {
		return store.Connection{}, err
	}
	release := m.red.Register(in.Credential.Secret)
	defer release()

	conn := store.NewConnection(m.cfg.NewID(), in.ConnectorID, in.Alias, snap.Settings, m.now())
	conn.AuthConfigID, conn.Method, conn.ExternalIDRef = in.AuthConfigID, in.Method, in.ExternalIDRef
	conn.Status = string(StatusInitiated)
	if in.IntervalSec != 0 {
		conn.IntervalSec = in.IntervalSec
	}
	if in.Selection.Regions != nil || in.Selection.Repos != nil {
		conn.Selection = in.Selection
	}
	// Audit comes first: a failure leaves no connection and no credential.
	if err := m.record(ctx, audit.EventConnect, audit.OutcomeSuccess, conn, map[string]string{"to": string(StatusInitiated)}); err != nil {
		return store.Connection{}, err
	}
	if err := m.cfg.Store.AddConnection(conn); err != nil {
		return store.Connection{}, storeError(err, m.red)
	}
	cred := credRef(conn.ID)
	exp := in.Credential.ExpiresAt
	if err := m.cfg.Vault.Put(ctx, cred, conn.ConnectorID, bytes.Clone(in.Credential.Secret), exp); err != nil {
		m.tombstone(conn.ID)
		return store.Connection{}, m.classify(err)
	}
	if len(in.Credential.RefreshToken) > 0 {
		if err := m.putRefresh(ctx, conn, in.Credential); err != nil {
			m.dropCredential(ctx, cred)
			m.tombstone(conn.ID)
			return store.Connection{}, err
		}
	}
	now := m.now().UTC()
	conn = m.patch(conn.ID, func(c *store.Connection) {
		c.CredentialCreatedAt, c.CredentialExpiresAt = &now, timePtr(exp)
	})
	if _, err := m.transition(ctx, conn.ID, StatusVerifying, "", true); err != nil {
		m.dropCredential(ctx, cred)
		m.tombstone(conn.ID)
		return store.Connection{}, err
	}
	return m.finishVerification(ctx, conn.ID, cred, true, in.Method == MethodDevice)
}

// finishVerification verifies the stored credential and moves a VERIFYING
// connection to ACTIVE or ERROR.
//
// With dropOnFailure (method device) any verification failure deletes the
// stored credential, so no token outlives a failed sign-in.
func (m *Manager) finishVerification(ctx context.Context, id string, cred vault.Ref, dropOnExcess, dropOnFailure bool) (store.Connection, error) {
	conn, _ := m.cfg.Store.Connection(id)
	v, verr := m.verify(ctx, conn, cred)
	if verr != nil {
		check := ""
		if verr.Code == CodeExcessPermission {
			check = store.PermissionExcess
		}
		if dropOnFailure || (check != "" && dropOnExcess) {
			m.dropCredential(ctx, cred)
			m.dropCredential(ctx, refRef(id))
		}
		m.patch(id, func(c *store.Connection) {
			if check != "" {
				c.PermissionCheck = check
			}
		})
		out, _ := m.transition(ctx, id, StatusError, verr.Error(), false)
		return out, verr
	}
	m.applyVerified(id, v)
	out, err := m.transition(ctx, id, StatusActive, "", false)
	if err != nil {
		return out, err
	}
	return out, nil
}

// Test verifies identity and permissions of a connection. It never changes the
// connection or its stored credential; a failure returns one typed error.
func (m *Manager) Test(ctx context.Context, id string) (TestReport, error) {
	conn, err := m.live(id)
	if err != nil {
		return TestReport{}, err
	}
	v, verr := m.verify(ctx, conn, credRef(id))
	if verr != nil {
		_ = m.record(ctx, audit.EventTest, audit.OutcomeFailure, conn, map[string]string{"code": string(verr.Code)})
		return TestReport{}, verr
	}
	if err := m.record(ctx, audit.EventTest, audit.OutcomeSuccess, conn, nil); err != nil {
		return TestReport{}, err
	}
	return TestReport{AccountLabel: v.identity.AccountLabel, Permission: v.check, CheckedAt: m.now().UTC()}, nil
}

// Reconnect replaces the credential of an ERROR or EXPIRED connection. The
// connection id, alias and source tag are kept.
func (m *Manager) Reconnect(ctx context.Context, id string, in CredentialInput) error {
	defer clear(in.Secret)
	conn, err := m.live(id)
	if err != nil {
		return err
	}
	if len(in.Secret) == 0 {
		return NewError(CodeValidationFailed, "credential is required", m.red)
	}
	if err := m.validateCredential(conn.ConnectorID, conn.Method, in.Secret); err != nil {
		return err
	}
	release := m.red.Register(in.Secret)
	defer release()
	if _, err := m.transition(ctx, id, StatusVerifying, "", true); err != nil {
		return err
	}
	v, verr := m.stage(ctx, conn, in)
	if verr != nil {
		m.markFailed(ctx, id, verr)
		return verr
	}
	if err := m.record(ctx, audit.EventConnect, audit.OutcomeSuccess, conn, map[string]string{"reconnect": "true"}); err != nil {
		m.dropCredential(ctx, candRef(id))
		m.markFailed(ctx, id, nil)
		return err
	}
	if err := m.commit(ctx, conn, in); err != nil {
		m.markFailed(ctx, id, nil)
		return err
	}
	m.applyVerified(id, v)
	_, err = m.transition(ctx, id, StatusActive, "", false)
	return err
}

// ReconnectVerified replaces the credential of an EXPIRED or ERROR connection
// with a device user token. The candidate is staged and verified first, like
// Rotate: on any failure nothing changes. On success it audits, commits the
// candidate, sets Method to device and the new expiry, and moves the
// connection to ACTIVE through VERIFYING. Id, alias and source tag are kept.
func (m *Manager) ReconnectVerified(ctx context.Context, id string, in CredentialInput) error {
	defer clear(in.Secret)
	conn, err := m.live(id)
	if err != nil {
		return err
	}
	if st := Status(conn.Status); st != StatusExpired && st != StatusError {
		return NewError(CodeTransitionRejected, "connection is not expired or in error", m.red)
	}
	if len(in.Secret) == 0 {
		return NewError(CodeValidationFailed, "credential is required", m.red)
	}
	if err := m.validateCredential(conn.ConnectorID, MethodDevice, in.Secret); err != nil {
		return err
	}
	release := m.red.Register(in.Secret)
	defer release()
	// The candidate is verified as a device token whatever the old method was.
	vconn := conn
	vconn.Method = MethodDevice
	v, verr := m.stage(ctx, vconn, in)
	if verr != nil {
		_ = m.record(ctx, audit.EventConnect, audit.OutcomeFailure, conn, map[string]string{"reconnect": "true", "code": string(verr.Code)})
		return verr
	}
	if err := m.record(ctx, audit.EventConnect, audit.OutcomeSuccess, conn, map[string]string{"reconnect": "true", "method": MethodDevice}); err != nil {
		m.dropCredential(ctx, candRef(id))
		return err
	}
	if err := m.commit(ctx, conn, in); err != nil {
		return err
	}
	m.patch(id, func(c *store.Connection) { c.Method = MethodDevice })
	if _, err := m.transition(ctx, id, StatusVerifying, "", true); err != nil {
		return err
	}
	m.applyVerified(id, v)
	_, err = m.transition(ctx, id, StatusActive, "", false)
	return err
}

// Rotate verifies the candidate credential first and swaps it in only if the
// identity and permission checks both pass. The status does not change.
func (m *Manager) Rotate(ctx context.Context, id string, in CredentialInput) error {
	defer clear(in.Secret)
	conn, err := m.live(id)
	if err != nil {
		return err
	}
	if len(in.Secret) == 0 {
		return NewError(CodeValidationFailed, "credential is required", m.red)
	}
	if err := m.validateCredential(conn.ConnectorID, conn.Method, in.Secret); err != nil {
		return err
	}
	release := m.red.Register(in.Secret)
	defer release()
	v, verr := m.stage(ctx, conn, in)
	if verr != nil {
		_ = m.record(ctx, audit.EventRotate, audit.OutcomeFailure, conn, map[string]string{"code": string(verr.Code)})
		return verr
	}
	if err := m.record(ctx, audit.EventRotate, audit.OutcomeSuccess, conn, nil); err != nil {
		m.dropCredential(ctx, candRef(id))
		return err
	}
	if err := m.commit(ctx, conn, in); err != nil {
		return err
	}
	m.applyVerified(id, v)
	return nil
}

// Pause stops collection: ACTIVE to PAUSED.
func (m *Manager) Pause(ctx context.Context, id string) error {
	_, err := m.transition(ctx, id, StatusPaused, "", false)
	return err
}

// Resume restarts collection: PAUSED to ACTIVE.
func (m *Manager) Resume(ctx context.Context, id string) error {
	_, err := m.transition(ctx, id, StatusActive, "", false)
	return err
}

// SyncNow runs one collection immediately for an ACTIVE connection.
func (m *Manager) SyncNow(ctx context.Context, id string) error {
	conn, err := m.live(id)
	if err != nil {
		return err
	}
	if Status(conn.Status) != StatusActive {
		return NewError(CodeTransitionRejected, "connection is not active", m.red)
	}
	if m.cfg.Supervisor == nil {
		return NewError(CodeValidationFailed, "collection is not available", m.red)
	}
	err = m.cfg.Supervisor.SyncNow(ctx, id)
	if errors.Is(err, ErrRunInProgress) {
		return NewError(CodeRunInProgress, "a run is already in progress", m.red)
	}
	return err
}

// Update changes alias, interval, live reads, rotation interval or selection.
// A rejected change keeps the previous values.
func (m *Manager) Update(ctx context.Context, id string, p ConnectionPatch) error {
	conn, err := m.live(id)
	if err != nil {
		return err
	}
	all := m.cfg.Store.Snapshot().Connections // outside UpdateConnection: the store lock is not reentrant
	err = m.cfg.Store.UpdateConnection(id, func(c *store.Connection) error {
		if p.Alias != nil {
			if err := store.ValidateAlias(*p.Alias, c.ConnectorID, c.ID, all); err != nil {
				return aliasError(*p.Alias, err, m.red)
			}
			c.Alias = *p.Alias
		}
		if p.IntervalSec != nil {
			if err := store.ValidateInterval(*p.IntervalSec); err != nil {
				return err
			}
			c.IntervalSec = *p.IntervalSec
		}
		if p.RotationIntervalDays != nil {
			if err := store.ValidateRotationDays(*p.RotationIntervalDays); err != nil {
				return err
			}
			c.RotationIntervalDays = *p.RotationIntervalDays
		}
		if p.AllowAgentLiveReads != nil {
			c.AllowAgentLiveReads = *p.AllowAgentLiveReads
		}
		if p.Selection != nil {
			c.Selection = *p.Selection
		}
		return nil
	})
	if err != nil {
		return storeError(err, m.red)
	}
	// New interval or selection apply to the running collector.
	if m.cfg.Supervisor != nil && Status(conn.Status) == StatusActive && (p.IntervalSec != nil || p.Selection != nil) {
		sctx, cancel := context.WithTimeout(ctx, StopTimeout)
		defer cancel()
		_ = m.cfg.Supervisor.Stop(sctx, id)
		updated, _ := m.cfg.Store.Connection(id)
		m.cfg.Supervisor.Start(updated)
	}
	return nil
}

// Disconnect stops collectors (at most 5 s), deletes the credential, applies an
// empty full observation for the collector, forgets its status entity and marks
// the connection removed. When the vault delete fails the state is kept and the
// collectors stay stopped.
func (m *Manager) Disconnect(ctx context.Context, id string) error {
	conn, err := m.live(id)
	if err != nil {
		return err
	}
	if m.cfg.Supervisor != nil {
		sctx, cancel := context.WithTimeout(ctx, StopTimeout)
		_ = m.cfg.Supervisor.Stop(sctx, id)
		cancel()
	}
	for _, ref := range []vault.Ref{credRef(id), candRef(id), refRef(id)} {
		if err := m.cfg.Vault.Delete(ctx, ref); err != nil {
			_ = m.record(ctx, audit.EventDisconnect, audit.OutcomeFailure, conn, map[string]string{"step": "credential_delete"})
			return m.classify(err)
		}
	}
	name := CollectorName(conn.ConnectorID, id)
	if _, err := m.cfg.Engine.Ingest().Apply(ctx, batch.Batch{Collector: name}); err != nil {
		_ = m.record(ctx, audit.EventDisconnect, audit.OutcomeFailure, conn, map[string]string{"step": "graph_clear"})
		return NewError(CodeValidationFailed, "could not remove graph data", m.red)
	}
	if m.cfg.Runner != nil {
		m.cfg.Runner.Forget(name)
	}
	m.tombstone(id)
	// Best effort: the credential is already gone, so an audit outage must not
	// leave a half-removed connection.
	_ = m.record(ctx, audit.EventDisconnect, audit.OutcomeSuccess, conn, nil)
	return nil
}

// transition moves a connection to a new status, auditing the change or the
// rejection. When strict, an audit failure aborts the change; moves into ERROR
// and EXPIRED are never blocked by the audit log.
func (m *Manager) transition(ctx context.Context, id string, to Status, reason string, strict bool) (store.Connection, error) {
	m.mu.Lock()
	conn, ok := m.cfg.Store.Connection(id)
	if !ok || conn.Removed {
		m.mu.Unlock()
		return store.Connection{}, NewError(CodeValidationFailed, "connection not found", m.red)
	}
	from := Status(conn.Status)
	detail := map[string]string{"from": string(from), "to": string(to), "at": m.now().UTC().Format(time.RFC3339)}
	if err := Next(from, to); err != nil {
		_ = m.record(ctx, audit.EventRejectedTransition, audit.OutcomeFailure, conn, detail)
		m.mu.Unlock()
		return conn, NewError(CodeTransitionRejected, err.Error(), m.red)
	}
	if reason != "" {
		detail["reason"] = reason
	}
	aerr := m.record(ctx, audit.EventStatusChange, audit.OutcomeSuccess, conn, detail)
	if aerr != nil && strict && to != StatusError && to != StatusExpired {
		m.mu.Unlock()
		return conn, aerr
	}
	conn = m.patch(id, func(c *store.Connection) {
		c.Status, c.StatusReason = string(to), reason
	})
	m.mu.Unlock()

	if m.cfg.Supervisor != nil {
		if from == StatusActive {
			sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), StopTimeout)
			_ = m.cfg.Supervisor.Stop(sctx, id)
			cancel()
		}
		if to == StatusActive {
			m.cfg.Supervisor.Start(conn)
		}
	}
	return conn, nil
}

// verify runs the identity and permission checks with the 30 s deadline.
// Excess permission yields an error naming every offender.
//
// The stored secret is registered with the redactor only while the provider
// calls run, so provider errors that echo it come back redacted. The plaintext
// is not kept beyond the vault callback.
func (m *Manager) verify(ctx context.Context, conn store.Connection, cred vault.Ref) (verified, *Error) {
	var (
		out  verified
		verr *Error
	)
	err := m.cfg.Vault.Use(ctx, cred, func(secret []byte) error {
		release := m.red.Register(secret)
		defer release()
		out, verr = m.verifyRegistered(ctx, conn, cred)
		return nil
	})
	if err != nil {
		return verified{}, m.classify(err)
	}
	return out, verr
}

func (m *Manager) verifyRegistered(ctx context.Context, conn store.Connection, cred vault.Ref) (verified, *Error) {
	p, ok := m.provider(conn.ConnectorID)
	if !ok {
		return verified{}, NewError(CodeValidationFailed, "unknown connector", m.red)
	}
	ctx, cancel := context.WithTimeout(ctx, VerifyTimeout)
	defer cancel()
	ref, err := m.brokerRef(conn, p, cred)
	if err != nil {
		return verified{}, NewError(CodeValidationFailed, "connector policy is invalid", m.red)
	}
	call := Call{Connection: conn, Ref: ref, Client: m.cfg.Clients.HTTPClient(ref, "lifecycle")}
	id, err := p.Verify(ctx, call)
	if err != nil {
		return verified{}, m.classify(err)
	}
	rep, err := p.CheckPermissions(ctx, call)
	if err != nil {
		return verified{}, m.classify(err)
	}
	if len(rep.WriteOffenders) > 0 {
		msg := "write permissions found: " + strings.Join(rep.WriteOffenders, ", ")
		return verified{}, NewError(CodeExcessPermission, msg, m.red).WithOffenders(rep.WriteOffenders, m.red)
	}
	check := store.PermissionOK
	if rep.Unverifiable {
		check = store.PermissionUnverifiable
	}
	return verified{identity: id, check: check}, nil
}

// stage stores the candidate credential in its own slot and verifies it. The
// candidate is deleted on any failure.
func (m *Manager) stage(ctx context.Context, conn store.Connection, in CredentialInput) (verified, *Error) {
	cand := candRef(conn.ID)
	if err := m.cfg.Vault.Put(ctx, cand, conn.ConnectorID, bytes.Clone(in.Secret), in.ExpiresAt); err != nil {
		return verified{}, m.classify(err)
	}
	v, verr := m.verify(ctx, conn, cand)
	if verr != nil {
		m.dropCredential(ctx, cand)
		return verified{}, verr
	}
	return v, nil
}

// commit swaps the verified candidate into the active slot.
func (m *Manager) commit(ctx context.Context, conn store.Connection, in CredentialInput) error {
	cand := candRef(conn.ID)
	defer m.dropCredential(ctx, cand)
	if err := m.cfg.Vault.Put(ctx, credRef(conn.ID), conn.ConnectorID, bytes.Clone(in.Secret), in.ExpiresAt); err != nil {
		return m.classify(err)
	}
	if err := m.putRefresh(ctx, conn, in); err != nil {
		return err
	}
	now := m.now().UTC()
	m.patch(conn.ID, func(c *store.Connection) {
		c.CredentialCreatedAt, c.CredentialExpiresAt = &now, timePtr(in.ExpiresAt)
	})
	return nil
}

func (m *Manager) applyVerified(id string, v verified) {
	now := m.now().UTC()
	m.patch(id, func(c *store.Connection) {
		c.AccountLabel = v.identity.AccountLabel
		c.LastPermissionCheck, c.PermissionCheck = &now, v.check
		if !v.identity.ExpiresAt.IsZero() {
			c.CredentialExpiresAt = timePtr(v.identity.ExpiresAt)
		}
	})
}

// markFailed moves a VERIFYING connection to ERROR after a failed reconnect.
func (m *Manager) markFailed(ctx context.Context, id string, verr *Error) {
	reason := "credential could not be stored"
	if verr != nil {
		reason = verr.Error()
	}
	_, _ = m.transition(ctx, id, StatusError, reason, false)
}

// classify maps any failure to exactly one typed error.
func (m *Manager) classify(err error) *Error {
	var te *Error
	var be *broker.BlockedError
	var ce *broker.CredentialError
	var rl *broker.RateLimitedError
	var ne *broker.NetworkError
	switch {
	case errors.As(err, &te):
		out := NewError(te.Code, te.Message, m.red)
		return out.WithOffenders(te.Offenders, m.red)
	case errors.As(err, &be):
		return NewError(CodeBlockedByPolicy, "operation blocked by policy", m.red)
	case errors.As(err, &ce):
		return NewError(CodeVaultUnavailable, "credential is unavailable", m.red)
	case errors.As(err, &rl):
		return NewError(CodeRateLimited, "provider rate limit reached", m.red)
	case errors.As(err, &ne), errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return NewError(CodeNetwork, "provider could not be reached", m.red)
	case errors.Is(err, vault.ErrAuditFailed):
		return NewError(CodeAuditFailed, "audit log is unavailable", m.red)
	case errors.Is(err, vault.ErrDecrypt):
		return NewError(CodeDecryptFailed, "credential cannot be decrypted", m.red)
	case errors.Is(err, vault.ErrNotFound), errors.Is(err, vault.ErrInvalidSecret):
		return NewError(CodeVaultUnavailable, "credential is unavailable", m.red)
	}
	return NewError(CodeNetwork, "verification failed", m.red)
}

func (m *Manager) provider(connectorID string) (Provider, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.providers[connectorID]
	return p, ok
}

func (m *Manager) brokerRef(conn store.Connection, p Provider, cred vault.Ref) (broker.ConnectionRef, error) {
	entry, ok := m.cfg.Registry.Get(conn.ConnectorID)
	if !ok {
		return broker.ConnectionRef{}, errors.New("unknown connector")
	}
	d := p.Describe(conn)
	pol, err := policy.Compile(entry.Manifest, policy.Selection{Regions: conn.Selection.Regions, Host: d.Host})
	if err != nil {
		return broker.ConnectionRef{}, err
	}
	return broker.ConnectionRef{
		ID: conn.ID, ConnectorID: conn.ConnectorID, Manifest: entry.Manifest, Policy: pol,
		Auth: d.Auth, Credential: cred, APIHost: d.APIHost, BasePath: d.BasePath,
	}, nil
}

// live returns a connection that exists and is not removed.
func (m *Manager) live(id string) (store.Connection, error) {
	conn, ok := m.cfg.Store.Connection(id)
	if !ok || conn.Removed {
		return store.Connection{}, NewError(CodeValidationFailed, "connection not found", m.red)
	}
	return conn, nil
}

func (m *Manager) record(ctx context.Context, event, outcome string, conn store.Connection, detail map[string]string) error {
	err := m.cfg.Audit.Append(ctx, audit.Entry{
		TS: m.now().UTC(), ConnectionID: conn.ID, ConnectorID: conn.ConnectorID,
		Event: event, Outcome: outcome, Actor: audit.ActorUser, Detail: detail,
	})
	if err != nil {
		return NewError(CodeAuditFailed, "audit log is unavailable", m.red)
	}
	return nil
}

// patch applies fn to the stored connection and returns the result.
func (m *Manager) patch(id string, fn func(*store.Connection)) store.Connection {
	_ = m.cfg.Store.UpdateConnection(id, func(c *store.Connection) error {
		fn(c)
		return nil
	})
	out, _ := m.cfg.Store.Connection(id)
	return out
}

func (m *Manager) tombstone(id string) {
	m.patch(id, func(c *store.Connection) { c.Removed = true })
}

func (m *Manager) dropCredential(ctx context.Context, ref vault.Ref) {
	_ = m.cfg.Vault.Delete(context.WithoutCancel(ctx), ref)
}

func credRef(id string) vault.Ref {
	return vault.Ref{Owner: vault.OwnerConnection, OwnerID: id, Slot: slotCredential}
}

// CredentialRef is the vault slot of the active credential of a connection.
func CredentialRef(id string) vault.Ref { return credRef(id) }

// RefreshRef is the vault slot of the refresh token of a connection.
func RefreshRef(id string) vault.Ref { return refRef(id) }

func refRef(id string) vault.Ref {
	return vault.Ref{Owner: vault.OwnerConnection, OwnerID: id, Slot: slotRefresh}
}

// putRefresh stores the refresh token of in, or removes a stale one when the
// new credential has none. The input token is zeroed.
func (m *Manager) putRefresh(ctx context.Context, conn store.Connection, in CredentialInput) error {
	if len(in.RefreshToken) == 0 {
		m.dropCredential(ctx, refRef(conn.ID))
		return nil
	}
	defer clear(in.RefreshToken)
	if err := m.cfg.Vault.Put(ctx, refRef(conn.ID), conn.ConnectorID, bytes.Clone(in.RefreshToken), time.Time{}); err != nil {
		return m.classify(err)
	}
	return nil
}

func candRef(id string) vault.Ref {
	return vault.Ref{Owner: vault.OwnerConnection, OwnerID: id, Slot: slotCandidate}
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "conn_" + hex.EncodeToString(b)
}

// aliasError distinguishes a malformed alias from a duplicate.
func aliasError(alias string, err error, r Redactor) *Error {
	if n := utf8.RuneCountInString(alias); n < store.MinAliasLen || n > store.MaxAliasLen || !utf8.ValidString(alias) {
		return NewError(CodeAliasInvalid, "alias must be 1 to 40 characters", r)
	}
	return NewError(CodeAliasTaken, "alias is already used by another connection of this connector", r)
}

func storeError(err error, r Redactor) error {
	var te *Error
	if errors.As(err, &te) {
		return err
	}
	var fe *store.FieldError
	if errors.As(err, &fe) {
		if fe.Field == "alias" {
			return NewError(CodeAliasTaken, fe.Message, r)
		}
		return NewError(CodeValidationFailed, fe.Field+": "+fe.Message, r)
	}
	return NewError(CodeValidationFailed, "state could not be saved", r)
}

// validateCredential runs the provider's optional pre-store credential check.
// A rejection is returned as a credential-free validation_failed error.
func (m *Manager) validateCredential(connectorID, method string, secret []byte) error {
	p, ok := m.provider(connectorID)
	if !ok {
		return nil
	}
	var verr error
	if mv, ok := p.(MethodCredentialValidator); ok {
		verr = mv.ValidateCredentialFor(method, secret)
	} else if v, ok := p.(CredentialValidator); ok {
		verr = v.ValidateCredential(secret)
	}
	if err := verr; err != nil {
		var le *Error
		if errors.As(err, &le) && le.Code == CodeValidationFailed {
			out := NewError(CodeValidationFailed, le.Message, m.red)
			if len(le.Offenders) > 0 {
				out.WithOffenders(le.Offenders, m.red)
			}
			return out
		}
		return NewError(CodeValidationFailed, "credential rejected", m.red)
	}
	return nil
}

// createMethod returns the method of the auth config a new connection uses.
func createMethod(snap store.State, authConfigID string) string {
	for _, a := range snap.AuthConfigs {
		if a.ID == authConfigID {
			return a.Method
		}
	}
	return ""
}
