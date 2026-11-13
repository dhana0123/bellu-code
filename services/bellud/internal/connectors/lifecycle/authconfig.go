package lifecycle

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/audit"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/manifest"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/redactor"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/registry"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/vault"
)

const (
	// MaxAuthConfigName is the maximum Auth_Config name length in characters.
	MaxAuthConfigName = 40
	// MaxCustomAuthConfigs is the maximum number of custom configs per connector.
	MaxCustomAuthConfigs = 10

	// DefaultAuthConfigName is the name of every connector's default config.
	DefaultAuthConfigName = "default"

	// SettingAppRef is the default config's reference to the built-in app
	// credentials. It is a reference, never a secret value.
	SettingAppRef = "appCredentialRef"
	// SettingSecretSlots lists (comma separated) the vault slots holding the
	// app secrets of a custom config. Slot names are not secret.
	SettingSecretSlots = "secretSlots"
)

// MethodSpec states which settings and app secrets a custom Auth_Config of one
// auth method needs.
type MethodSpec struct {
	// Required lists the non-secret settings that must be present.
	Required []string
	// Secrets lists the app secrets that must be present (stored in the vault).
	Secrets []string
}

// DefaultMethodSpecs covers the OAuth app, GitHub App and AWS role settings
// types of Req 13.2. Methods that are not listed need no settings.
func DefaultMethodSpecs() map[string]MethodSpec {
	return map[string]MethodSpec{
		"oauth_app":   {Required: []string{"clientId"}, Secrets: []string{"clientSecret"}},
		"github_app":  {Required: []string{"appId"}, Secrets: []string{"privateKey"}},
		"assume_role": {Required: []string{"roleArn"}},
	}
}

// AuthConfigServiceConfig wires an AuthConfigService.
type AuthConfigServiceConfig struct {
	Store    *store.Store
	Vault    Vault
	Audit    audit.Log
	Registry registry.Registry
	Redactor *redactor.Redactor
	// Methods maps an auth method id to its requirements; nil uses DefaultMethodSpecs.
	Methods map[string]MethodSpec
	Now     func() time.Time
	NewID   func() string
}

// AuthConfigService manages the default and custom Auth_Configs of connectors
// (Req 13). It is safe for concurrent use.
type AuthConfigService struct {
	cfg     AuthConfigServiceConfig
	red     *redactor.Redactor
	methods map[string]MethodSpec
	now     func() time.Time
	newID   func() string
	mu      sync.Mutex // serializes creates and deletes
}

// NewAuthConfigService returns a service over the given dependencies.
func NewAuthConfigService(cfg AuthConfigServiceConfig) *AuthConfigService {
	s := &AuthConfigService{cfg: cfg, red: cfg.Redactor, methods: cfg.Methods, now: cfg.Now, newID: cfg.NewID}
	if s.red == nil {
		s.red = redactor.New()
	}
	if s.methods == nil {
		s.methods = DefaultMethodSpecs()
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.newID == nil {
		s.newID = newAuthConfigID
	}
	return s
}

// CreateAuthConfigInput is a custom Auth_Config request. The service zeroes
// every Secrets value when done.
type CreateAuthConfigInput struct {
	ConnectorID string
	Name        string
	Method      string
	Scopes      []string
	// Settings are the non-secret app settings.
	Settings map[string]string
	// Secrets are the app secrets by name; they go to the vault only.
	Secrets map[string][]byte
}

// DefaultAuthConfigID is the id of a connector's default Auth_Config.
func DefaultAuthConfigID(connectorID string) string { return "ac_default_" + connectorID }

// EnsureDefaults creates the default Auth_Config of every registered connector
// that lacks one. It is idempotent.
//
// It also resumes tombstoned deletes whose vault cleanup failed earlier
// (best effort: a still-failing vault leaves them tombstoned for the next call).
func (s *AuthConfigService) EnsureDefaults() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureDefaultsLocked(); err != nil {
		return err
	}
	s.resumeDeletesLocked(context.Background())
	return nil
}

// ResumeDeletes finishes every tombstoned delete. Vault failures are returned
// as vault_unavailable and leave the configs tombstoned.
func (s *AuthConfigService) ResumeDeletes(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.resumeDeletesLocked(ctx)
}

func (s *AuthConfigService) resumeDeletesLocked(ctx context.Context) error {
	var failed error
	for _, cfg := range s.cfg.Store.Snapshot().AuthConfigs {
		if cfg.Deleting {
			if err := s.finishDelete(ctx, cfg); err != nil {
				failed = err
			}
		}
	}
	return failed
}

func (s *AuthConfigService) ensureDefaultsLocked() error {
	entries := s.cfg.Registry.List()
	return s.cfg.Store.Update(func(st *store.State) error {
		for _, e := range entries {
			id := DefaultAuthConfigID(e.Manifest.ID)
			if slices.ContainsFunc(st.AuthConfigs, func(a store.AuthConfig) bool { return a.ID == id }) {
				continue
			}
			st.AuthConfigs = append(st.AuthConfigs, defaultConfig(id, e.Manifest.ID, readScopes(e), defaultMethod(e)))
		}
		return nil
	})
}

// List returns the connector's Auth_Configs, the default first. It carries no
// secret value: app secrets are only in the vault.
func (s *AuthConfigService) List(connectorID string) ([]store.AuthConfig, error) {
	if _, ok := s.cfg.Registry.Get(connectorID); !ok {
		return nil, NewError(CodeValidationFailed, "unknown connector", s.red)
	}
	if err := s.EnsureDefaults(); err != nil {
		return nil, storeError(err, s.red)
	}
	out := []store.AuthConfig{}
	for _, a := range s.cfg.Store.Snapshot().AuthConfigs {
		if a.ConnectorID == connectorID && !a.Deleting {
			out = append(out, a)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Builtin && !out[j].Builtin })
	return out, nil
}

// Create validates and stores a custom Auth_Config. Any failure leaves no
// vault secret and no config behind.
func (s *AuthConfigService) Create(ctx context.Context, in CreateAuthConfigInput) (store.AuthConfig, error) {
	defer func() {
		for _, v := range in.Secrets {
			clear(v)
		}
	}()
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.cfg.Registry.Get(in.ConnectorID)
	if !ok {
		return store.AuthConfig{}, NewError(CodeValidationFailed, "unknown connector", s.red)
	}
	for _, v := range in.Secrets {
		defer s.red.Register(v)()
	}
	// The default config must exist so its name is always reserved (Req 13.3).
	if err := s.ensureDefaultsLocked(); err != nil {
		return store.AuthConfig{}, storeError(err, s.red)
	}
	slots := slices.Sorted(maps.Keys(in.Secrets))
	if verr := s.validate(in, entry, slots); verr != nil {
		return store.AuthConfig{}, verr
	}

	cfg := store.AuthConfig{
		ID: s.newID(), ConnectorID: in.ConnectorID, Name: in.Name, Method: in.Method,
		Scopes: slices.Clone(in.Scopes), Settings: maps.Clone(in.Settings),
	}
	if cfg.Settings == nil {
		cfg.Settings = map[string]string{}
	}
	if len(slots) > 0 {
		cfg.Settings[SettingSecretSlots] = strings.Join(slots, ",")
	}
	for _, slot := range slots {
		ref := authConfigRef(cfg.ID, slot)
		if err := s.cfg.Vault.Put(ctx, ref, in.ConnectorID, in.Secrets[slot], time.Time{}); err != nil {
			s.dropSecrets(ctx, cfg.ID, slots)
			return store.AuthConfig{}, storageError(s.red)
		}
	}
	detail := map[string]string{"kind": "auth_config_create", "authConfigId": cfg.ID}
	if err := s.record(ctx, audit.EventConnect, audit.OutcomeSuccess, in.ConnectorID, detail); err != nil {
		s.dropSecrets(ctx, cfg.ID, slots)
		return store.AuthConfig{}, err
	}
	err := s.cfg.Store.Update(func(st *store.State) error {
		st.AuthConfigs = append(st.AuthConfigs, cfg)
		return nil
	})
	if err != nil {
		s.dropSecrets(ctx, cfg.ID, slots)
		return store.AuthConfig{}, storeError(err, s.red)
	}
	return cfg, nil
}

// Delete removes a custom Auth_Config that no connection uses. It first
// tombstones the config (hidden, unusable), then deletes its vault secrets,
// then removes it. If a vault delete fails the config stays tombstoned and the
// cleanup is retried by EnsureDefaults/ResumeDeletes; secrets are never restored.
// The default cannot be deleted.
func (s *AuthConfigService) Delete(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.cfg.Store.Snapshot()
	i := slices.IndexFunc(snap.AuthConfigs, func(a store.AuthConfig) bool { return a.ID == id && !a.Deleting })
	if i < 0 {
		return NewError(CodeValidationFailed, "auth config not found", s.red)
	}
	cfg := snap.AuthConfigs[i]
	if cfg.Builtin {
		return NewError(CodeForbidden, "the default auth config cannot be deleted", s.red)
	}
	if n := countUsing(snap.Connections, id); n > 0 {
		return NewError(CodeValidationFailed, fmt.Sprintf("auth config is in use by %d connection(s)", n), s.red).
			withInUse(n)
	}
	err := s.cfg.Store.Update(func(st *store.State) error {
		for j := range st.AuthConfigs {
			if st.AuthConfigs[j].ID == id {
				st.AuthConfigs[j].Deleting = true
			}
		}
		return nil
	})
	if err != nil {
		return storeError(err, s.red)
	}
	cfg.Deleting = true
	return s.finishDelete(ctx, cfg)
}

// finishDelete deletes a tombstoned config's secrets, then the config.
func (s *AuthConfigService) finishDelete(ctx context.Context, cfg store.AuthConfig) error {
	id := cfg.ID
	for _, slot := range splitSlots(cfg.Settings[SettingSecretSlots]) {
		if err := s.cfg.Vault.Delete(ctx, authConfigRef(id, slot)); err != nil {
			_ = s.record(ctx, audit.EventDisconnect, audit.OutcomeFailure, cfg.ConnectorID,
				map[string]string{"kind": "auth_config_delete", "authConfigId": id, "step": "secret_delete"})
			return storageError(s.red)
		}
	}
	err := s.cfg.Store.Update(func(st *store.State) error {
		st.AuthConfigs = slices.DeleteFunc(st.AuthConfigs, func(a store.AuthConfig) bool { return a.ID == id })
		return nil
	})
	if err != nil {
		return storeError(err, s.red)
	}
	// Best effort: the secrets are already gone.
	_ = s.record(ctx, audit.EventDisconnect, audit.OutcomeSuccess, cfg.ConnectorID,
		map[string]string{"kind": "auth_config_delete", "authConfigId": id})
	return nil
}

// validate checks every rule of Req 13.2, 13.4 and 13.7 and names each
// offending field or scope. It returns nil when the input is acceptable.
func (s *AuthConfigService) validate(in CreateAuthConfigInput, e registry.Entry, slots []string) *Error {
	var fields, badScopes []string
	if n := utf8.RuneCountInString(in.Name); n < 1 || n > MaxAuthConfigName || !utf8.ValidString(in.Name) {
		fields = append(fields, "name")
	}
	existing := []store.AuthConfig{}
	for _, a := range s.cfg.Store.Snapshot().AuthConfigs {
		if a.ConnectorID == in.ConnectorID {
			existing = append(existing, a)
		}
	}
	custom := 0
	for _, a := range existing {
		if !a.Builtin {
			custom++
		}
		if (a.Name == in.Name || in.Name == DefaultAuthConfigName) && !slices.Contains(fields, "name") {
			fields = append(fields, "name")
		}
	}
	if !slices.ContainsFunc(e.Manifest.AuthMethods, func(m manifest.AuthMethod) bool { return m.ID == in.Method && m.Enabled }) {
		fields = append(fields, "method")
	}
	spec := s.methods[in.Method]
	for _, k := range spec.Required {
		if in.Settings[k] == "" {
			fields = append(fields, "settings."+k)
		}
	}
	for _, k := range spec.Secrets {
		if len(in.Secrets[k]) == 0 {
			fields = append(fields, "secrets."+k)
		}
	}
	if _, ok := in.Settings[SettingSecretSlots]; ok {
		fields = append(fields, "settings."+SettingSecretSlots)
	}
	for _, slot := range slots {
		if !slices.Contains(spec.Secrets, slot) {
			fields = append(fields, "secrets."+slot)
		}
	}
	if len(in.Scopes) == 0 {
		fields = append(fields, "scopes")
	}
	allowed := readScopes(e)
	for _, sc := range in.Scopes {
		if !slices.Contains(allowed, sc) && !slices.Contains(badScopes, sc) {
			badScopes = append(badScopes, sc)
		}
	}
	if custom >= MaxCustomAuthConfigs {
		return NewError(CodeValidationFailed, fmt.Sprintf("limit of %d custom auth configs reached", MaxCustomAuthConfigs), s.red).
			WithOffenders([]string{"limit"}, s.red)
	}
	switch {
	case len(fields) > 0:
		// Scopes are named too, so one response lists everything to fix.
		names := append(fields, prefixAll("scope:", badScopes)...)
		return NewError(CodeValidationFailed, "invalid: "+strings.Join(names, ", "), s.red).WithOffenders(names, s.red)
	case len(badScopes) > 0:
		return NewError(CodeScopeDenied, "scopes outside the read-only set: "+strings.Join(badScopes, ", "), s.red).
			WithOffenders(badScopes, s.red)
	}
	return nil
}

func (s *AuthConfigService) dropSecrets(ctx context.Context, id string, slots []string) {
	for _, slot := range slots {
		_ = s.cfg.Vault.Delete(context.WithoutCancel(ctx), authConfigRef(id, slot))
	}
}

func (s *AuthConfigService) record(ctx context.Context, event, outcome, connectorID string, detail map[string]string) error {
	err := s.cfg.Audit.Append(ctx, audit.Entry{
		TS: s.now().UTC(), ConnectorID: connectorID, Event: event, Outcome: outcome,
		Actor: audit.ActorUser, Detail: detail,
	})
	if err != nil {
		return NewError(CodeAuditFailed, "audit log is unavailable", s.red)
	}
	return nil
}

func authConfigRef(id, slot string) vault.Ref {
	return vault.Ref{Owner: vault.OwnerAuthConfig, OwnerID: id, Slot: slot}
}

func defaultConfig(id, connectorID string, scopes []string, method string) store.AuthConfig {
	return store.AuthConfig{
		ID: id, ConnectorID: connectorID, Name: DefaultAuthConfigName, Builtin: true, Method: method,
		Scopes: scopes, Settings: map[string]string{SettingAppRef: "builtin:" + connectorID},
	}
}

func defaultMethod(e registry.Entry) string {
	for _, m := range e.Manifest.AuthMethods {
		if m.Enabled {
			return m.ID
		}
	}
	return e.Manifest.AuthMethods[0].ID
}

// readScopes is the connector's read-only scope set: the manifest permissions
// (the manifest validator requires every one to be read-only).
func readScopes(e registry.Entry) []string {
	out := []string{}
	for _, p := range e.Manifest.Permissions {
		if p.ReadOnly {
			out = append(out, p.Name)
		}
	}
	return out
}

func countUsing(conns []store.Connection, authConfigID string) int {
	n := 0
	for _, c := range conns {
		if !c.Removed && c.AuthConfigID == authConfigID {
			n++
		}
	}
	return n
}

func splitSlots(v string) []string {
	if v == "" {
		return nil
	}
	return strings.Split(v, ",")
}

func prefixAll(p string, in []string) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = p + v
	}
	return out
}

func storageError(r Redactor) *Error {
	return NewError(CodeVaultUnavailable, "credential storage failed", r)
}

// withInUse records the exact number of connections using a config.
func (e *Error) withInUse(n int) *Error {
	e.InUse = n
	return e
}

func newAuthConfigID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "ac_" + hex.EncodeToString(b)
}
