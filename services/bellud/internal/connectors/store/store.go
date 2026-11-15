// Package store persists the non-secret connector state (state.json):
// settings, auth configs, connections, scopes and plugins. Credentials never
// live here; they are referenced by vault slot only.
//
// Writes are temp file + fsync + rename + directory fsync, with mode 0600 for
// the file and 0700 for the directory. Every mutation is validated on a copy
// and only committed after it is durably written, so a rejected change keeps
// the previous value.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	// Version is the state.json document version.
	Version = 1
	// FileName is the state document name inside the connectors directory.
	FileName = "state.json"

	DefaultIntervalSec        = 900
	MinIntervalSec            = 60
	MaxIntervalSec            = 24 * 60 * 60
	DefaultRotationDays       = 90
	MinRotationDays           = 1
	MaxRotationDays           = 365
	DefaultAuditRetentionDays = 90
	MinRetentionDays          = 1
	MaxRetentionDays          = 365
	MinAliasLen               = 1
	MaxAliasLen               = 40
)

// Permission check results for Connection.PermissionCheck.
const (
	PermissionOK           = "ok"
	PermissionExcess       = "excess"
	PermissionUnverifiable = "unverifiable"
)

// ErrNotFound is returned when a connection or auth config id is unknown.
var ErrNotFound = errors.New("not found")

// FieldError names the rejected field and the allowed range or rule.
// It never echoes the offending value.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (e *FieldError) Error() string { return e.Field + ": " + e.Message }

// Settings are the global connector settings.
type Settings struct {
	AuditRetentionDays int `json:"audit_retention_days"`
	DefaultIntervalSec int `json:"default_interval_sec"`
}

// AuthConfig is a connector auth configuration. App secrets live in the vault.
type AuthConfig struct {
	ID          string            `json:"id"`
	ConnectorID string            `json:"connectorId"`
	Name        string            `json:"name"`
	Builtin     bool              `json:"builtin"`
	Method      string            `json:"method"`
	Scopes      []string          `json:"scopes"`
	Settings    map[string]string `json:"settings"`
	// Deleting marks a tombstone: the config is hidden and unusable while its
	// vault secrets are being deleted (Req 13.8, 13.9).
	Deleting bool `json:"deleting,omitempty"`
}

// Selection is the user's region/repository selection for a connection.
type Selection struct {
	Regions []string `json:"regions"`
	Repos   []string `json:"repos"`
	// Items is the generic per-source scope selection (GitLab project paths,
	// Azure subscription ids, GCP project ids, Bitbucket workspaces, Cloudflare
	// zone ids, Kubernetes namespaces).
	Items []string `json:"items,omitempty"`
}

// LastSync describes the most recent collection run.
type LastSync struct {
	Status   string     `json:"status"`
	EndedAt  *time.Time `json:"endedAt,omitempty"`
	Entities int        `json:"entities"`
	Partial  []string   `json:"partial"`
	// RateLimitWaits, AuthError and DeniedScopes are the Run_Status fields
	// the collector reported for the run.
	RateLimitWaits []RateLimitWait `json:"rateLimitWaits,omitempty"`
	AuthError      string          `json:"authError,omitempty"`
	DeniedScopes   []string        `json:"deniedScopes,omitempty"`
}

// RateLimitWait is one wait a collector performed until a source's rate-limit
// reset time.
type RateLimitWait struct {
	Scope    string    `json:"scope"`
	Until    time.Time `json:"until"`
	WaitedMS int64     `json:"waitedMs"`
}

// Connection is one configured account of a connector.
type Connection struct {
	ID                   string     `json:"id"`
	ConnectorID          string     `json:"connectorId"`
	Alias                string     `json:"alias"`
	AuthConfigID         string     `json:"authConfigId"`
	Method               string     `json:"method"`
	Status               string     `json:"status"`
	StatusReason         string     `json:"statusReason"`
	AccountLabel         string     `json:"accountLabel"`
	ExternalIDRef        string     `json:"externalIdRef,omitempty"`
	Selection            Selection  `json:"selection"`
	IntervalSec          int        `json:"intervalSec"`
	AllowAgentLiveReads  bool       `json:"allowAgentLiveReads"`
	RotationIntervalDays int        `json:"rotationIntervalDays"`
	CredentialCreatedAt  *time.Time `json:"credentialCreatedAt"`
	CredentialExpiresAt  *time.Time `json:"credentialExpiresAt"`
	LastPermissionCheck  *time.Time `json:"lastPermissionCheck"`
	PermissionCheck      string     `json:"permissionCheck"`
	LastSync             *LastSync  `json:"lastSync,omitempty"`
	Removed              bool       `json:"removed"`
	CreatedAt            time.Time  `json:"createdAt"`
}

// Scope is an agent/principal scope entry (Requirement 17).
type Scope struct {
	Principal   string              `json:"principal"`
	Connectors  []string            `json:"connectors"`
	Connections []string            `json:"connections"`
	Operations  map[string][]string `json:"operations"`
}

// Plugin is a pinned connector plugin entry.
type Plugin struct {
	ID                   string   `json:"id"`
	PinnedVersion        string   `json:"pinnedVersion"`
	ConfirmedPermissions []string `json:"confirmedPermissions"`
	ConfirmedHosts       []string `json:"confirmedHosts"`
	Signed               bool     `json:"signed"`
}

// State is the whole state.json document.
type State struct {
	Version     int          `json:"version"`
	Settings    Settings     `json:"settings"`
	AuthConfigs []AuthConfig `json:"authConfigs"`
	Connections []Connection `json:"connections"`
	Scopes      []Scope      `json:"scopes"`
	Plugins     []Plugin     `json:"plugins"`
}

// Default returns an empty state with default settings.
func Default() State {
	return State{
		Version: Version,
		Settings: Settings{
			AuditRetentionDays: DefaultAuditRetentionDays,
			DefaultIntervalSec: DefaultIntervalSec,
		},
		AuthConfigs: []AuthConfig{},
		Connections: []Connection{},
		Scopes:      []Scope{},
		Plugins:     []Plugin{},
	}
}

// NewConnection returns a connection with defaults applied: interval from the
// settings, rotation 90 days, and allowAgentLiveReads=false.
func NewConnection(id, connectorID, alias string, settings Settings, now time.Time) Connection {
	interval := settings.DefaultIntervalSec
	if interval == 0 {
		interval = DefaultIntervalSec
	}
	return Connection{
		ID:                   id,
		ConnectorID:          connectorID,
		Alias:                alias,
		IntervalSec:          interval,
		RotationIntervalDays: DefaultRotationDays,
		AllowAgentLiveReads:  false,
		Selection:            Selection{Regions: []string{}, Repos: []string{}},
		CreatedAt:            now.UTC(),
	}
}

// ValidateAlias checks length (1-40 characters) and uniqueness among the
// non-removed connections of the same connector. selfID is excluded so a
// connection can keep its own alias.
func ValidateAlias(alias, connectorID, selfID string, existing []Connection) error {
	n := utf8.RuneCountInString(alias)
	if n < MinAliasLen || n > MaxAliasLen {
		return &FieldError{"alias", fmt.Sprintf("must be %d to %d characters", MinAliasLen, MaxAliasLen)}
	}
	if !utf8.ValidString(alias) {
		return &FieldError{"alias", "must be valid UTF-8"}
	}
	for _, c := range existing {
		if c.Removed || c.ID == selfID || c.ConnectorID != connectorID {
			continue
		}
		if c.Alias == alias {
			return &FieldError{"alias", "already used by another connection of this connector"}
		}
	}
	return nil
}

// ValidateInterval checks a collection interval: whole minutes, 1 min to 24 h.
func ValidateInterval(sec int) error {
	if sec < MinIntervalSec || sec > MaxIntervalSec || sec%60 != 0 {
		return &FieldError{"intervalSec", "must be a whole number of minutes from 1 minute to 24 hours"}
	}
	return nil
}

// ValidateRotationDays checks a credential rotation interval (1-365 days).
func ValidateRotationDays(days int) error {
	if days < MinRotationDays || days > MaxRotationDays {
		return &FieldError{"rotationIntervalDays", fmt.Sprintf("must be %d to %d days", MinRotationDays, MaxRotationDays)}
	}
	return nil
}

// ValidateRetentionDays checks the audit retention (1-365 days).
func ValidateRetentionDays(days int) error {
	if days < MinRetentionDays || days > MaxRetentionDays {
		return &FieldError{"audit_retention_days", fmt.Sprintf("must be %d to %d days", MinRetentionDays, MaxRetentionDays)}
	}
	return nil
}

// ValidateSettings checks the global settings.
func ValidateSettings(s Settings) error {
	if err := ValidateRetentionDays(s.AuditRetentionDays); err != nil {
		return err
	}
	if err := ValidateInterval(s.DefaultIntervalSec); err != nil {
		var fe *FieldError
		errors.As(err, &fe)
		return &FieldError{"default_interval_sec", fe.Message}
	}
	return nil
}

// Validate checks every invariant of a whole state document.
func Validate(s State) error {
	if s.Version != Version {
		return &FieldError{"version", fmt.Sprintf("unsupported version, expected %d", Version)}
	}
	if err := ValidateSettings(s.Settings); err != nil {
		return err
	}
	for i, c := range s.Connections {
		if err := ValidateAlias(c.Alias, c.ConnectorID, c.ID, s.Connections[:i]); err != nil {
			return err
		}
		if err := ValidateInterval(c.IntervalSec); err != nil {
			return err
		}
		if err := ValidateRotationDays(c.RotationIntervalDays); err != nil {
			return err
		}
	}
	return nil
}

// Store is the on-disk state.json holder. It is safe for concurrent use.
type Store struct {
	mu    sync.Mutex
	dir   string
	state State
}

// Open loads dir/state.json, creating the directory (0700) and a default
// document when missing.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("store: create directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("store: directory mode: %w", err)
	}
	s := &Store{dir: dir}
	raw, err := os.ReadFile(s.path())
	if errors.Is(err, os.ErrNotExist) {
		s.state = Default()
		if err := s.write(s.state); err != nil {
			return nil, err
		}
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: read state: %w", err)
	}
	state, err := Decode(raw)
	if err != nil {
		return nil, err
	}
	s.state = state
	return s, nil
}

// Decode parses and validates a state document, normalizing nil slices.
func Decode(raw []byte) (State, error) {
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		return State{}, errors.New("store: state.json is not valid JSON")
	}
	normalize(&st)
	if err := Validate(st); err != nil {
		return State{}, fmt.Errorf("store: invalid state: %w", err)
	}
	return st, nil
}

// Encode serializes a state document.
func Encode(st State) ([]byte, error) {
	normalize(&st)
	return json.MarshalIndent(st, "", "  ")
}

// Snapshot returns a deep copy of the current state.
func (s *Store) Snapshot() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return clone(s.state)
}

// Update applies fn to a copy of the state, validates it, persists it and then
// commits it. Any error from fn, validation or persistence leaves the previous
// state in memory and on disk.
func (s *Store) Update(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := clone(s.state)
	if err := fn(&next); err != nil {
		return err
	}
	normalize(&next)
	if err := Validate(next); err != nil {
		return err
	}
	if err := s.write(next); err != nil {
		return err
	}
	s.state = next
	return nil
}

// SetSettings validates and stores the global settings.
func (s *Store) SetSettings(v Settings) error {
	return s.Update(func(st *State) error {
		st.Settings = v
		return nil
	})
}

// AddConnection appends a connection after validating alias, interval and
// rotation. The alias must be unique among the connector's live connections.
func (s *Store) AddConnection(c Connection) error {
	return s.Update(func(st *State) error {
		if c.ID == "" {
			return &FieldError{"id", "must not be empty"}
		}
		for _, e := range st.Connections {
			if e.ID == c.ID {
				return &FieldError{"id", "already exists"}
			}
		}
		st.Connections = append(st.Connections, c)
		return nil
	})
}

// UpdateConnection mutates the connection with the given id. The result is
// validated like any other change.
func (s *Store) UpdateConnection(id string, fn func(*Connection) error) error {
	return s.Update(func(st *State) error {
		for i := range st.Connections {
			if st.Connections[i].ID != id {
				continue
			}
			return fn(&st.Connections[i])
		}
		return ErrNotFound
	})
}

// Connection returns a copy of the connection with the given id.
func (s *Store) Connection(id string) (Connection, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.state.Connections {
		if c.ID == id {
			return clone(State{Connections: []Connection{c}}).Connections[0], true
		}
	}
	return Connection{}, false
}

func (s *Store) path() string { return filepath.Join(s.dir, FileName) }

func (s *Store) write(st State) error {
	raw, err := Encode(st)
	if err != nil {
		return fmt.Errorf("store: encode: %w", err)
	}
	return writeAtomic(s.path(), raw)
}

func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("store: temp file: %w", err)
	}
	name := tmp.Name()
	fail := func(err error) error {
		tmp.Close()
		os.Remove(name)
		return fmt.Errorf("store: write: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return fmt.Errorf("store: close: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return fmt.Errorf("store: rename: %w", err)
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("store: open directory: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("store: sync directory: %w", err)
	}
	return nil
}

func clone(st State) State {
	raw, err := json.Marshal(st)
	if err != nil {
		panic("store: clone: " + err.Error())
	}
	var out State
	if err := json.Unmarshal(raw, &out); err != nil {
		panic("store: clone: " + err.Error())
	}
	normalize(&out)
	return out
}

// normalize replaces nil slices with empty ones so documents serialize stably.
func normalize(st *State) {
	if st.AuthConfigs == nil {
		st.AuthConfigs = []AuthConfig{}
	}
	if st.Connections == nil {
		st.Connections = []Connection{}
	}
	if st.Scopes == nil {
		st.Scopes = []Scope{}
	}
	if st.Plugins == nil {
		st.Plugins = []Plugin{}
	}
	for i := range st.AuthConfigs {
		if st.AuthConfigs[i].Scopes == nil {
			st.AuthConfigs[i].Scopes = []string{}
		}
		if st.AuthConfigs[i].Settings == nil {
			st.AuthConfigs[i].Settings = map[string]string{}
		}
	}
	for i := range st.Connections {
		c := &st.Connections[i]
		if c.Selection.Regions == nil {
			c.Selection.Regions = []string{}
		}
		if c.Selection.Repos == nil {
			c.Selection.Repos = []string{}
		}
		if c.LastSync != nil && c.LastSync.Partial == nil {
			c.LastSync.Partial = []string{}
		}
	}
	for i := range st.Scopes {
		sc := &st.Scopes[i]
		if sc.Connectors == nil {
			sc.Connectors = []string{}
		}
		if sc.Connections == nil {
			sc.Connections = []string{}
		}
		if sc.Operations == nil {
			sc.Operations = map[string][]string{}
		}
	}
	for i := range st.Plugins {
		if st.Plugins[i].ConfirmedPermissions == nil {
			st.Plugins[i].ConfirmedPermissions = []string{}
		}
		if st.Plugins[i].ConfirmedHosts == nil {
			st.Plugins[i].ConfirmedHosts = []string{}
		}
	}
}
