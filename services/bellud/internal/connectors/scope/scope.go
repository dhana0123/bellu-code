// Package scope holds the Session_Scope of agent principals (Requirement 17).
//
// A principal's scope names the connectors, connections and read operations an
// agent may use for live reads. The default is the empty scope, which denies
// everything. Decisions read an atomic snapshot that is rebuilt on every Put
// and at most MaxAge after the last build, so a change made by any path (scope
// edit, "Allow agent live reads" toggle, connection removal) is effective well
// inside the 5 s bound of Requirements 17.5 and 17.7.
package scope

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/manifest"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/policy"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/registry"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
)

// Principal is the only principal of the MVP.
const Principal = "agent"

// MaxAge bounds how stale a snapshot can be. It is far below the 5 s limit.
const MaxAge = time.Second

// Source is the persisted state; *store.Store implements it.
type Source interface {
	Snapshot() store.State
	Update(fn func(*store.State) error) error
}

// Manifests resolves a connector manifest; registry.Registry implements it.
type Manifests interface {
	Get(id string) (registry.Entry, bool)
}

// ValidationError rejects a scope and names the offending field or operation.
type ValidationError struct {
	Field     string
	Operation string // set when an operation is not on the read allowlist
	Message   string
}

func (e *ValidationError) Error() string { return "scope: " + e.Message }

// Service stores scopes and answers scope decisions.
type Service struct {
	src       Source
	manifests Manifests
	now       func() time.Time

	snap atomic.Pointer[snapshot]
	mu   sync.Mutex // serializes rebuilds
}

type snapshot struct {
	at     time.Time
	scopes map[string]scopeSet
	conns  map[string]connInfo
	// allow caches the read allowlist per connector id.
	allow map[string]map[string]bool
}

type scopeSet struct {
	connectors  map[string]bool
	connections map[string]bool
	operations  map[string]map[string]bool
}

type connInfo struct {
	connector string
	live      bool
}

// New returns a Service. now defaults to time.Now when nil.
func New(src Source, manifests Manifests, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{src: src, manifests: manifests, now: now}
}

// Get returns the stored scope of principal; an unknown principal yields the
// empty scope.
func (s *Service) Get(principal string) store.Scope {
	for _, sc := range s.src.Snapshot().Scopes {
		if sc.Principal == principal {
			return sc
		}
	}
	return store.Scope{Principal: principal, Connectors: []string{}, Connections: []string{}, Operations: map[string][]string{}}
}

// Put validates and stores the scope of principal. On any error the previous
// scope is kept unchanged.
func (s *Service) Put(principal string, sc store.Scope) error {
	if principal != Principal {
		return &ValidationError{Field: "principal", Message: fmt.Sprintf("unknown principal %q", principal)}
	}
	err := s.src.Update(func(st *store.State) error {
		clean, err := s.validate(principal, sc, st.Connections)
		if err != nil {
			return err
		}
		for i := range st.Scopes {
			if st.Scopes[i].Principal == principal {
				st.Scopes[i] = clean
				return nil
			}
		}
		st.Scopes = append(st.Scopes, clean)
		return nil
	})
	s.Invalidate()
	return err
}

func (s *Service) validate(principal string, sc store.Scope, conns []store.Connection) (store.Scope, error) {
	out := store.Scope{Principal: principal, Operations: map[string][]string{}}
	out.Connectors = uniqueSorted(sc.Connectors)
	for _, id := range out.Connectors {
		if _, ok := s.manifests.Get(id); !ok {
			return store.Scope{}, &ValidationError{Field: "connectors", Message: fmt.Sprintf("unknown connector %q", id)}
		}
	}
	out.Connections = uniqueSorted(sc.Connections)
	for _, id := range out.Connections {
		if !liveConnection(conns, id) {
			return store.Scope{}, &ValidationError{Field: "connections", Message: fmt.Sprintf("unknown connection %q", id)}
		}
	}
	connectors := make([]string, 0, len(sc.Operations))
	for id := range sc.Operations {
		connectors = append(connectors, id)
	}
	sort.Strings(connectors) // deterministic error: the first offender by name
	for _, id := range connectors {
		allow, ok := s.readAllowlist(id)
		if !ok {
			return store.Scope{}, &ValidationError{Field: "operations", Message: fmt.Sprintf("unknown connector %q", id)}
		}
		ops := uniqueSorted(sc.Operations[id])
		for _, op := range ops {
			if !allow[op] {
				return store.Scope{}, &ValidationError{Field: "operations", Operation: op,
					Message: fmt.Sprintf("operation %q is not on the read allowlist of connector %q", op, id)}
			}
		}
		out.Operations[id] = ops
	}
	return out, nil
}

// Invalidate drops the snapshot so the next decision rebuilds it. Call it
// after any change of connections that does not go through Put.
func (s *Service) Invalidate() { s.snap.Store(nil) }

// AgentInputs implements broker.AgentGate. It never blocks on I/O beyond the
// periodic snapshot rebuild and denies on any unknown fact.
func (s *Service) AgentInputs(principal, connectionID, connectorID, operation string) policy.AgentInputs {
	snap := s.current()
	sc, ok := snap.scopes[principal]
	if !ok || len(sc.connections) == 0 {
		return policy.AgentInputs{Why: "empty_scope"}
	}
	conn, ok := snap.conns[connectionID]
	if !ok || conn.connector != connectorID {
		return policy.AgentInputs{Why: "unknown_connection"}
	}
	switch {
	case !sc.connectors[connectorID]:
		return policy.AgentInputs{Why: "connector_not_in_scope"}
	case !sc.connections[connectionID]:
		return policy.AgentInputs{Why: "connection_not_in_scope"}
	case !sc.operations[connectorID][operation]:
		return policy.AgentInputs{Why: "operation_not_in_scope"}
	case !snap.allow[connectorID][operation]:
		return policy.AgentInputs{Why: "operation_not_allowlisted"}
	}
	if !conn.live {
		return policy.AgentInputs{InScope: true, Why: "live_reads_disabled"}
	}
	return policy.AgentInputs{InScope: true, LiveReads: true}
}

func (s *Service) current() *snapshot {
	if sn := s.snap.Load(); sn != nil && s.now().Sub(sn.at) < MaxAge {
		return sn
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if sn := s.snap.Load(); sn != nil && s.now().Sub(sn.at) < MaxAge {
		return sn
	}
	sn := s.build()
	s.snap.Store(sn)
	return sn
}

func (s *Service) build() *snapshot {
	st := s.src.Snapshot()
	sn := &snapshot{
		at:     s.now(),
		scopes: map[string]scopeSet{},
		conns:  map[string]connInfo{},
		allow:  map[string]map[string]bool{},
	}
	for _, c := range st.Connections {
		if c.Removed {
			continue
		}
		sn.conns[c.ID] = connInfo{connector: c.ConnectorID, live: c.AllowAgentLiveReads}
		if _, ok := sn.allow[c.ConnectorID]; !ok {
			allow, _ := s.readAllowlist(c.ConnectorID)
			sn.allow[c.ConnectorID] = allow
		}
	}
	for _, sc := range st.Scopes {
		set := scopeSet{
			connectors:  toSet(sc.Connectors),
			connections: toSet(sc.Connections),
			operations:  map[string]map[string]bool{},
		}
		for id, ops := range sc.Operations {
			set.operations[id] = toSet(ops)
		}
		sn.scopes[sc.Principal] = set
	}
	return sn
}

// readAllowlist returns the names of the read-class, non-write operations of a
// connector's manifest.
func (s *Service) readAllowlist(connectorID string) (map[string]bool, bool) {
	e, ok := s.manifests.Get(connectorID)
	if !ok {
		return nil, false
	}
	out := map[string]bool{}
	for _, op := range e.Manifest.Operations {
		if op.Class == manifest.ClassRead && !manifest.IsWrite(op) {
			out[op.Name] = true
		}
	}
	return out, true
}

// ReadOperations lists the read allowlist of a connector, sorted, for editors.
func (s *Service) ReadOperations(connectorID string) ([]string, error) {
	allow, ok := s.readAllowlist(connectorID)
	if !ok {
		return nil, errors.New("scope: unknown connector")
	}
	out := make([]string, 0, len(allow))
	for n := range allow {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

func liveConnection(conns []store.Connection, id string) bool {
	for _, c := range conns {
		if c.ID == id && !c.Removed {
			return true
		}
	}
	return false
}

func toSet(in []string) map[string]bool {
	out := make(map[string]bool, len(in))
	for _, v := range in {
		out[v] = true
	}
	return out
}

func uniqueSorted(in []string) []string {
	set := toSet(in)
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
