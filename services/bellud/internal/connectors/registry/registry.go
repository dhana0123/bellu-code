// Package registry holds the connector manifests known to bellud. Built-in
// and plugin connectors share one Entry shape; only Plugin differs.
package registry

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/manifest"
)

// ErrDuplicate is returned by Register when the manifest id is already taken.
var ErrDuplicate = errors.New("registry: duplicate connector id")

// ErrInvalid is returned (wrapped in *InvalidError) for manifests failing Validate.
var ErrInvalid = errors.New("registry: invalid manifest")

// InvalidError carries the field errors from manifest.Validate. Values are
// never echoed, only field names and messages.
type InvalidError struct{ Fields []manifest.FieldError }

func (e *InvalidError) Error() string {
	parts := make([]string, len(e.Fields))
	for i, f := range e.Fields {
		parts[i] = f.Error()
	}
	return ErrInvalid.Error() + ": " + strings.Join(parts, "; ")
}

func (e *InvalidError) Unwrap() error { return ErrInvalid }

// Entry is a registered connector. Built-ins and plugins have the same shape.
type Entry struct {
	Manifest manifest.Manifest
	// Plugin is true for Plugin_Connectors and false for built-ins.
	Plugin bool
}

// Registry lists, looks up and registers connector manifests.
type Registry interface {
	List() []Entry
	Get(id string) (Entry, bool)
	Register(m manifest.Manifest) error
}

type memRegistry struct {
	mu      sync.RWMutex
	entries map[string]Entry
}

// New returns an empty, mutex-guarded in-memory Registry.
func New() Registry { return &memRegistry{entries: map[string]Entry{}} }

func (r *memRegistry) Register(m manifest.Manifest) error {
	if errs := manifest.Validate(m); len(errs) > 0 {
		return &InvalidError{Fields: errs}
	}
	e := Entry{Manifest: clone(m), Plugin: !m.Builtin}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.entries[m.ID]; ok {
		return fmt.Errorf("%w: %s", ErrDuplicate, m.ID)
	}
	r.entries[m.ID] = e
	return nil
}

func (r *memRegistry) Get(id string) (Entry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[id]
	if !ok {
		return Entry{}, false
	}
	e.Manifest = clone(e.Manifest)
	return e, true
}

// List returns all entries sorted by manifest id.
func (r *memRegistry) List() []Entry {
	r.mu.RLock()
	out := make([]Entry, 0, len(r.entries))
	for _, e := range r.entries {
		e.Manifest = clone(e.Manifest)
		out = append(out, e)
	}
	r.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Manifest.ID < out[j].Manifest.ID })
	return out
}

// clone copies the manifest's slices so callers cannot mutate registry state.
func clone(m manifest.Manifest) manifest.Manifest {
	m.AuthMethods = append([]manifest.AuthMethod(nil), m.AuthMethods...)
	m.Permissions = append([]manifest.Permission(nil), m.Permissions...)
	ops := append([]manifest.Operation(nil), m.Operations...)
	for i := range ops {
		ops[i].StripKeys = append([]string(nil), ops[i].StripKeys...)
	}
	m.Operations = ops
	m.Egress = append([]string(nil), m.Egress...)
	m.Entities = append([]string(nil), m.Entities...)
	return m
}
