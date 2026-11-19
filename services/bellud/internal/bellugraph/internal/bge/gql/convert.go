package gql

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/engine"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/uri"
)

// ref resolves an entity reference argument (Entity_ID, Local_ID or URI).
func (r *Resolver) ref(name, v string) (engine.EntityID, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", fmt.Errorf("%w: %s is required", errs.Validation, name)
	}
	return r.cfg.Core.Resolve(v)
}

// optRef resolves an optional entity reference; nil or empty yields "".
func (r *Resolver) optRef(name string, v *string) (engine.EntityID, error) {
	if v == nil || strings.TrimSpace(*v) == "" {
		return "", nil
	}
	return r.ref(name, *v)
}

// entityOf converts an engine view read at the instant at.
func entityOf(e engine.EntityView, at *time.Time) *Entity {
	attrs := e.Attributes
	if attrs == nil {
		attrs = map[string]any{}
	}
	ann := e.Annotations
	if ann == nil {
		ann = map[string]string{}
	}
	return &Entity{
		ID: e.ID, IdentityFingerprint: e.ID, Kind: e.Kind, Label: e.Label,
		Attributes: attrs, Annotations: ann,
		ObservedAt: e.ObservedAt.UTC(), RecordedAt: e.RecordedAt.UTC(),
		URI: entityURI(e.ID), at: at,
	}
}

func entityURI(id string) string {
	kind, hex, ok := strings.Cut(id, ":")
	if !ok {
		return ""
	}
	u, err := uri.Format(uri.Entity{Kind: kind, Hex: hex})
	if err != nil {
		return ""
	}
	return u
}

func edgeOf(e engine.EdgeView, at *time.Time) *Edge {
	return &Edge{Type: e.Type, Direction: dirOut(e.Direction), Hops: e.Hops, Derived: e.Derived,
		Evidence: nonEmpty(e.Evidence), Confidence: nonEmpty(e.Confidence), ObservedAt: nonEmpty(e.ObservedAt),
		fromID: e.From, toID: e.To, at: at}
}

func edgesOf(es []engine.EdgeView, at *time.Time) []*Edge {
	out := make([]*Edge, len(es))
	for i, e := range es {
		out[i] = edgeOf(e, at)
	}
	return out
}

// dirIn maps the schema enum to the engine direction; nil is BOTH.
func dirIn(d *Direction) string {
	if d == nil {
		return engine.DirBoth
	}
	switch *d {
	case DirectionOut:
		return engine.DirOut
	case DirectionIn:
		return engine.DirIn
	}
	return engine.DirBoth
}

func dirOut(d string) Direction {
	switch d {
	case engine.DirOut:
		return DirectionOut
	case engine.DirIn:
		return DirectionIn
	}
	return DirectionBoth
}

func changeOf(c engine.ChangeView) *Change {
	out := &Change{
		Seq:        strconv.FormatUint(c.Seq, 10),
		Kind:       ChangeKind(strings.ToUpper(string(c.Kind))),
		Subject:    Subject(strings.ToUpper(string(c.Subject))),
		ObservedAt: c.ObservedAt.UTC(),
		RecordedAt: c.RecordedAt.UTC(),
	}
	if c.Entity != "" {
		out.Entity = ptr(c.Entity)
	}
	if c.From != "" {
		out.From = ptr(c.From)
	}
	if c.To != "" {
		out.To = ptr(c.To)
	}
	if c.RelationType != "" {
		out.RelationType = ptr(c.RelationType)
	}
	return out
}

func changePage(p engine.Page[engine.ChangeView]) *ChangePage {
	out := &ChangePage{Items: make([]*Change, len(p.Items)), Total: p.Total, Truncated: p.Truncated, NextCursor: cursor(p.NextCursor)}
	for i, c := range p.Items {
		out.Items[i] = changeOf(c)
	}
	return out
}

// changeFilter converts the schema filter, resolving its entity reference.
func (r *Resolver) changeFilter(f *ChangeFilter) (engine.ChangeFilter, error) {
	var out engine.ChangeFilter
	if f == nil {
		return out, nil
	}
	if f.Kind != nil {
		out.Kind = engine.ChangeKind(strings.ToLower(string(*f.Kind)))
	}
	if f.Subject != nil {
		out.Subject = engine.ChangeSubject(strings.ToLower(string(*f.Subject)))
	}
	if f.EntityKind != nil {
		out.EntityKind = *f.EntityKind
	}
	id, err := r.optRef("filter.entity", f.Entity)
	if err != nil {
		return out, err
	}
	out.Entity = id
	return out, nil
}

func flapsOf(fs []engine.Flap) []*Flap {
	out := make([]*Flap, len(fs))
	for i, f := range fs {
		out[i] = &Flap{Entity: f.ID, Changes: f.Changes}
	}
	return out
}

// sharedAttrs drops secret-named keys.
func sharedAttrs(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		if !ident.IsSecretName(k) {
			out[k] = v
		}
	}
	return out
}

// paging converts first/after; nil first means the engine default.
func paging(first *int, after *string) engine.Paging {
	var p engine.Paging
	if first != nil {
		p.PageSize = *first
		if *first == 0 {
			// 0 would select the default; reject it like other out-of-range sizes.
			p.PageSize = -1
		}
	}
	if after != nil {
		p.Cursor = *after
	}
	return p
}

func intOr(v *int, def int) int {
	if v == nil {
		return def
	}
	return *v
}

func cursor(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func ptr[T any](v T) *T { return &v }

func zeroIfNil(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

// stringMap converts a JSON object argument whose values must be strings.
func stringMap(name string, v any) (map[string]string, error) {
	if v == nil {
		return map[string]string{}, nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: %s must be an object of strings", errs.Validation, name)
	}
	out := make(map[string]string, len(m))
	for k, val := range m {
		s, ok := val.(string)
		if !ok {
			return nil, fmt.Errorf("%w: %s.%s must be a string", errs.Validation, name, k)
		}
		out[k] = s
	}
	return out, nil
}

// loader caches entities per operation, keyed by ID and read instant, so the
// endpoints of many edges are read once each.
type loader struct {
	core *engine.Core
	mu   sync.Mutex
	m    map[loadKey]*Entity
}

type loadKey struct {
	id string
	at int64
	as bool
}

type loaderKey struct{}

func withLoader(ctx context.Context, c *engine.Core) context.Context {
	return context.WithValue(ctx, loaderKey{}, &loader{core: c, m: map[loadKey]*Entity{}})
}

// entity reads id at the instant at, through the operation's loader.
func (r *Resolver) entity(ctx context.Context, id engine.EntityID, at *time.Time) (*Entity, error) {
	l, _ := ctx.Value(loaderKey{}).(*loader)
	k := loadKey{id: id}
	if at != nil {
		k.at, k.as = at.UnixNano(), true
	}
	if l != nil {
		l.mu.Lock()
		e, ok := l.m[k]
		l.mu.Unlock()
		if ok {
			return e, nil
		}
	}
	v, err := r.cfg.Core.Entity(ctx, id, at)
	if err != nil {
		return nil, err
	}
	e := entityOf(v, at)
	if l != nil {
		l.mu.Lock()
		l.m[k] = e
		l.mu.Unlock()
	}
	return e, nil
}

// entities reads ids at at, skipping entities that are not found.
func (r *Resolver) entities(ctx context.Context, ids []engine.EntityID, at *time.Time) ([]*Entity, error) {
	out := make([]*Entity, 0, len(ids))
	for _, id := range ids {
		e, err := r.entity(ctx, id, at)
		if errors.Is(err, errs.NotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// neighbors serves the root and nested neighbors fields.
func (r *Resolver) neighbors(ctx context.Context, id engine.EntityID, direction *Direction, relationType *string, depth *int, resolve *bool, at *time.Time, first *int, after *string) (*EdgePage, error) {
	o := engine.NeighborOpts{
		Direction: dirIn(direction), Depth: intOr(depth, 1),
		Resolve: resolve == nil || *resolve,
		Paging:  paging(first, after),
	}
	if relationType != nil {
		o.RelationType = *relationType
	}
	if o.Depth == 0 {
		// 0 would select the default depth; reject it like other bad depths.
		o.Depth = -1
	}
	p, err := r.cfg.Core.Neighbors(ctx, id, o, at)
	if err != nil {
		return nil, err
	}
	return &EdgePage{Items: edgesOf(p.Items, at), Total: p.Total, Truncated: p.Truncated, NextCursor: cursor(p.NextCursor)}, nil
}

// history serves the root and nested history fields.
func (r *Resolver) history(ctx context.Context, id engine.EntityID, from, to *time.Time, first *int, after *string) (*ChangePage, error) {
	p, err := r.cfg.Core.History(ctx, id, engine.TimeRange{From: zeroIfNil(from), To: zeroIfNil(to)}, paging(first, after))
	if err != nil {
		return nil, err
	}
	return changePage(p), nil
}

// counts returns a non-nil JSON object for a count map.
func counts(m map[string]int) map[string]int {
	if m == nil {
		return map[string]int{}
	}
	return m
}

// nonEmpty returns nil for the empty string so absent attributes read as null.
func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
