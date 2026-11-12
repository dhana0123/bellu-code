package facade

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

// CodeUnavailable is the error code returned with HTTP 503 by every graph
// route while the engine is disabled or failed.
const CodeUnavailable = "graph_unavailable"

// The error values below are the engine's own sentinels, so errors.Is works
// for errors returned by the engine and by the Facade alike.
var (
	// ErrUnavailable is returned (wrapped) when the engine is not ready.
	ErrUnavailable = errs.Unavailable
	// ErrInsecurePermissions: the data dir has group/world bits set.
	ErrInsecurePermissions = errs.InsecurePermissions
	// ErrLocked: another process holds the store lock.
	ErrLocked = errs.Locked
	// ErrCorrupt: the store failed to open or validate; it is left untouched.
	ErrCorrupt = errs.Corrupt
	// ErrNotImplemented marks surface completed by later tasks (10.3).
	ErrNotImplemented = errors.New("not implemented")
	// ErrNotFound: the entity does not exist (at the requested time).
	ErrNotFound = errs.NotFound
	// ErrValidation is wrapped by every input rejection (batch or query).
	ErrValidation = errs.Validation
)

// Batch is one collector run's observations.
type Batch = batch.Batch

// Engine is the facade surface the rest of bellud uses.
type Engine interface {
	Ingest() Ingest
	Query() Query
	MCPHandler() http.Handler
	Close(ctx context.Context) error
}

// Ingest appends collector batches.
type Ingest interface {
	Apply(ctx context.Context, b Batch) (Receipt, error)
}

// Query reads the graph.
type Query interface {
	Entity(ctx context.Context, id EntityID, at *time.Time) (Entity, error)
	Find(ctx context.Context, q FindQuery) (Page[Entity], error)
	Neighbors(ctx context.Context, id EntityID, opt NeighborOpts) (Page[Edge], error)
	History(ctx context.Context, id EntityID, r TimeRange, p Paging) (Page[Change], error)
	Changes(ctx context.Context, r TimeRange, f ChangeFilter) (Page[Change], error)
	Diff(ctx context.Context, from, to time.Time) (Diff, error)
}

// Kind is the lifecycle phase of the engine.
type Kind string

const (
	StateDisabled Kind = "disabled"
	StateStarting Kind = "starting"
	StateReady    Kind = "ready"
	StateFailed   Kind = "failed"
)

// State is the engine status with a human-readable reason.
type State struct {
	Kind   Kind
	Reason string
}

// Stateful is implemented by every Engine returned from Open.
type Stateful interface{ State() State }

// StateOf reports e's state; an engine without State reports ready.
func StateOf(e Engine) State {
	if s, ok := e.(Stateful); ok {
		return s.State()
	}
	return State{Kind: StateReady}
}

// Page size bounds (Requirement 13.12, 13.13).
const (
	DefaultPageSize = 100
	MaxPageSize     = 1000
)

// EntityID is the stable Entity_ID: the engine identity hash of the entity
// kind and its registered identity attributes, "kind:<32 hex>". See Hash.
type EntityID string

// Receipt identifies one appended Batch.
type Receipt struct {
	// ID is the event ID of the first event of the append (a ULID), or a fresh
	// ULID when the batch produced no event.
	ID         string
	ObservedAt time.Time
	RecordedAt time.Time
	// Entities and Relations count the observations applied; Removed counts
	// entities and relations the full-observation semantics retired.
	Entities  int
	Relations int
	Removed   int
}

// Entity is an entity state. Attributes holds identity and descriptive
// attributes. ObservedAt/RecordedAt are those of the latest entity event
// folded into the state.
type Entity struct {
	ID         EntityID
	Type       string
	Label      string
	Attributes map[string]any
	// Annotations holds operator annotations; nil when there are none.
	Annotations map[string]string
	ObservedAt  time.Time
	RecordedAt  time.Time
}

// Paging selects a page. PageSize 0 means DefaultPageSize; values outside
// 1..MaxPageSize are rejected. Cursor is opaque and comes from NextCursor.
type Paging struct {
	PageSize int
	Cursor   string
}

// FindQuery filters live entities. Zero Type matches every kind.
type FindQuery struct {
	Type       string
	Attributes map[string]string // AND over identity and descriptive attributes
	Paging
}

// Edge directions.
const (
	DirOut  = "out"
	DirIn   = "in"
	DirBoth = "both"
)

// NeighborOpts selects the traversal. Zero Direction is DirBoth, zero Depth 1.
type NeighborOpts struct {
	Direction    string
	RelationType string
	Depth        int // 1..MaxNeighborDepth
	// Resolve includes derived endpoint-resolution edges.
	Resolve bool
	Paging
}

// MaxNeighborDepth bounds NeighborOpts.Depth.
const MaxNeighborDepth = 10

// Edge is a relation reached while traversing from the queried entity.
// Direction is relative to the traversal step ("out": followed From->To).
type Edge struct {
	From      EntityID
	To        EntityID
	Type      string
	Direction string
	Hops      int
	// Derived is true for resolves_to edges computed rather than stored.
	Derived bool
}

// TimeRange bounds observed_at, inclusive on both ends. A zero bound is open.
type TimeRange struct{ From, To time.Time }

// ChangeKind and ChangeSubject mirror packages/schema/src/graph.ts.
type (
	ChangeKind    string
	ChangeSubject string
)

const (
	ChangeAdded   ChangeKind = "added"
	ChangeChanged ChangeKind = "changed"
	ChangeRemoved ChangeKind = "removed"

	SubjectEntity   ChangeSubject = "entity"
	SubjectRelation ChangeSubject = "relation"
)

// Change is one entry of the log, classified by the engine.
type Change struct {
	Kind         ChangeKind
	Subject      ChangeSubject
	Entity       EntityID // subject entity
	From, To     EntityID // subject relation
	RelationType string
	ObservedAt   time.Time
	RecordedAt   time.Time
}

// ChangeFilter narrows Changes. Zero fields match everything. Entity matches a
// change about the entity or a relation touching it.
type ChangeFilter struct {
	Kind    ChangeKind
	Subject ChangeSubject
	Entity  EntityID
	Paging
}

// Diff compares the graph at two observed_at instants. Lists are capped at
// MaxPageSize each, with Truncated set when a cap was hit.
type Diff struct {
	From, To time.Time
	Added    []Entity
	Changed  []Entity
	Removed  []EntityID
	// Flapping lists entities that changed at least twice yet ended unchanged.
	Flapping  []Flap
	Truncated bool
}

// Flap is an entity with its change count over a Diff range.
type Flap struct {
	ID      EntityID
	Changes int
}

// Page is one page of results. Items is ordered by the query; Total counts the
// whole matching set; Truncated is true when more items follow (NextCursor).
type Page[T any] struct {
	Items      []T
	Total      int
	Truncated  bool
	Limit      int
	NextCursor string
}
