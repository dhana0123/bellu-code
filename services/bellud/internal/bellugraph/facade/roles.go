package facade

import (
	"context"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
)

// Role is a caller's permission level.
type Role string

// Roles.
const (
	RoleRead   Role = "read"
	RoleIngest Role = "ingest"
	RoleWrite  Role = "write"
)

// Allows reports whether r may perform an operation needing the role need.
// Write allows everything; read and ingest allow only themselves.
func (r Role) Allows(need Role) bool {
	if r == RoleWrite {
		return need == RoleRead || need == RoleIngest || need == RoleWrite
	}
	return (r == RoleRead || r == RoleIngest) && r == need
}

// Grant maps a bearer token to a role.
type Grant struct {
	Token string
	Role  Role
}

// Caller is the authenticated party behind a request.
type Caller struct {
	Role     Role
	Identity string
}

type callerKey struct{}

// WithCaller returns ctx carrying c.
func WithCaller(ctx context.Context, c Caller) context.Context {
	return context.WithValue(ctx, callerKey{}, c)
}

// CallerFrom returns the Caller set by WithCaller.
func CallerFrom(ctx context.Context) (Caller, bool) {
	c, ok := ctx.Value(callerKey{}).(Caller)
	return c, ok
}

// ErrForbidden: the caller's role does not allow the operation.
var ErrForbidden = errs.Forbidden

// PathOpts bounds a path search. Zero MaxDepth means the engine default.
// StoredOnly excludes derived endpoint-resolution edges.
type PathOpts struct {
	MaxDepth   int
	StoredOnly bool
}

// PathResult is the outcome of Path.
type PathResult struct {
	Connected        bool
	Path             []Edge
	Exhausted        bool
	DepthSearched    int
	SharedNeighbors  []EntityID
	SharedAttributes map[string]string
}

// ImpactOpts bounds an impact traversal. Zero Depth means the engine default.
type ImpactOpts struct {
	Depth      int
	StoredOnly bool
}

// Impacted is an entity reached by Impact, with the relation path to it.
type Impacted struct {
	ID   EntityID
	Kind string
	Hops int
	Via  []Edge
}

// ImpactResult lists impacted entities ordered by (hops, ID).
type ImpactResult struct{ Items []Impacted }

// SubscribeOpts filters a subscription. From, when set, replays retained
// changes after that log sequence before live delivery.
type SubscribeOpts struct {
	Kind       ChangeKind
	Subject    ChangeSubject
	EntityKind string
	Entity     EntityID
	From       *uint64
}

// SeqChange is a Change with its log sequence.
type SeqChange struct {
	Seq uint64
	Change
}

// Subscription delivers committed changes until closed or overflowed.
type Subscription interface {
	// C yields changes; it is closed when the subscription ends.
	C() <-chan SeqChange
	// Err reports why C closed (nil after Close).
	Err() error
	Close()
}

// Extended is implemented by the ready engine beyond Engine.
type Extended interface {
	Annotate(ctx context.Context, ref string, set map[string]string, unset []string) (Entity, error)
	Resolve(ctx context.Context, ref string) (EntityID, error)
	Path(ctx context.Context, from, to string, o PathOpts) (PathResult, error)
	Impact(ctx context.Context, ref string, o ImpactOpts) (ImpactResult, error)
	Subscribe(ctx context.Context, o SubscribeOpts) (Subscription, error)
}

// ExtendedOf returns e's Extended surface, or false when e lacks it
// (disabled, failed, or not yet supported).
func ExtendedOf(e Engine) (Extended, bool) {
	x, ok := e.(Extended)
	return x, ok
}
