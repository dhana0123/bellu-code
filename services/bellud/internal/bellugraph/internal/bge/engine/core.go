// Package engine wires the graph Projection, the Pebble store, the planner and
// the supporting services into the Engine core: Open, Apply, Annotate, Close.
// Reads, as-of queries, snapshots, retention and subscriptions are added by
// further files in this package.
package engine

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/graph"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/localid"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/metrics"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/plan"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/store"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/subscribe"
)

// Mode is how a Batch relates to the collector's earlier observations.
type Mode = plan.Mode

const (
	// ModeFull treats the Batch as the collector's complete observation.
	ModeFull = plan.ModeFull
	// ModePartial only adds and updates.
	ModePartial = plan.ModePartial
)

// Annotation is the operator-owned data of one entity.
type Annotation = graph.Annotation

// Receipt acknowledges an applied Batch.
type Receipt struct {
	ID                  string // ULID of the first appended Event, or a fresh ULID for a no-op
	ObservedAt          time.Time
	RecordedAt          time.Time
	Entities, Relations int
	Removed             int
}

// State is the lifecycle state of the Engine.
type State string

// Engine states.
const (
	StateStarting State = "starting"
	StateReady    State = "ready"
	StateClosing  State = "closing"
	StateClosed   State = "closed"
	StateFailed   State = "failed"
)

// Core is the Engine. Fields are declared here for every part of the Engine;
// later files only add methods.
type Core struct {
	// Annotations is a read view over the Projection (used by Facade tests).
	Annotations *Annotations

	dir   string
	opts  Options
	log   *slog.Logger
	clock func() time.Time
	met   *metrics.Set

	st *store.Store

	applyMu sync.Mutex   // serializes writers
	mu      sync.RWMutex // guards g
	g       *graph.Graph
	ulids   ulidGen

	hub *subscribe.Hub[ChangeView]
	ids *localid.Registry

	// Snapshot bookkeeping (written by the snapshot loop, read by Apply).
	snapMu          sync.Mutex
	lastSnapSeq     uint64
	eventsSinceSnap atomic.Uint64
	snapKick        chan struct{}

	stateMu sync.Mutex
	state   State
	failure error
	closing atomic.Bool

	closeMu sync.Mutex
	closed  bool
	onClose []func() // run on Close, before the store is closed

	bgCtx    context.Context
	bgCancel context.CancelFunc
	wg       sync.WaitGroup
}

// State returns the current lifecycle state.
func (c *Core) State() State {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.state
}

// Failure returns the reason the Engine is in StateFailed, or nil.
func (c *Core) Failure() error {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.failure
}

// setState moves to a new state and logs the transition with its reason.
func (c *Core) setState(to State, reason string) {
	c.stateMu.Lock()
	from := c.state
	if from == to {
		c.stateMu.Unlock()
		return
	}
	c.state = to
	c.stateMu.Unlock()
	c.log.Info("graph engine state changed", "from", string(from), "to", string(to), "reason", reason)
}

// fail moves the Engine to StateFailed (for example after a CRC mismatch on a
// read). Writers then return ErrUnavailable.
func (c *Core) fail(err error) {
	c.stateMu.Lock()
	if c.failure == nil {
		c.failure = err
	}
	c.stateMu.Unlock()
	c.setState(StateFailed, err.Error())
}

// Metrics returns the Prometheus text handler for the Engine's metrics.
func (c *Core) Metrics() http.Handler { return c.met.Handler() }
