// Package graph is the entry point the rest of bellud uses for the in-process
// Bellu Graph Engine. It re-exports the bellud-owned facade so no other package
// imports vendored engine code.
package graph

import (
	"context"
	"os"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/facade"
)

// release is set at link time: -ldflags "-X github.com/bellu/bellucode/services/bellud/internal/graph.release=true".
// Release builds default the graph to off; dev builds default it to on.
var release = ""

// IsRelease reports whether this is a release build.
func IsRelease() bool { return release == "true" || release == "1" }

type (
	Config        = facade.Config
	ConfigError   = facade.ConfigError
	Engine        = facade.Engine
	Ingest        = facade.Ingest
	Query         = facade.Query
	State         = facade.State
	Kind          = facade.Kind
	Batch         = facade.Batch
	Receipt       = facade.Receipt
	EntityID      = facade.EntityID
	Entity        = facade.Entity
	FindQuery     = facade.FindQuery
	NeighborOpts  = facade.NeighborOpts
	Edge          = facade.Edge
	TimeRange     = facade.TimeRange
	Change        = facade.Change
	ChangeFilter  = facade.ChangeFilter
	Diff          = facade.Diff
	Paging        = facade.Paging
	ChangeKind    = facade.ChangeKind
	ChangeSubject = facade.ChangeSubject
)

type Page[T any] = facade.Page[T]

const (
	StateDisabled   = facade.StateDisabled
	StateStarting   = facade.StateStarting
	StateReady      = facade.StateReady
	StateFailed     = facade.StateFailed
	CodeUnavailable = facade.CodeUnavailable

	DefaultPageSize = facade.DefaultPageSize
	MaxPageSize     = facade.MaxPageSize
	DirOut          = facade.DirOut
	DirIn           = facade.DirIn
	DirBoth         = facade.DirBoth
	ChangeAdded     = facade.ChangeAdded
	ChangeChanged   = facade.ChangeChanged
	ChangeRemoved   = facade.ChangeRemoved
	SubjectEntity   = facade.SubjectEntity
	SubjectRelation = facade.SubjectRelation
)

var (
	ErrUnavailable         = facade.ErrUnavailable
	ErrInsecurePermissions = facade.ErrInsecurePermissions
	ErrLocked              = facade.ErrLocked
	ErrCorrupt             = facade.ErrCorrupt
	ErrNotFound            = facade.ErrNotFound
	ErrValidation          = facade.ErrValidation
)

// LoadConfig reads BELLU_GRAPH_* from the process environment using the build default.
func LoadConfig() (Config, error) { return LoadConfigFrom(os.Getenv) }

// LoadConfigFrom is LoadConfig with an injectable environment.
func LoadConfigFrom(getenv func(string) string) (Config, error) {
	return facade.LoadConfig(getenv, !IsRelease())
}

// Open starts the engine in-process. See facade.Open for failure semantics.
func Open(ctx context.Context, cfg Config) (Engine, error) { return facade.Open(ctx, cfg) }

// StateOf reports the engine status.
func StateOf(e Engine) State { return facade.StateOf(e) }

// UnavailableHandler answers 503 {"code":"graph_unavailable"}.
var UnavailableHandler = facade.UnavailableHandler
