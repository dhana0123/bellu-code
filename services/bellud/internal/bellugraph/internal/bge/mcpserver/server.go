// Package mcpserver serves the Bellu Graph Engine over MCP: the 12 typed
// tools, and (added by further files) resources and prompts.
//
// The package builds the MCP server and an http.Handler that speaks Streamable
// HTTP. Authentication, the 4 MiB body limit, the readiness check and caller
// resolution belong to the Facade, which wraps Server.Handler and supplies
// Config.CallerRole and Config.Annotate.
package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/engine"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
)

// Server identity reported to MCP clients.
const (
	Name  = "bellugraph"
	Title = "Bellu Graph Engine"
)

// Instructions is the server instructions text sent at initialization.
const Instructions = "Bellu Graph Engine: an infrastructure graph of hosts, processes, ports, containers, " +
	"images, repositories, dependencies and more, built from collector observations with a full change history. " +
	"Start with describe_schema, then find_entities. Entities are named by identity_fingerprint (stable) or a " +
	"short @local id (valid for about 15 minutes); every entity argument accepts either, or a bellugraph:// URI. " +
	"Use verbosity=brief to save context. Use get_neighbors, find_path and impact_of to explore relations, and " +
	"recent_changes, entity_history and graph_diff for what changed. Never ask for secret values."

// Roles understood by Config.CallerRole.
const (
	RoleRead   = "read"
	RoleIngest = "ingest"
	RoleWrite  = "write"
)

// ForbiddenMessage is the error text of a tool call that lacks the write role.
const ForbiddenMessage = "forbidden: needs write role"

// AnnotateFunc applies an operator annotation to the entity id. The Facade
// implementation writes the audit record first and then calls Core.Annotate;
// when the audit write fails it returns an error and applies nothing.
type AnnotateFunc func(ctx context.Context, id string, set map[string]string, unset []string) error

// Config configures New.
type Config struct {
	// Core is the Engine to serve. Required.
	Core *engine.Core
	// Version is reported as the server version. Empty means "dev".
	Version string
	// Annotate backs annotate_entity. Nil disables annotation (the tool
	// returns an error result).
	Annotate AnnotateFunc
	// CallerRole returns the role ("read", "ingest" or "write") of the caller
	// that made the tool call, from the request context. Nil denies
	// annotate_entity.
	CallerRole func(ctx context.Context) string
}

// Server is the Engine's MCP server.
type Server struct {
	cfg Config
	srv *mcp.Server
}

// New builds the MCP server with all tools registered.
func New(cfg Config) (*Server, error) {
	if cfg.Core == nil {
		return nil, errors.New("mcpserver: Config.Core is required")
	}
	if cfg.Version == "" {
		cfg.Version = "dev"
	}
	s := &Server{cfg: cfg}
	s.srv = mcp.NewServer(
		&mcp.Implementation{Name: Name, Title: Title, Version: cfg.Version},
		&mcp.ServerOptions{Instructions: Instructions},
	)
	s.registerTools()
	s.registerExtras()
	return s, nil
}

// MCP returns the underlying SDK server, for connecting in-memory transports
// and for adding resources and prompts.
func (s *Server) MCP() *mcp.Server { return s.srv }

// Handler returns the Streamable HTTP handler. The caller (the Facade) wraps
// it with body limits, readiness and caller resolution. The caller's context
// values are visible to Config.CallerRole.
func (s *Server) Handler() http.Handler {
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s.srv }, nil)
}

// ref resolves an Entity_Ref argument.
func (s *Server) ref(name, v string) (string, error) {
	if strings.TrimSpace(v) == "" {
		return "", fmt.Errorf("%w: %s is required", errs.Validation, name)
	}
	return s.cfg.Core.Resolve(strings.TrimSpace(v))
}

// parseTime parses an RFC 3339 instant; an empty string yields nil.
func parseTime(name, v string) (*time.Time, error) {
	if v == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return nil, fmt.Errorf("%w: %s %q is not an RFC 3339 time", errs.Validation, name, v)
	}
	return &t, nil
}

func zeroIfNil(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}
