// Package connectors serves the agent-facing connector MCP endpoint. It is a
// separate server from the graph MCP: it has its own per-start bearer token,
// exposes one tool (connector_read) and runs every call through broker.Do with
// caller "agent:<principal>". The broker consults the Session_Scope gate before
// every send, so the default (an empty scope) denies every call.
package connectors

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/audit"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/policy"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/scope"
	"github.com/bellu/bellucode/services/bellud/internal/mcptoken"
)

// Path is the only route of the connector MCP endpoint.
const Path = "/api/experimental/connectors/mcp"

// Limits.
const (
	// MaxResponseBytes caps the text returned to the agent (same as
	// broker.DoMaxBytes, which already caps the provider response).
	MaxResponseBytes = 64 << 10
	maxRequestBody   = 1 << 20
	// ToolName is the single tool of the endpoint.
	ToolName = "connector_read"
)

// Doer is the broker's Do; *broker.Broker implements it.
type Doer interface {
	Do(ctx context.Context, c broker.Call) (broker.Result, error)
}

// Resolver finds a live connection by alias or id and builds its broker
// reference (policy, credential slot, API host). Connectors/service.go wires it.
type Resolver interface {
	ResolveConnection(ref string) (broker.ConnectionRef, bool)
}

// Config configures NewMCP.
type Config struct {
	// Token is the per-start bearer token of this endpoint. It must be minted
	// separately from the graph tokens. A zero Token rejects every request.
	Token mcptoken.Token
	// Principal is the agent principal; empty means scope.Principal.
	Principal string
	Broker    Doer
	Resolver  Resolver
	Audit     audit.Log
	// Enabled reports the connectors feature flag; nil means disabled. When
	// it returns false the route answers 404.
	Enabled func() bool
	Version string
}

// ReadInput is the input of connector_read.
type ReadInput struct {
	Connection string         `json:"connection" jsonschema:"connection alias or id"`
	Operation  string         `json:"operation" jsonschema:"read operation name on the connector's allowlist"`
	Params     map[string]any `json:"params,omitempty" jsonschema:"operation parameters (path and query values)"`
}

type handler struct {
	cfg       Config
	principal string
	mcp       http.Handler
}

// NewMCP returns the http.Handler for Path.
func NewMCP(cfg Config) (http.Handler, error) {
	if cfg.Broker == nil || cfg.Resolver == nil {
		return nil, errors.New("connectors mcp: Broker and Resolver are required")
	}
	if cfg.Version == "" {
		cfg.Version = "dev"
	}
	h := &handler{cfg: cfg, principal: cfg.Principal}
	if h.principal == "" {
		h.principal = scope.Principal
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: "bellu-connectors", Title: "Bellu Connectors", Version: cfg.Version},
		&mcp.ServerOptions{Instructions: "Read-only live reads of connected services. Call connector_read with a connection alias, an allowlisted operation and its params. Access is limited by the user's scope; denials are final."})
	mcp.AddTool(srv, &mcp.Tool{
		Name:        ToolName,
		Description: "Run one allowlisted read operation against a connected service. Credentials are never visible; responses are redacted and capped at 64 KiB.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(true)},
	}, h.read)
	h.mcp = mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)
	return h, nil
}

func boolPtr(b bool) *bool { return &b }

// ServeHTTP authenticates with the endpoint's own token only. Graph tokens and
// bellud credentials are not accepted here.
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.cfg.Enabled == nil || !h.cfg.Enabled() {
		http.NotFound(w, r)
		return
	}
	if !h.cfg.Token.Verify(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="bellu-connectors"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	h.mcp.ServeHTTP(w, r)
}

func (h *handler) read(ctx context.Context, _ *mcp.CallToolRequest, in ReadInput) (*mcp.CallToolResult, any, error) {
	if h.cfg.Enabled == nil || !h.cfg.Enabled() {
		return toolError("connectors are disabled"), nil, nil
	}
	caller := policy.CallerAgentPrefix + h.principal
	ref, ok := h.cfg.Resolver.ResolveConnection(strings.TrimSpace(in.Connection))
	if !ok {
		// Same message whether the connection is missing or out of scope.
		h.auditUnknown(ctx, caller, in)
		return toolError("authorization error: not permitted"), nil, nil
	}
	res, err := h.cfg.Broker.Do(ctx, broker.Call{Connection: ref, Caller: caller, Operation: in.Operation, Params: in.Params})
	if err != nil {
		return toolError(describe(err)), nil, nil
	}
	body := string(res.Body)
	if len(body) > MaxResponseBytes {
		return toolError("response exceeds the 64 KiB cap"), nil, nil
	}
	out := &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: body}}}
	if res.Status >= 400 {
		out.IsError = true
	}
	return out, nil, nil
}

// auditUnknown records a call for a connection that does not resolve.
func (h *handler) auditUnknown(ctx context.Context, caller string, in ReadInput) {
	if h.cfg.Audit == nil {
		return
	}
	_ = h.cfg.Audit.Append(context.WithoutCancel(ctx), audit.Entry{
		Event: audit.EventScopeDenied, Outcome: audit.OutcomeBlocked, Actor: caller,
		Detail: map[string]string{
			"caller": caller, "connection": in.Connection, "operation": in.Operation,
			"reason": string(policy.ReasonScope), "violated": "scope", "why": "unknown_connection",
		},
	})
}

// describe maps a broker error to agent-visible text. Typed broker errors
// carry no credential or request data.
func describe(err error) string {
	var (
		be *broker.BlockedError
		ce *broker.CredentialError
		ne *broker.NetworkError
		re *broker.RateLimitedError
	)
	switch {
	case errors.As(err, &be):
		if be.Reason == policy.ReasonScope {
			return fmt.Sprintf("authorization error: denied by %s", be.Violated)
		}
		return fmt.Sprintf("denied: %s (%s)", be.Reason, be.Violated)
	case errors.As(err, &ce):
		return "credential unavailable"
	case errors.As(err, &re):
		return "rate limited, retry later"
	case errors.As(err, &ne):
		if ne.Timeout {
			return "network timeout"
		}
		return "network error"
	case errors.Is(err, broker.ErrTooLarge):
		return "response exceeds the 64 KiB cap"
	case errors.Is(err, broker.ErrBadParams):
		return "invalid parameters"
	}
	return "internal error"
}

func toolError(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: msg}}}
}
