// Package gql serves the Bellu Graph Engine over GraphQL: the schema in
// schema.graphqls, the gqlgen-generated executor (generated.go,
// models_gen.go) and the hand-written resolvers over *engine.Core.
//
// Authentication, the readiness check and caller resolution belong to the
// Facade, which wraps the handler and supplies Options.CallerRole and
// Options.Annotate.
package gql

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/99designs/gqlgen/graphql"
	"github.com/99designs/gqlgen/graphql/errcode"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/extension"
	"github.com/99designs/gqlgen/graphql/handler/lru"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/engine"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
)

// Limits checked before execution.
const (
	MaxDepth      = 12
	MaxComplexity = 5000
)

// Error codes set in extensions.code.
const (
	CodeValidation  = "VALIDATION"
	CodeNotFound    = "NOT_FOUND"
	CodeForbidden   = "FORBIDDEN"
	CodeUnavailable = "UNAVAILABLE"
	CodeInternal    = "INTERNAL"
)

// RoleWrite is the role CallerRole must return for annotateEntity.
const RoleWrite = "write"

// AnnotateFunc applies an operator annotation to the entity id. The Facade
// implementation writes the audit record first and then calls Core.Annotate;
// when the audit write fails it returns an error and applies nothing.
type AnnotateFunc func(ctx context.Context, id string, set map[string]string, unset []string) error

// Options configure New. (Config is the name of the generated schema config.)
type Options struct {
	// Core is the Engine to serve. Required.
	Core *engine.Core
	// Annotate backs annotateEntity. Nil makes the mutation UNAVAILABLE.
	Annotate AnnotateFunc
	// CallerRole returns the role ("read", "ingest" or "write") of the
	// caller from the request context. Nil denies annotateEntity.
	CallerRole func(ctx context.Context) string
}

// New returns the GraphQL handler: POST, SSE (Accept: text/event-stream) and
// graphql-transport-ws websocket transports, introspection, a complexity
// limit of 5000, a depth limit of 12 and a 256-entry query cache. It panics
// when cfg.Core is nil.
func New(cfg Options) http.Handler {
	if cfg.Core == nil {
		panic("gql: Options.Core is required")
	}
	srv := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{cfg: cfg}}))
	srv.AddTransport(transport.SSE{})
	srv.AddTransport(transport.POST{})
	srv.AddTransport(transport.Websocket{KeepAlivePingInterval: 15 * time.Second})
	srv.SetQueryCache(lru.New[*ast.QueryDocument](256))
	srv.Use(extension.Introspection{})
	srv.Use(extension.FixedComplexityLimit(MaxComplexity))
	srv.Use(depthLimit{max: MaxDepth})
	srv.SetErrorPresenter(presentError)
	srv.AroundOperations(func(ctx context.Context, next graphql.OperationHandler) graphql.ResponseHandler {
		return next(withLoader(ctx, cfg.Core))
	})
	return srv
}

// depthLimit rejects operations whose selection sets nest deeper than max.
// Introspection roots (__schema, __type) are not counted: their shape is
// fixed by the schema and the standard introspection query nests deeper.
type depthLimit struct{ max int }

var _ interface {
	graphql.HandlerExtension
	graphql.OperationContextMutator
} = depthLimit{}

func (depthLimit) ExtensionName() string                   { return "DepthLimit" }
func (depthLimit) Validate(graphql.ExecutableSchema) error { return nil }
func (d depthLimit) MutateOperationContext(_ context.Context, oc *graphql.OperationContext) *gqlerror.Error {
	if oc.Operation == nil {
		return nil
	}
	if depth := selectionDepth(oc.Operation.SelectionSet, true); depth > d.max {
		err := gqlerror.Errorf("operation depth %d exceeds the limit of %d", depth, d.max)
		errcode.Set(err, CodeValidation)
		return err
	}
	return nil
}

// selectionDepth is the deepest field nesting in ss; fragments add no depth.
func selectionDepth(ss ast.SelectionSet, root bool) int {
	best := 0
	for _, s := range ss {
		var d int
		switch s := s.(type) {
		case *ast.Field:
			if root && (s.Name == "__schema" || s.Name == "__type") {
				continue
			}
			d = 1 + selectionDepth(s.SelectionSet, false)
		case *ast.InlineFragment:
			d = selectionDepth(s.SelectionSet, root)
		case *ast.FragmentSpread:
			if s.Definition != nil {
				d = selectionDepth(s.Definition.SelectionSet, root)
			}
		}
		best = max(best, d)
	}
	return best
}

// presentError maps errs sentinels to extensions.code. Framework errors
// (parse, validation, limits) become VALIDATION with their message; any
// other resolver error becomes INTERNAL with a generic message.
func presentError(ctx context.Context, err error) *gqlerror.Error {
	var gerr *gqlerror.Error
	if !errors.As(err, &gerr) {
		gerr = gqlerror.WrapPath(graphql.GetPath(ctx), err)
	}
	cause := gerr.Err
	if cause == nil {
		code, _ := gerr.Extensions["code"].(string)
		switch code {
		case errcode.ValidationFailed, errcode.ParseFailed, "COMPLEXITY_LIMIT_EXCEEDED", CodeValidation, "":
			if code == "" && gerr.Path != nil {
				// A field error raised by the executor itself (for example a
				// null in a non-null position).
				return withCode(gerr, CodeInternal, "internal error")
			}
			return withCode(gerr, CodeValidation, gerr.Message)
		}
		return withCode(gerr, CodeInternal, "internal error")
	}
	switch {
	case errors.Is(cause, errs.Validation), errors.Is(cause, errs.Overflow):
		return withCode(gerr, CodeValidation, gerr.Message)
	case errors.Is(cause, errs.NotFound):
		return withCode(gerr, CodeNotFound, gerr.Message)
	case errors.Is(cause, errs.Forbidden):
		return withCode(gerr, CodeForbidden, gerr.Message)
	case errors.Is(cause, errs.Unavailable):
		return withCode(gerr, CodeUnavailable, gerr.Message)
	}
	return withCode(gerr, CodeInternal, "internal error")
}

func withCode(e *gqlerror.Error, code, msg string) *gqlerror.Error {
	out := &gqlerror.Error{Message: msg, Path: e.Path, Locations: e.Locations, Rule: e.Rule}
	out.Extensions = map[string]any{"code": code}
	return out
}
