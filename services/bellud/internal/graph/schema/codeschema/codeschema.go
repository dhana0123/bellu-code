// Package codeschema declares the kinds and relation types that the code
// source owns: Graphify symbols, files, communities, and verified findings.
// It imports only the standard library and schema.
package codeschema

import (
	"errors"
	"fmt"
	"reflect"
	"slices"

	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
)

// Kind names.
const (
	KindSymbol    = "code_symbol"
	KindFile      = "code_file"
	KindCommunity = "code_community"
	KindFinding   = "finding"
)

// Relation type names.
const (
	RelDefinedIn          = "defined_in"
	RelCalls              = "calls"
	RelImports            = "imports"
	RelInCommunity        = "in_community"
	RelDeclaresDependency = "declares_dependency"
	RelBuiltInto          = "built_into"
	RelDeployedAs         = "deployed_as"
	RelReachableFrom      = "reachable_from"
	RelSupersedes         = "supersedes"
)

// Errors returned by a Set.
var (
	// ErrNameConflict reports a name registered with a different definition.
	ErrNameConflict = errors.New("codeschema: name already registered with a different definition")
	// ErrDirectionMismatch reports a relation whose source or target kind
	// does not match its registered direction.
	ErrDirectionMismatch = errors.New("codeschema: relation endpoint kinds violate the registered direction")
	// ErrUnknownRelation reports a relation type that is not registered.
	ErrUnknownRelation = errors.New("codeschema: unknown relation type")
)

func kind(name, desc string, identity ...string) schema.KindDeclaration {
	return schema.KindDeclaration{Name: name, Identity: identity, Description: desc}
}

func rel(name string, d schema.Direction, c schema.Confidence, from, to []string, desc string) schema.RelationDeclaration {
	return schema.RelationDeclaration{Name: name, Direction: d, Confidence: c, From: from, To: to, Description: desc}
}

func kinds() []schema.KindDeclaration {
	return []schema.KindDeclaration{
		kind(KindSymbol, "A code symbol (function, class, method) from the code graph, identified by its stable symbol id. Revision, path, and lines are descriptive.", "connection", "repo", "bid"),
		kind(KindFile, "A source or manifest file in a repository.", "connection", "repo", "path"),
		kind(KindCommunity, "A Leiden community of code symbols at a revision.", "connection", "repo", "community_id", "revision"),
		kind(KindFinding, "A finding produced by an execution agent and recorded only after verification.", "id"),
	}
}

func relations() []schema.RelationDeclaration {
	sym, file := []string{KindSymbol}, []string{KindFile}
	return []schema.RelationDeclaration{
		rel(RelDefinedIn, schema.Reverse, schema.Extracted, sym, file, "A symbol is defined in a file, so failure of the file impacts the symbol."),
		rel(RelCalls, schema.Reverse, schema.Extracted, sym, sym, "A symbol calls another symbol. Graphify tags the call extracted or inferred."),
		rel(RelImports, schema.Reverse, schema.Extracted, file, []string{KindFile, "package"}, "A file imports another file or a package."),
		rel(RelInCommunity, schema.Reverse, schema.Extracted, sym, []string{KindCommunity}, "A symbol belongs to a community."),
		rel(RelDeclaresDependency, schema.Reverse, schema.Extracted, file, []string{"package"}, "A manifest file declares a dependency on a package."),
		rel(RelBuiltInto, schema.Reverse, schema.Extracted, file, []string{"image", "workflow", "github_workflow"}, "A file is built into a container image or consumed by a workflow."),
		rel(RelDeployedAs, schema.Reverse, schema.Inferred, []string{"github_repo", "image"}, []string{"aws_resource"}, "A repository or image is deployed as a cloud resource, inferred until evidence confirms it."),
		rel(RelReachableFrom, schema.Forward, schema.Inferred, sym, sym, "A vulnerable symbol is reachable from another symbol along a call path."),
		rel(RelSupersedes, schema.Forward, schema.Inferred, sym, sym, "A symbol supersedes another after a rename or move."),
	}
}

// Declaration returns the code source declaration.
func Declaration() schema.SourceDeclaration {
	return schema.SourceDeclaration{Source: schema.SourceCode, Kinds: kinds(), Relations: relations()}
}

// Set is a registration table that rejects conflicting redefinitions. A
// failed registration leaves the set unchanged.
type Set struct {
	kinds map[string]schema.KindDeclaration
	rels  map[string]schema.RelationDeclaration
}

// NewSet returns a Set that holds the code declaration.
func NewSet() *Set {
	s := &Set{kinds: map[string]schema.KindDeclaration{}, rels: map[string]schema.RelationDeclaration{}}
	for _, k := range kinds() {
		s.kinds[k.Name] = k
	}
	for _, r := range relations() {
		s.rels[r.Name] = r
	}
	return s
}

// RegisterKind adds k. Registering an identical definition again is a no-op.
// A different definition under a registered name returns ErrNameConflict.
func (s *Set) RegisterKind(k schema.KindDeclaration) error {
	if old, ok := s.kinds[k.Name]; ok {
		if reflect.DeepEqual(old, k) {
			return nil
		}
		return fmt.Errorf("%w: kind %q", ErrNameConflict, k.Name)
	}
	s.kinds[k.Name] = k
	return nil
}

// RegisterRelation adds r with the same rules as RegisterKind.
func (s *Set) RegisterRelation(r schema.RelationDeclaration) error {
	if old, ok := s.rels[r.Name]; ok {
		if reflect.DeepEqual(old, r) {
			return nil
		}
		return fmt.Errorf("%w: relation %q", ErrNameConflict, r.Name)
	}
	s.rels[r.Name] = r
	return nil
}

// CheckRelation verifies that a relation of type rel from a source of kind
// fromKind to a target of kind toKind matches the registered endpoints.
// Empty endpoint lists allow any kind.
func (s *Set) CheckRelation(rel, fromKind, toKind string) error {
	r, ok := s.rels[rel]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownRelation, rel)
	}
	if len(r.From) > 0 && !slices.Contains(r.From, fromKind) {
		return fmt.Errorf("%w: %s source kind %q, want one of %v (%s)", ErrDirectionMismatch, rel, fromKind, r.From, r.Direction)
	}
	if len(r.To) > 0 && !slices.Contains(r.To, toKind) {
		return fmt.Errorf("%w: %s target kind %q, want one of %v (%s)", ErrDirectionMismatch, rel, toKind, r.To, r.Direction)
	}
	return nil
}
