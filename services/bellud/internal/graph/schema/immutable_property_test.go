package schema

import (
	"reflect"
	"testing"

	"pgregory.net/rapid"
)

// Feature: aws-relationship-registry, Property 3: Rejected additions and late additions change nothing
//
// Validates: Requirements 1.6, 1.8

// registryState is everything the registry exposes, for before/after comparison.
type registryState struct {
	Kinds      []KindDeclaration
	Relations  []RelationDeclaration
	Categories []CategoryDeclaration
}

func stateOf(r *Registry) registryState {
	return registryState{Kinds: r.Kinds(), Relations: r.Relations(), Categories: r.Categories()}
}

var nameGen = rapid.StringMatching(`[a-z][a-z0-9_]{0,10}`)

// genCoreDecl draws a valid core declaration with unique kind and relation names.
func genCoreDecl(t *rapid.T) SourceDeclaration {
	d := SourceDeclaration{Source: SourceCore}
	kinds := rapid.SliceOfNDistinct(nameGen, 1, 6, func(s string) string { return s }).Draw(t, "kindNames")
	for _, n := range kinds {
		d.Kinds = append(d.Kinds, KindDeclaration{
			Name:        n,
			Identity:    rapid.SliceOfNDistinct(nameGen, 1, 4, func(s string) string { return s }).Draw(t, "identity"),
			Description: "A kind.",
		})
	}
	rels := rapid.SliceOfNDistinct(nameGen, 0, 6, func(s string) string { return s }).Draw(t, "relNames")
	for _, n := range rels {
		d.Relations = append(d.Relations, RelationDeclaration{
			Name:        n,
			Direction:   rapid.SampledFrom([]Direction{Reverse, Forward}).Draw(t, "dir"),
			Confidence:  rapid.SampledFrom([]Confidence{Extracted, Inferred}).Draw(t, "conf"),
			Description: "A relation.",
		})
	}
	return d
}

// genInvalidDecl draws a declaration that the check must reject, some of them
// conflicting with base.
func genInvalidDecl(t *rapid.T, base SourceDeclaration) SourceDeclaration {
	switch rapid.IntRange(0, 3).Draw(t, "invalidKind") {
	case 0: // blank description
		return SourceDeclaration{Source: SourceGitHub, Prefix: "github_", Kinds: []KindDeclaration{
			{Name: "github_x", Identity: []string{"id"}, Description: "  "},
		}}
	case 1: // invalid name
		return SourceDeclaration{Source: SourceGitHub, Prefix: "github_", Relations: []RelationDeclaration{
			{Name: "Bad-Name", Direction: Forward, Confidence: Extracted, Description: "x"},
		}}
	case 2: // same kind name as base, different identity
		k := rapid.SampledFrom(base.Kinds).Draw(t, "kind")
		return SourceDeclaration{Source: SourceGitHub, Prefix: "github_", Kinds: []KindDeclaration{
			{Name: k.Name, Identity: append(append([]string{}, k.Identity...), "extra_attr"), Description: "Conflicts."},
		}}
	default: // bad confidence
		return SourceDeclaration{Source: SourceGitHub, Prefix: "github_", Relations: []RelationDeclaration{
			{Name: "github_rel", Direction: Forward, Confidence: "maybe", Description: "x"},
		}}
	}
}

func TestPropertyRegistryImmutable(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		base := genCoreDecl(t)

		var b Builder
		if err := b.Add(base); err != nil {
			t.Fatalf("valid base rejected: %v", err)
		}
		reg, err := b.Build()
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		before := stateOf(reg)

		// A rejected addition leaves the builder and its result unchanged.
		if err := b.Add(genInvalidDecl(t, base)); err == nil {
			t.Fatal("invalid declaration accepted")
		}
		again, err := b.Build()
		if err != nil {
			t.Fatalf("Build after rejected Add: %v", err)
		}
		if !reflect.DeepEqual(before, stateOf(again)) {
			t.Fatal("rejected Add changed the built registry")
		}

		// Late additions to a built registry fail and change nothing, valid or not.
		late := genCoreDecl(t)
		late.Source = SourceGitHub
		late.Prefix = ""
		for _, d := range []SourceDeclaration{late, genInvalidDecl(t, base), {}} {
			if err := reg.Register(d); err != ErrImmutable {
				t.Fatalf("Register = %v, want ErrImmutable", err)
			}
		}
		if !reflect.DeepEqual(before, stateOf(reg)) {
			t.Fatal("Register changed the registry")
		}

		// Mutating returned copies does not reach the registry.
		for _, k := range reg.Kinds() {
			if len(k.Identity) > 0 {
				k.Identity[0] = "tampered"
			}
		}
		if !reflect.DeepEqual(before, stateOf(reg)) {
			t.Fatal("mutating a returned copy changed the registry")
		}
	})
}
