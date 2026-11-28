package schema

import "slices"

// Builder accumulates source declarations. It is the only mutable object in
// the package and is dropped after Build.
type Builder struct {
	accepted []SourceDeclaration // normalized, sorted by source
	required map[Source]Requirement
}

// Require makes Add and Build fail a declaration from source s that lacks any
// name in r, with one failure per missing name.
func (b *Builder) Require(s Source, r Requirement) {
	if b.required == nil {
		b.required = map[Source]Requirement{}
	}
	b.required[s] = r
}

// Add validates d alone and against the declarations accepted so far. On
// error it returns a *CheckError and leaves the Builder unchanged. Names that
// refer to other declarations (relation endpoints, categories) are resolved
// in Build, so the result does not depend on the order of Add calls.
func (b *Builder) Add(d SourceDeclaration) error {
	next := append(slices.Clone(b.accepted), normalize(d))
	sortDecls(next)
	if fs := check(next, b.required, false); len(fs) > 0 {
		return &CheckError{Failures: fs}
	}
	b.accepted = next
	return nil
}

// Build resolves cross-references and returns the immutable registry.
func (b *Builder) Build() (*Registry, error) {
	if fs := check(b.accepted, b.required, true); len(fs) > 0 {
		return nil, &CheckError{Failures: fs}
	}
	return newRegistry(b.accepted), nil
}

// Merge adds every declaration and builds the registry. It reports every
// failure in one error, with the same text for every ordering of ds.
func Merge(ds ...SourceDeclaration) (*Registry, error) {
	return MergeRequired(nil, ds...)
}

// MergeRequired is Merge with per-source required names.
func MergeRequired(required map[Source]Requirement, ds ...SourceDeclaration) (*Registry, error) {
	all := make([]SourceDeclaration, len(ds))
	for i, d := range ds {
		all[i] = normalize(d)
	}
	sortDecls(all)
	if fs := check(all, required, true); len(fs) > 0 {
		return nil, &CheckError{Failures: fs}
	}
	return newRegistry(all), nil
}
