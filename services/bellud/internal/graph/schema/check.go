package schema

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"
)

// Failure is one violated rule.
type Failure struct {
	Source  Source // the declaring source; the first in sorted order for a pair
	Other   Source // the second source of a conflict between two sources
	Subject string // "source", "kind", "relation", "type", "category"
	Name    string
	Rule    string
	Detail  string
}

func (f Failure) String() string {
	src := string(f.Source)
	if f.Other != "" {
		src += "/" + string(f.Other)
	}
	s := fmt.Sprintf("%s: %s %q: %s", src, f.Subject, f.Name, f.Rule)
	if f.Detail != "" {
		s += ": " + f.Detail
	}
	return s
}

// CheckError carries every failure of a check, sorted by source, name, and
// rule, so that one set of declarations gives one text in every order.
type CheckError struct{ Failures []Failure }

func (e *CheckError) Error() string {
	lines := make([]string, len(e.Failures))
	for i, f := range e.Failures {
		lines[i] = f.String()
	}
	return fmt.Sprintf("schema check failed with %d failure(s):\n%s", len(lines), strings.Join(lines, "\n"))
}

const (
	maxNameLen     = 64
	maxDescLen     = 500
	maxIdentityLen = 16
)

// genericRelations keep one meaning in every source.
var genericRelations = map[string]bool{
	"owned_by": true, "runs_on": true, "on": true, "uses": true, "attached_to": true,
	"depends_on": true, "mounts": true, "resolves_to": true, "found_in": true,
	"affected_by": true, "same_as": true, "likely_same_as": true,
}

// legacyNames are migrated kinds and relations exempt from the prefix rule.
var legacyNames = map[string]bool{
	"package": true, "vulnerability": true, "affected_by": true, "same_as": true, "likely_same_as": true,
}

var secretFragments = []string{"secret", "token", "password", "passwd", "credential", "private", "apikey", "api_key", "hash"}

// IsSecretName reports whether an attribute name looks secret-bearing.
func IsSecretName(name string) bool {
	l := strings.ToLower(name)
	for _, f := range secretFragments {
		if strings.Contains(l, f) {
			return true
		}
	}
	return false
}

// normalize copies d and sorts its lists so that input order never matters.
// Identity order is kept: it is part of a kind's meaning.
func normalize(d SourceDeclaration) SourceDeclaration {
	out := d
	out.Kinds = make([]KindDeclaration, len(d.Kinds))
	for i, k := range d.Kinds {
		k = cloneKind(k)
		slices.SortStableFunc(k.Types, func(a, b TypeDeclaration) int { return cmp.Compare(a.Name, b.Name) })
		out.Kinds[i] = k
	}
	slices.SortStableFunc(out.Kinds, func(a, b KindDeclaration) int { return cmp.Compare(a.Name, b.Name) })
	out.Relations = make([]RelationDeclaration, len(d.Relations))
	for i, r := range d.Relations {
		r = cloneRelation(r)
		slices.Sort(r.From)
		slices.Sort(r.To)
		out.Relations[i] = r
	}
	slices.SortStableFunc(out.Relations, func(a, b RelationDeclaration) int { return cmp.Compare(a.Name, b.Name) })
	out.Categories = make([]CategoryDeclaration, len(d.Categories))
	for i, c := range d.Categories {
		out.Categories[i] = cloneCategory(c)
	}
	slices.SortStableFunc(out.Categories, func(a, b CategoryDeclaration) int { return cmp.Compare(a.ID, b.ID) })
	return out
}

func sortDecls(ds []SourceDeclaration) {
	slices.SortStableFunc(ds, func(a, b SourceDeclaration) int { return cmp.Compare(a.Source, b.Source) })
}

// check applies every rule to normalized declarations sorted by source and
// returns all failures sorted. refs enables the rules that need every
// declaration to be present (endpoint and category names).
func check(ds []SourceDeclaration, required map[Source]Requirement, refs bool) []Failure {
	c := &checker{}
	for i, d := range ds {
		if i > 0 && ds[i-1].Source == d.Source {
			c.add(d.Source, "source", string(d.Source), "duplicate-source", "source declared more than once")
		}
		c.source(d)
		if r, ok := required[d.Source]; ok {
			c.required(d, r)
		}
	}
	c.crossSource(ds)
	if refs {
		c.references(ds)
	}
	slices.SortFunc(c.fs, func(a, b Failure) int {
		return cmp.Or(
			cmp.Compare(a.Source, b.Source), cmp.Compare(a.Name, b.Name), cmp.Compare(a.Rule, b.Rule),
			cmp.Compare(a.Subject, b.Subject), cmp.Compare(a.Other, b.Other), cmp.Compare(a.Detail, b.Detail),
		)
	})
	return slices.Compact(c.fs)
}

type checker struct{ fs []Failure }

func (c *checker) add(src Source, subject, name, rule, detail string) {
	c.fs = append(c.fs, Failure{Source: src, Subject: subject, Name: name, Rule: rule, Detail: detail})
}

func (c *checker) pair(a, b Source, subject, name, rule, detail string) {
	c.fs = append(c.fs, Failure{Source: a, Other: b, Subject: subject, Name: name, Rule: rule, Detail: detail})
}

// source applies the rules that need only one declaration.
func (c *checker) source(d SourceDeclaration) {
	if !validName(string(d.Source)) {
		c.add(d.Source, "source", string(d.Source), "name-pattern", "source name must match [a-z][a-z0-9_]* and be at most 64 characters")
	}
	seen := map[string]bool{}
	dup := func(subject, name string) {
		if seen[subject+"\x00"+name] {
			c.add(d.Source, subject, name, "duplicate-name", "declared twice by the same source")
		}
		seen[subject+"\x00"+name] = true
	}
	for _, k := range d.Kinds {
		dup("kind", k.Name)
		c.kind(d, k)
		for _, t := range k.Types {
			dup("type", t.Name)
			if strings.TrimSpace(t.Name) == "" || t.Name != strings.TrimSpace(t.Name) {
				c.add(d.Source, "type", t.Name, "name-pattern", "type name must be non-blank and have no surrounding space")
			}
			c.description(d.Source, "type", t.Name, t.Description)
		}
	}
	for _, r := range d.Relations {
		dup("relation", r.Name)
		c.relation(d, r)
	}
	for _, cat := range d.Categories {
		dup("category", cat.ID)
		if !validName(cat.ID) {
			c.add(d.Source, "category", cat.ID, "name-pattern", "category id must match [a-z][a-z0-9_]* and be at most 64 characters")
		}
		if strings.TrimSpace(cat.Name) == "" {
			c.add(d.Source, "category", cat.ID, "name-blank", "category name must not be blank")
		}
		if cat.Status != Implemented && cat.Status != RegisteredOnly {
			c.add(d.Source, "category", cat.ID, "status", fmt.Sprintf("status %q must be %q or %q", cat.Status, Implemented, RegisteredOnly))
		}
	}
}

func (c *checker) kind(d SourceDeclaration, k KindDeclaration) {
	if !validName(k.Name) {
		c.add(d.Source, "kind", k.Name, "name-pattern", "kind name must match [a-z][a-z0-9_]* and be at most 64 characters")
	}
	c.prefix(d, "kind", k.Name)
	c.description(d.Source, "kind", k.Name, k.Description)
	if n := len(k.Identity); n < 1 || n > maxIdentityLen {
		c.add(d.Source, "kind", k.Name, "identity-count", fmt.Sprintf("identity has %d attributes, want 1..%d", n, maxIdentityLen))
	}
	seen := map[string]bool{}
	for _, a := range k.Identity {
		switch {
		case a == "":
			c.add(d.Source, "kind", k.Name, "identity-empty", "identity attribute name is empty")
		case seen[a]:
			c.add(d.Source, "kind", k.Name, "identity-duplicate", fmt.Sprintf("identity attribute %q is listed twice", a))
		}
		seen[a] = true
		c.attr(d.Source, k.Name, a)
	}
	if k.Discriminator != "" {
		c.attr(d.Source, k.Name, k.Discriminator)
	}
}

func (c *checker) attr(src Source, kind, attr string) {
	if attr != "" && (IsSecretName(attr) || attr == "data") {
		c.add(src, "kind", kind, "attribute-secret", fmt.Sprintf("attribute %q is a secret name or %q", attr, "data"))
	}
}

func (c *checker) relation(d SourceDeclaration, r RelationDeclaration) {
	if !validName(r.Name) {
		c.add(d.Source, "relation", r.Name, "name-pattern", "relation name must match [a-z][a-z0-9_]* and be at most 64 characters")
	}
	c.prefix(d, "relation", r.Name)
	c.description(d.Source, "relation", r.Name, r.Description)
	if r.Confidence != Extracted && r.Confidence != Inferred {
		c.add(d.Source, "relation", r.Name, "confidence", fmt.Sprintf("confidence %q must be %q or %q", r.Confidence, Extracted, Inferred))
	}
	if r.Direction != Forward && r.Direction != Reverse {
		c.add(d.Source, "relation", r.Name, "direction", fmt.Sprintf("direction %d must be Forward or Reverse", r.Direction))
	}
}

func (c *checker) description(src Source, subject, name, desc string) {
	t := strings.TrimSpace(desc)
	switch {
	case t == "":
		c.add(src, subject, name, "description-blank", "description must not be blank")
	case utf8.RuneCountInString(t) > maxDescLen:
		c.add(src, subject, name, "description-length", fmt.Sprintf("description has %d characters, want at most %d", utf8.RuneCountInString(t), maxDescLen))
	}
}

func (c *checker) prefix(d SourceDeclaration, subject, name string) {
	if d.Source == SourceCore || d.Prefix == "" || strings.HasPrefix(name, d.Prefix) {
		return
	}
	if genericRelations[name] || legacyNames[name] {
		return
	}
	c.add(d.Source, subject, name, "prefix", fmt.Sprintf("name must start with the source prefix %q", d.Prefix))
}

func (c *checker) required(d SourceDeclaration, r Requirement) {
	kinds, types, rels, cats := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, k := range d.Kinds {
		kinds[k.Name] = true
		for _, t := range k.Types {
			types[t.Name] = true
		}
	}
	for _, x := range d.Relations {
		rels[x.Name] = true
	}
	for _, x := range d.Categories {
		cats[x.ID] = true
	}
	miss := func(subject string, want []string, have map[string]bool) {
		for _, n := range want {
			if !have[n] {
				c.add(d.Source, subject, n, "missing-required", "required name is not declared")
			}
		}
	}
	miss("kind", r.Kinds, kinds)
	miss("type", r.Types, types)
	miss("relation", r.Relations, rels)
	miss("category", r.Categories, cats)
}

// crossSource compares every pair of declarations from different sources.
// ds is sorted by source, so a pair is always reported first-source first.
func (c *checker) crossSource(ds []SourceDeclaration) {
	type kindAt struct {
		src Source
		k   KindDeclaration
	}
	type relAt struct {
		src Source
		r   RelationDeclaration
	}
	kinds, rels := map[string][]kindAt{}, map[string][]relAt{}
	types, cats := map[string][]Source{}, map[string][]Source{}
	for _, d := range ds {
		for _, k := range d.Kinds {
			kinds[k.Name] = append(kinds[k.Name], kindAt{d.Source, k})
			for _, t := range k.Types {
				types[t.Name] = append(types[t.Name], d.Source)
			}
		}
		for _, r := range d.Relations {
			rels[r.Name] = append(rels[r.Name], relAt{d.Source, r})
		}
		for _, x := range d.Categories {
			cats[x.ID] = append(cats[x.ID], d.Source)
		}
	}
	for name, at := range kinds {
		for i := range at {
			for j := i + 1; j < len(at); j++ {
				if at[i].src == at[j].src {
					continue
				}
				if !slices.Equal(at[i].k.Identity, at[j].k.Identity) {
					c.pair(at[i].src, at[j].src, "kind", name, "identity-conflict",
						fmt.Sprintf("identity %v (%s) differs from %v (%s)", at[i].k.Identity, at[i].src, at[j].k.Identity, at[j].src))
					continue
				}
				c.pair(at[i].src, at[j].src, "kind", name, "duplicate-name", "kind declared by more than one source")
			}
		}
	}
	for name, at := range rels {
		for i := range at {
			for j := i + 1; j < len(at); j++ {
				a, b := at[i], at[j]
				if a.src == b.src {
					continue
				}
				switch {
				case a.r.Direction != b.r.Direction:
					c.pair(a.src, b.src, "relation", name, "direction-conflict",
						fmt.Sprintf("direction %s (%s) differs from %s (%s)", a.r.Direction, a.src, b.r.Direction, b.src))
				case !genericRelations[name]:
					c.pair(a.src, b.src, "relation", name, "duplicate-name", "relation declared by more than one source")
				case a.r.Confidence != b.r.Confidence:
					c.pair(a.src, b.src, "relation", name, "confidence-conflict",
						fmt.Sprintf("default confidence %s (%s) differs from %s (%s)", a.r.Confidence, a.src, b.r.Confidence, b.src))
				}
			}
		}
	}
	dupSources := func(subject string, m map[string][]Source) {
		for name, srcs := range m {
			for i := range srcs {
				for j := i + 1; j < len(srcs); j++ {
					if srcs[i] != srcs[j] {
						c.pair(srcs[i], srcs[j], subject, name, "duplicate-name", subject+" declared by more than one source")
					}
				}
			}
		}
	}
	dupSources("type", types)
	dupSources("category", cats)
}

// references checks that endpoint and category names resolve.
func (c *checker) references(ds []SourceDeclaration) {
	names, cats := map[string]bool{}, map[string]bool{}
	for _, d := range ds {
		for _, k := range d.Kinds {
			names[k.Name] = true
			for _, t := range k.Types {
				names[t.Name] = true
			}
		}
		for _, x := range d.Categories {
			cats[x.ID] = true
		}
	}
	for _, d := range ds {
		for _, k := range d.Kinds {
			for _, t := range k.Types {
				if !cats[t.Category] {
					c.add(d.Source, "type", t.Name, "unknown-category", fmt.Sprintf("category %q is not declared", t.Category))
				}
			}
		}
		for _, r := range d.Relations {
			if r.Category != "" && !cats[r.Category] {
				c.add(d.Source, "relation", r.Name, "unknown-category", fmt.Sprintf("category %q is not declared", r.Category))
			}
			for _, e := range slices.Concat(r.From, r.To) {
				if !names[e] {
					c.add(d.Source, "relation", r.Name, "unknown-endpoint", fmt.Sprintf("endpoint %q is not a declared kind or type", e))
				}
			}
		}
	}
}

func validName(s string) bool {
	if len(s) == 0 || len(s) > maxNameLen || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		ch := s[i]
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '_') {
			return false
		}
	}
	return true
}
