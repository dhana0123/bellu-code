package schema

import (
	"fmt"
	"reflect"
	"slices"
	"testing"

	"pgregory.net/rapid"
)

// Generators for valid declarations. Every source owns names under its own
// prefix, so any set of generated sources is conflict free. The generic
// relations in genericPool carry one meaning everywhere, so a source may
// declare them identically to another source.

var genericPool = []string{"uses", "mounts", "attached_to", "owned_by"}

var identityAttrs = []string{"arn", "region", "connection", "account", "hostname", "name", "id"}

func prefixOf(s Source) string {
	if s == SourceCore {
		return ""
	}
	return string(s) + "_"
}

type genericMeaning struct {
	dir  Direction
	conf Confidence
}

func genDirection() *rapid.Generator[Direction] {
	return rapid.SampledFrom([]Direction{Forward, Reverse})
}

func genConfidence() *rapid.Generator[Confidence] {
	return rapid.SampledFrom([]Confidence{Extracted, Inferred})
}

func genDescription() *rapid.Generator[string] {
	return rapid.StringMatching(`[A-Za-z][A-Za-z ]{0,30}`)
}

// genValidDecls draws 2..4 distinct sources, each with valid declarations.
func genValidDecls() *rapid.Generator[[]SourceDeclaration] {
	return rapid.Custom(func(t *rapid.T) []SourceDeclaration {
		all := []Source{SourceCore, SourceGitHub, SourceAWS, SourceCorrelator}
		srcs := rapid.SliceOfNDistinct(rapid.SampledFrom(all), 2, 4, func(s Source) Source { return s }).Draw(t, "sources")
		meaning := map[string]genericMeaning{}
		for _, g := range genericPool {
			meaning[g] = genericMeaning{genDirection().Draw(t, "gdir"), genConfidence().Draw(t, "gconf")}
		}
		out := make([]SourceDeclaration, len(srcs))
		for i, s := range srcs {
			out[i] = genSourceDecl(t, s, meaning)
		}
		return out
	})
}

func genSourceDecl(t *rapid.T, s Source, meaning map[string]genericMeaning) SourceDeclaration {
	p := prefixOf(s)
	if s == SourceCore {
		p = "core_" // core has no prefix rule; this keeps names apart from other sources
	}
	d := SourceDeclaration{Source: s, Prefix: prefixOf(s)}
	catID := p + "cat"
	d.Categories = []CategoryDeclaration{{
		ID: catID, Name: genDescription().Draw(t, "catname"),
		Status:  rapid.SampledFrom([]Status{Implemented, RegisteredOnly}).Draw(t, "status"),
		ReadOps: rapid.SliceOfN(rapid.StringMatching(`[A-Za-z]{1,8}`), 0, 3).Draw(t, "readops"),
	}}
	var endpoints []string
	for i := range rapid.IntRange(1, 3).Draw(t, "nkinds") {
		k := KindDeclaration{
			Name:        fmt.Sprintf("%sk%d_%s", p, i, rapid.StringMatching(`[a-z0-9_]{0,8}`).Draw(t, "ksuffix")),
			Identity:    rapid.SliceOfNDistinct(rapid.SampledFrom(identityAttrs), 1, 4, func(a string) string { return a }).Draw(t, "identity"),
			Description: genDescription().Draw(t, "kdesc"),
			Overview:    OvCloud,
		}
		endpoints = append(endpoints, k.Name)
		if nt := rapid.IntRange(0, 2).Draw(t, "ntypes"); nt > 0 {
			k.Discriminator = "resource_type"
			for j := range nt {
				tn := fmt.Sprintf("%st%d_%d:x", p, i, j)
				k.Types = append(k.Types, TypeDeclaration{Name: tn, Category: catID, Description: genDescription().Draw(t, "tdesc")})
				endpoints = append(endpoints, tn)
			}
		}
		d.Kinds = append(d.Kinds, k)
	}
	for i := range rapid.IntRange(0, 3).Draw(t, "nrels") {
		r := RelationDeclaration{
			Name:        fmt.Sprintf("%sr%d", p, i),
			Direction:   genDirection().Draw(t, "dir"),
			Confidence:  genConfidence().Draw(t, "conf"),
			Description: genDescription().Draw(t, "rdesc"),
			From:        rapid.SliceOfNDistinct(rapid.SampledFrom(endpoints), 0, 2, func(e string) string { return e }).Draw(t, "from"),
			To:          rapid.SliceOfNDistinct(rapid.SampledFrom(endpoints), 0, 2, func(e string) string { return e }).Draw(t, "to"),
			Derived:     rapid.Bool().Draw(t, "derived"),
		}
		if rapid.Bool().Draw(t, "withcat") {
			r.Category = catID
		}
		d.Relations = append(d.Relations, r)
	}
	for _, g := range genericPool {
		if rapid.Bool().Draw(t, "generic:"+g) {
			m := meaning[g]
			d.Relations = append(d.Relations, RelationDeclaration{Name: g, Direction: m.dir, Confidence: m.conf, Description: "Generic " + g + "."})
		}
	}
	return d
}

// snapshot captures everything a Registry exposes.
type snapshot struct {
	Kinds         []KindDeclaration
	Relations     []RelationDeclaration
	Categories    []CategoryDeclaration
	KindSource    map[string]Source
	RelSource     map[string]Source
	TypeCategory  map[string]string
	CategoryOfAll map[string]CategoryDeclaration
}

func snapshotOf(r *Registry) snapshot {
	s := snapshot{
		Kinds: r.Kinds(), Relations: r.Relations(), Categories: r.Categories(),
		KindSource: map[string]Source{}, RelSource: map[string]Source{},
		TypeCategory: map[string]string{}, CategoryOfAll: map[string]CategoryDeclaration{},
	}
	for _, k := range s.Kinds {
		s.KindSource[k.Name], _ = r.SourceOfKind(k.Name)
		for _, ty := range k.Types {
			s.TypeCategory[ty.Name], _ = r.CategoryOfType(ty.Name)
		}
	}
	for _, rel := range s.Relations {
		s.RelSource[rel.Name], _ = r.SourceOfRelation(rel.Name)
	}
	for _, c := range s.Categories {
		s.CategoryOfAll[c.ID], _ = r.Category(c.ID)
	}
	return s
}

func reversed(ds []SourceDeclaration) []SourceDeclaration {
	out := slices.Clone(ds)
	slices.Reverse(out)
	return out
}

// Feature: aws-relationship-registry, Property 1: Merge is order independent and complete
//
// **Validates: Requirements 1.1, 1.7, 2.4, 2.13**
func TestMergeOrderIndependentAndCompleteProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		ds := genValidDecls().Draw(t, "decls")
		base, err := Merge(ds...)
		if err != nil {
			t.Fatalf("valid declarations rejected: %v", err)
		}
		want := snapshotOf(base)

		for _, order := range [][]SourceDeclaration{
			reversed(ds),
			rapid.Permutation(ds).Draw(t, "order"),
		} {
			got, err := Merge(order...)
			if err != nil {
				t.Fatalf("reordered declarations rejected: %v", err)
			}
			if !reflect.DeepEqual(want, snapshotOf(got)) {
				t.Fatalf("registry differs for ordering %v", sourcesOf(order))
			}
		}

		// Completeness: every declared name maps to its declaring source;
		// a generic relation maps to the first declarer in source order.
		wantRelSource := map[string]Source{}
		sorted := slices.Clone(ds)
		sortDecls(sorted)
		for _, d := range sorted {
			for _, k := range d.Kinds {
				if s, ok := base.SourceOfKind(k.Name); !ok || s != d.Source {
					t.Fatalf("kind %q source = %q, %v; want %q", k.Name, s, ok, d.Source)
				}
				for _, ty := range k.Types {
					if c, ok := base.CategoryOfType(ty.Name); !ok || c != ty.Category {
						t.Fatalf("type %q category = %q, %v; want %q", ty.Name, c, ok, ty.Category)
					}
				}
			}
			for _, r := range d.Relations {
				if _, seen := wantRelSource[r.Name]; !seen {
					wantRelSource[r.Name] = d.Source
				}
			}
			for _, c := range d.Categories {
				if _, ok := base.Category(c.ID); !ok {
					t.Fatalf("category %q missing", c.ID)
				}
			}
		}
		for name, src := range wantRelSource {
			if s, ok := base.SourceOfRelation(name); !ok || s != src {
				t.Fatalf("relation %q source = %q, %v; want %q", name, s, ok, src)
			}
		}
		if got := len(base.Relations()); got != len(wantRelSource) {
			t.Fatalf("relations = %d, want %d distinct names", got, len(wantRelSource))
		}
	})
}

// Feature: aws-relationship-registry, Property 2: Invalid declarations are rejected with every failure reported
//
// Defect-free declarations that differ only by an identical generic relation
// merge, and the relation is kept once.
//
// **Validates: Requirements 2.4, 2.13, 16.1**
func TestIdenticalGenericRelationsMergeToOneEntryProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		ds := genValidDecls().Draw(t, "decls")
		name := rapid.SampledFrom(genericPool).Draw(t, "generic")
		dir, conf := genDirection().Draw(t, "dir"), genConfidence().Draw(t, "conf")
		for i := range ds {
			ds[i].Relations = slices.DeleteFunc(ds[i].Relations, func(r RelationDeclaration) bool { return r.Name == name })
			ds[i].Relations = append(ds[i].Relations, RelationDeclaration{Name: name, Direction: dir, Confidence: conf, Description: "Same."})
		}
		r, err := Merge(rapid.Permutation(ds).Draw(t, "order")...)
		if err != nil {
			t.Fatalf("identical generic relations rejected: %v", err)
		}
		n := 0
		for _, rel := range r.Relations() {
			if rel.Name == name {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("relation %q appears %d times, want 1", name, n)
		}
	})
}

func sourcesOf(ds []SourceDeclaration) []Source {
	out := make([]Source, len(ds))
	for i, d := range ds {
		out[i] = d.Source
	}
	return out
}
