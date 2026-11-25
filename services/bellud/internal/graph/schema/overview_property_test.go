package schema_test

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schemaall"
)

var ovSources = []schema.Source{schema.SourceCore, schema.SourceGitHub, schema.SourceAWS, schema.SourceCorrelator}

func ovPrefix(s schema.Source) string {
	if s == schema.SourceCore {
		return "core_"
	}
	return string(s) + "_"
}

func genOverview() *rapid.Generator[schema.OverviewCategory] {
	return rapid.SampledFrom(schema.OverviewOrder[:])
}

// ovFindingTypes holds the category each finding type must have across all
// generated sources, so valid sources never conflict.
type ovFindingTypes map[string]schema.OverviewCategory

// genOverviewSources draws 1..4 distinct sources with valid kinds, type
// overrides and finding types.
func genOverviewSources(t *rapid.T) []schema.SourceDeclaration {
	srcs := rapid.SliceOfNDistinct(rapid.SampledFrom(ovSources), 1, 4, func(s schema.Source) schema.Source { return s }).Draw(t, "sources")
	ftCat := ovFindingTypes{}
	pool := []string{"vuln_a", "vuln_b", "secret_a", "misconfig_a", "ai_a"}
	for _, f := range pool {
		ftCat[f] = genOverview().Draw(t, "ft:"+f)
	}
	out := make([]schema.SourceDeclaration, len(srcs))
	for i, s := range srcs {
		p := ovPrefix(s)
		prefix := p
		if s == schema.SourceCore {
			prefix = ""
		}
		d := schema.SourceDeclaration{Source: s, Prefix: prefix}
		d.Categories = []schema.CategoryDeclaration{{ID: p + "cat", Name: "Category", Status: schema.Implemented}}
		for k := range rapid.IntRange(1, 3).Draw(t, "nkinds") {
			kd := schema.KindDeclaration{
				Name: fmt.Sprintf("%sk%d", p, k), Identity: []string{"id"}, Description: "A kind.",
				Overview: genOverview().Draw(t, "kov"),
			}
			if nt := rapid.IntRange(0, 3).Draw(t, "ntypes"); nt > 0 {
				kd.Discriminator = "resource_type"
				for j := range nt {
					td := schema.TypeDeclaration{Name: fmt.Sprintf("%st%d_%d:x", p, k, j), Category: p + "cat", Description: "A type."}
					if rapid.Bool().Draw(t, "tovset") {
						td.Overview = genOverview().Draw(t, "tov")
					}
					kd.Types = append(kd.Types, td)
				}
			}
			d.Kinds = append(d.Kinds, kd)
		}
		for _, f := range rapid.SliceOfNDistinct(rapid.SampledFrom(pool), 0, 3, func(s string) string { return s }).Draw(t, "fts") {
			d.FindingTypes = append(d.FindingTypes, schema.FindingTypeDeclaration{Type: f, Overview: ftCat[f]})
		}
		out[i] = d
	}
	return out
}

// ovState is everything a registry exposes, including each entity's category.
func ovState(r *schema.Registry) string {
	type entity struct {
		Kind, Type string
		Overview   schema.OverviewCategory
	}
	var es []entity
	for _, k := range r.Kinds() {
		es = append(es, entity{k.Name, "", r.OverviewOf(k.Name, "")})
		for _, ty := range k.Types {
			es = append(es, entity{k.Name, ty.Name, r.OverviewOf(k.Name, ty.Name)})
		}
	}
	b, err := json.Marshal(struct {
		Kinds      []schema.KindDeclaration
		Relations  []schema.RelationDeclaration
		Categories []schema.CategoryDeclaration
		Entities   []entity
	}{r.Kinds(), r.Relations(), r.Categories(), es})
	if err != nil {
		panic(err)
	}
	return string(b)
}

func assertTotal(t interface {
	Fatalf(string, ...any)
}, r *schema.Registry) {
	for _, k := range r.Kinds() {
		got := r.OverviewOf(k.Name, "")
		if !slices.Contains(schema.OverviewOrder[:], got) {
			t.Fatalf("kind %q resolves to %q, not one of the nine categories", k.Name, got)
		}
		for _, ty := range k.Types {
			if got := r.OverviewOf(k.Name, ty.Name); !slices.Contains(schema.OverviewOrder[:], got) {
				t.Fatalf("type %q of kind %q resolves to %q", ty.Name, k.Name, got)
			}
		}
	}
}

// Feature: bellu-wiz-security-platform, Property 9: Category assignment is total and registration is atomic
//
// **Validates: Requirements 1.8, 1.12**
func TestOverviewTotalAndRegistrationAtomicProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		ds := genOverviewSources(t)

		// Totality: every kind and type resolves to a valid category, and a
		// type override wins over the kind default.
		r, err := schema.Merge(ds...)
		if err != nil {
			t.Fatalf("valid sources rejected: %v", err)
		}
		assertTotal(t, r)
		for _, d := range ds {
			for _, k := range d.Kinds {
				for _, ty := range k.Types {
					want := k.Overview
					if ty.Overview != "" {
						want = ty.Overview
					}
					if got := r.OverviewOf(k.Name, ty.Name); got != want {
						t.Fatalf("OverviewOf(%q,%q) = %q, want %q", k.Name, ty.Name, got, want)
					}
				}
			}
		}

		// Atomicity: build a registry from all but the last source, then try a
		// bad registration. It must fail naming the culprit and change nothing.
		last := ds[len(ds)-1]
		b := new(schema.Builder)
		for _, d := range ds[:len(ds)-1] {
			if err := b.Add(d); err != nil {
				t.Fatalf("valid source rejected: %v", err)
			}
		}
		before, err := b.Build()
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		want := ovState(before)

		bad := schema.SourceDeclaration{Source: last.Source, Prefix: last.Prefix, Categories: last.Categories,
			Kinds: slices.Clone(last.Kinds), FindingTypes: slices.Clone(last.FindingTypes)}
		var culprit string
		switch mode := rapid.IntRange(0, 3).Draw(t, "badMode"); mode {
		case 0: // kind with no Overview
			bad.Kinds[0].Overview = ""
			culprit = bad.Kinds[0].Name
		case 1: // kind with an invalid Overview
			bad.Kinds[0].Overview = "other"
			culprit = bad.Kinds[0].Name
		case 2: // finding type with an invalid Overview
			bad.FindingTypes = append(bad.FindingTypes, schema.FindingTypeDeclaration{Type: "bad_ft", Overview: "other"})
			culprit = "bad_ft"
		default: // finding type declared by an earlier source with another category
			var prior *schema.FindingTypeDeclaration
			for _, d := range ds[:len(ds)-1] {
				if len(d.FindingTypes) > 0 {
					prior = &d.FindingTypes[0]
					break
				}
			}
			if prior == nil {
				bad.FindingTypes = append(bad.FindingTypes, schema.FindingTypeDeclaration{Type: "bad_ft", Overview: "other"})
				culprit = "bad_ft"
				break
			}
			other := schema.OvCloud
			if prior.Overview == other {
				other = schema.OvAI
			}
			bad.FindingTypes = append(slices.DeleteFunc(bad.FindingTypes, func(f schema.FindingTypeDeclaration) bool { return f.Type == prior.Type }),
				schema.FindingTypeDeclaration{Type: prior.Type, Overview: other})
			culprit = prior.Type
		}
		err = b.Add(bad)
		if err == nil {
			t.Fatalf("bad registration accepted (culprit %q)", culprit)
		}
		if !strings.Contains(err.Error(), culprit) {
			t.Fatalf("error %q does not name %q", err, culprit)
		}
		after, err := b.Build()
		if err != nil {
			t.Fatalf("build after rejected add: %v", err)
		}
		if got := ovState(after); got != want {
			t.Fatalf("registry changed after rejected registration:\nbefore %s\nafter  %s", want, got)
		}
		if got := ovState(before); got != want {
			t.Fatalf("previous registry changed after rejected registration")
		}
	})
}

// Feature: bellu-wiz-security-platform, Property 9: Category assignment is total and registration is atomic
//
// **Validates: Requirements 1.8, 1.12**
func TestDefaultRegistryOverviewTotal(t *testing.T) {
	r, err := schemaall.Default()
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Kinds()) == 0 {
		t.Fatal("default registry has no kinds")
	}
	assertTotal(t, r)

	// Registry has no finding-type lookup, so check the declarations that
	// feed it: each finding type has one valid category across all sources.
	seen := map[string]schema.OverviewCategory{}
	for _, d := range schemaall.Sources() {
		for _, f := range d.FindingTypes {
			if !f.Overview.Valid() {
				t.Errorf("finding type %q has invalid Overview %q", f.Type, f.Overview)
			}
			if prev, ok := seen[f.Type]; ok && prev != f.Overview {
				t.Errorf("finding type %q declared as %q and %q", f.Type, prev, f.Overview)
			}
			seen[f.Type] = f.Overview
		}
	}
	if len(seen) == 0 {
		t.Error("no finding types declared")
	}
}
