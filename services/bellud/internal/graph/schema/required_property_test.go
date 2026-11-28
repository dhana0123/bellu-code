package schema_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/aws/awsschema"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schemaall"
	"pgregory.net/rapid"
)

// Feature: aws-relationship-registry, Property 2: Invalid declarations are rejected with every failure reported
//
// Missing required AWS name.
//
// **Validates: Requirements 3.4, 10.12, 16.1**
func TestPropertyMissingRequiredAWSName(t *testing.T) {
	req := map[schema.Source]schema.Requirement{schema.SourceAWS: awsschema.Required}
	if _, err := schema.MergeRequired(req, schemaall.Sources()...); err != nil {
		t.Fatalf("full declaration rejected: %v", err)
	}
	type pick struct{ subject, name string }
	var all []pick
	for _, n := range awsschema.Required.Kinds {
		all = append(all, pick{"kind", n})
	}
	for _, n := range awsschema.Required.Types {
		all = append(all, pick{"type", n})
	}
	for _, n := range awsschema.Required.Relations {
		all = append(all, pick{"relation", n})
	}
	for _, n := range awsschema.Required.Categories {
		all = append(all, pick{"category", n})
	}
	rapid.Check(t, func(t *rapid.T) {
		p := rapid.SampledFrom(all).Draw(t, "removed")
		srcs := schemaall.Sources()
		for i := range srcs {
			if srcs[i].Source == schema.SourceAWS {
				srcs[i] = remove(srcs[i], p.subject, p.name)
			}
		}
		_, err := schema.MergeRequired(req, srcs...)
		if err == nil {
			t.Fatalf("removing %s %s was accepted", p.subject, p.name)
		}
		msg := err.Error()
		if !strings.Contains(msg, p.name) || !strings.Contains(msg, "missing-required") {
			t.Fatalf("error does not name %s with missing-required: %v", p.name, err)
		}
	})
}

// remove returns d without the named item. Removing a kind or type also drops
// the references that would otherwise fail for another reason.
func remove(d schema.SourceDeclaration, subject, name string) schema.SourceDeclaration {
	switch subject {
	case "relation":
		d.Relations = slices.DeleteFunc(slices.Clone(d.Relations), func(r schema.RelationDeclaration) bool { return r.Name == name })
	case "category":
		d.Categories = slices.DeleteFunc(slices.Clone(d.Categories), func(c schema.CategoryDeclaration) bool { return c.ID == name })
	case "kind":
		d.Kinds = slices.DeleteFunc(slices.Clone(d.Kinds), func(k schema.KindDeclaration) bool { return k.Name == name })
	case "type":
		kinds := slices.Clone(d.Kinds)
		for i := range kinds {
			kinds[i].Types = slices.DeleteFunc(slices.Clone(kinds[i].Types), func(x schema.TypeDeclaration) bool { return x.Name == name })
		}
		d.Kinds = kinds
	}
	return d
}
