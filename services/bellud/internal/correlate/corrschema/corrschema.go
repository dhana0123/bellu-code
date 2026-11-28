// Package corrschema declares the kinds and relation types that the
// correlator source owns. It imports only the standard library and schema.
package corrschema

import "github.com/bellu/bellucode/services/bellud/internal/graph/schema"

// Names.
const (
	KindVulnerability = "vulnerability"
	RelAffectedBy     = "affected_by"
	RelSameAs         = "same_as"
	RelLikelySameAs   = "likely_same_as"
)

// Declaration returns the correlator source declaration. A vulnerability is
// global: one node per canonical id, shared by every package it affects, so
// it has no connection attribute.
func Declaration() schema.SourceDeclaration {
	return schema.SourceDeclaration{
		Source: schema.SourceCorrelator,
		Kinds: []schema.KindDeclaration{{
			Name:        KindVulnerability,
			Overview:    schema.OvVuln,
			Identity:    []string{"id"},
			Description: "A vulnerability with one node per canonical id, shared by every package it affects.",
		}},
		Relations: []schema.RelationDeclaration{
			{Name: RelAffectedBy, Direction: schema.Reverse, Confidence: schema.Extracted,
				Description: "A package is affected by a vulnerability, so the vulnerability impacts the package."},
			{Name: RelSameAs, Direction: schema.Reverse, Confidence: schema.Extracted,
				Description: "Two entities share an identity key, so failure of the anchor impacts the other."},
			{Name: RelLikelySameAs, Direction: schema.Reverse, Confidence: schema.Inferred,
				Description: "Two entities probably describe the same thing, inferred without a shared key."},
		},
	}
}
