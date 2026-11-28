// Package postureschema declares the kinds and relation types of the posture
// source: Rule_Packs and Rules for the compliance view. It imports only schema.
package postureschema

import "github.com/bellu/bellucode/services/bellud/internal/graph/schema"

// Kind and relation names.
const (
	KindPack         = "posture_pack"
	KindRule         = "posture_rule"
	RelRuleAppliesTo = "rule_applies_to"
)

// Declaration returns the posture source declaration.
func Declaration() schema.SourceDeclaration {
	return schema.SourceDeclaration{
		Source: schema.SourcePosture,
		Kinds: []schema.KindDeclaration{
			{Name: KindPack, Identity: []string{"id"}, Description: "A Rule_Pack: a versioned bundle of posture rules.", Overview: schema.OvCloud},
			{Name: KindRule, Identity: []string{"pack", "id"}, Description: "A posture rule in a Rule_Pack, shown in the compliance view.", Overview: schema.OvCloud},
		},
		Relations: []schema.RelationDeclaration{
			{Name: RelRuleAppliesTo, Direction: schema.Forward, Confidence: schema.Extracted, From: []string{KindRule}, Description: "A rule applies to every entity of a kind it lists."},
		},
	}
}
