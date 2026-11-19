package ident

import (
	"regexp"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
)

var relNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// Feature: aws-relationship-registry, Property 4: Lookups are total and well formed
//
// For any string that is not a registered relation type, DirectionOf reports
// Reverse with isDefault and DefaultConfidence reports extracted with
// registered=false.
//
// **Validates: Requirements 1.4, 1.5, 4.4, 4.10, 4.11, 16.2**
func TestPropertyLookupsTotalForAnyString(t *testing.T) {
	reg, err := Registry()
	if err != nil {
		t.Fatal(err)
	}
	rapid.Check(t, func(t *rapid.T) {
		gen := rapid.OneOf(
			rapid.String(),
			rapid.StringMatching(`[a-z][a-z0-9_]{0,30}`),
			rapid.StringMatching(`aws_[a-z0-9_]{0,30}`),
		)
		s := gen.Draw(t, "relType")
		_, registered := reg.Relation(s)

		d, isDefault := DirectionOf(s)
		conf, confRegistered := DefaultConfidence(s)
		if confRegistered != registered || isDefault == registered {
			t.Fatalf("%q: registered=%v isDefault=%v confRegistered=%v", s, registered, isDefault, confRegistered)
		}
		if !registered {
			if d != Reverse || !isDefault {
				t.Fatalf("%q: unregistered direction = %v, isDefault=%v", s, d, isDefault)
			}
			if conf != "extracted" {
				t.Fatalf("%q: unregistered confidence = %q", s, conf)
			}
		}
	})
}

// Feature: aws-relationship-registry, Property 4: Lookups are total and well formed
//
// Every registered relation type has a valid direction and default
// confidence, a declaring source, and every AWS relation type starts with
// aws_ and matches [a-z][a-z0-9_]*.
//
// **Validates: Requirements 1.4, 1.5, 4.4, 4.10, 4.11, 16.2**
func TestPropertyRegisteredRelationsWellFormed(t *testing.T) {
	reg, err := Registry()
	if err != nil {
		t.Fatal(err)
	}
	names := RelationTypes()
	if len(names) == 0 {
		t.Fatal("no registered relation types")
	}
	rapid.Check(t, func(t *rapid.T) {
		name := rapid.SampledFrom(names).Draw(t, "relType")

		d, isDefault := DirectionOf(name)
		if isDefault || (d != Forward && d != Reverse) {
			t.Fatalf("%q: direction = %v, isDefault=%v", name, d, isDefault)
		}
		conf, registered := DefaultConfidence(name)
		if !registered || (conf != "extracted" && conf != "inferred") {
			t.Fatalf("%q: confidence = %q, registered=%v", name, conf, registered)
		}
		src, ok := reg.SourceOfRelation(name)
		if !ok || src == "" {
			t.Fatalf("%q: declaring source = %q, ok=%v", name, src, ok)
		}
		if src == schema.SourceAWS {
			if !strings.HasPrefix(name, "aws_") || !relNamePattern.MatchString(name) {
				t.Fatalf("aws relation %q is not aws_ prefixed [a-z][a-z0-9_]*", name)
			}
		}
	})
}
