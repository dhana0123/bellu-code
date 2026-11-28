package lens

import (
	"slices"
	"sort"
	"testing"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schemaall"
)

// Feature: aws-relationship-registry, Property 24: missing_data is the registered-only part of the needs
//
// **Validates: Requirements 12.3, 12.4, 12.5, 12.6, 12.7, 13.3, 13.5, 13.10**
func TestPropertyMissingData(t *testing.T) {
	r, err := schemaall.Default()
	if err != nil {
		t.Fatal(err)
	}
	defs := append(Catalog(), Def{ID: "exposed-resources", Needs: ExposedNeeds})
	types := []string{"", "rds:instance", "ec2:instance", "iam:role", "s3:bucket", "route53:record", "nope:type"}
	rapid.Check(t, func(t *rapid.T) {
		def := rapid.SampledFrom(defs).Draw(t, "def")
		p := Params{TargetType: rapid.SampledFrom(types).Draw(t, "targetType")}
		got := MissingData(def, p)
		if got == nil || !sort.StringsAreSorted(got) || len(slices.Compact(slices.Clone(got))) != len(got) {
			t.Fatalf("missing_data %v is nil, unsorted, or has duplicates", got)
		}
		needs := slices.Clone(def.Needs)
		if def.Select == SelectAttackPaths {
			if c, ok := r.CategoryOfType(p.TargetType); ok {
				needs = append(needs, c)
			}
		}
		var want []string
		for _, n := range needs {
			if c, ok := r.Category(n); !ok || c.Status != schema.Implemented {
				want = append(want, n)
			}
		}
		sort.Strings(want)
		want = slices.Compact(want)
		if !slices.Equal(got, want) && !(len(got) == 0 && len(want) == 0) {
			t.Fatalf("%s %q: missing_data %v, want %v", def.ID, p.TargetType, got, want)
		}
		if again := MissingData(def, p); !slices.Equal(again, got) {
			t.Fatal("missing_data is not stable")
		}
	})
	// The IAM questions list identity and data (Req 13.10).
	br, _ := lookup("blast-radius")
	if got := MissingData(br, Params{}); !slices.Contains(got, "identity") || !slices.Contains(got, "data") {
		t.Fatalf("blast-radius missing_data %v", got)
	}
	ap, _ := lookup("attack-path")
	if got := MissingData(ap, Params{TargetType: "rds:instance"}); !slices.Contains(got, "data") {
		t.Fatalf("attack-path to rds missing_data %v", got)
	}
}
