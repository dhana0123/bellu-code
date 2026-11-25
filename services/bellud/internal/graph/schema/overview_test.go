package schema

import (
	"slices"
	"testing"
)

func TestOverviewOrderHasNineValidCategories(t *testing.T) {
	seen := map[OverviewCategory]bool{}
	for _, c := range OverviewOrder {
		if !c.Valid() || seen[c] {
			t.Fatalf("category %q invalid or repeated", c)
		}
		seen[c] = true
	}
	if len(seen) != 9 {
		t.Fatalf("got %d categories, want 9", len(seen))
	}
}

func TestCheckRejectsMissingAndInvalidOverview(t *testing.T) {
	d := coreDecl()
	d.Kinds = append(d.Kinds,
		KindDeclaration{Name: "nokind", Identity: []string{"a"}, Description: "d"},
		KindDeclaration{Name: "badkind", Identity: []string{"a"}, Description: "d", Overview: "other"},
		KindDeclaration{Name: "badtype", Identity: []string{"a"}, Description: "d", Overview: OvCloud, Discriminator: "t",
			Types: []TypeDeclaration{{Name: "x:y", Category: "c", Description: "d", Overview: "nope"}}},
	)
	d.FindingTypes = []FindingTypeDeclaration{{Type: "vulnerability", Overview: "nope"}}
	_, err := Merge(d)
	fs := failures(t, err)
	for _, w := range [][2]string{{"overview-missing", "nokind"}, {"overview-invalid", "badkind"}, {"overview-invalid", "x:y"}, {"overview-invalid", "vulnerability"}} {
		if !hasRule(fs, w[0], w[1]) {
			t.Errorf("missing failure %v in %v", w, fs)
		}
	}
}

func TestCheckRejectsConflictingFindingTypeOverview(t *testing.T) {
	a, b := coreDecl(), SourceDeclaration{Source: SourceCode}
	a.FindingTypes = []FindingTypeDeclaration{{Type: "secret", Overview: OvSecrets}}
	b.FindingTypes = []FindingTypeDeclaration{{Type: "secret", Overview: OvCode}}
	_, err := Merge(a, b)
	if err == nil || !hasRule(failures(t, err), "overview-conflict", "secret") {
		t.Fatalf("err = %v", err)
	}
	b.FindingTypes[0].Overview = OvSecrets
	if _, err := Merge(a, b); err != nil {
		t.Fatalf("agreeing finding types rejected: %v", err)
	}
}

func TestRejectedMergeLeavesBuilderRegistryUnchanged(t *testing.T) {
	b := new(Builder)
	if err := b.Add(coreDecl()); err != nil {
		t.Fatal(err)
	}
	r1, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Add(SourceDeclaration{Source: SourceGitHub, Prefix: "github_",
		Kinds: []KindDeclaration{{Name: "github_x", Identity: []string{"id"}, Description: "d"}}}); err == nil {
		t.Fatal("kind without Overview accepted")
	}
	if got := r1.Kinds(); len(got) != 1 || got[0].Name != "host" {
		t.Fatalf("previous registry changed: %v", got)
	}
}

func TestOverviewOfResolvesTypeThenKindAndIsTotal(t *testing.T) {
	d := awsDecl()
	d.Kinds[0].Types[0].Overview = OvNetwork
	r, err := Merge(d, coreDecl())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		kind, typ string
		want      OverviewCategory
	}{
		{"aws_resource", "ec2:vpc", OvNetwork},
		{"aws_resource", "unknown", OvCloud},
		{"aws_resource", "", OvCloud},
		{"host", "", OvCloud},
		{"nope", "", ""},
	}
	for _, c := range cases {
		if got := r.OverviewOf(c.kind, c.typ); got != c.want {
			t.Errorf("OverviewOf(%q,%q) = %q, want %q", c.kind, c.typ, got, c.want)
		}
	}
	for _, k := range r.Kinds() {
		if !slices.Contains(OverviewOrder[:], r.OverviewOf(k.Name, "")) {
			t.Errorf("kind %s has no valid category", k.Name)
		}
	}
}
