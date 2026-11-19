package schema

import (
	"errors"
	"strings"
	"testing"
)

func coreDecl() SourceDeclaration {
	return SourceDeclaration{
		Source: SourceCore,
		Kinds:  []KindDeclaration{{Name: "host", Identity: []string{"hostname"}, Description: "A host."}},
		Relations: []RelationDeclaration{
			{Name: "runs_on", Direction: Reverse, Confidence: Extracted, Description: "Runs on."},
		},
	}
}

func awsDecl() SourceDeclaration {
	return SourceDeclaration{
		Source: SourceAWS, Prefix: "aws_",
		Kinds: []KindDeclaration{{
			Name: "aws_resource", Identity: []string{"connection", "arn"}, Description: "A resource.",
			Discriminator: "resource_type",
			Types:         []TypeDeclaration{{Name: "ec2:vpc", Category: "network", Description: "A VPC."}},
		}},
		Relations: []RelationDeclaration{
			{Name: "aws_in_vpc", Direction: Reverse, Confidence: Extracted, Description: "In VPC.", From: []string{"ec2:vpc"}, To: []string{"host"}, Category: "network"},
			{Name: "runs_on", Direction: Reverse, Confidence: Extracted, Description: "Runs on."},
		},
		Categories: []CategoryDeclaration{{ID: "network", Name: "Network", Status: Implemented}},
	}
}

func failures(t *testing.T, err error) []Failure {
	t.Helper()
	var ce *CheckError
	if !errors.As(err, &ce) {
		t.Fatalf("want *CheckError, got %v", err)
	}
	return ce.Failures
}

func hasRule(fs []Failure, rule, name string) bool {
	for _, f := range fs {
		if f.Rule == rule && f.Name == name {
			return true
		}
	}
	return false
}

func TestMergeAcceptsValidAndKeepsIdenticalGenericOnce(t *testing.T) {
	r, err := Merge(awsDecl(), coreDecl())
	if err != nil {
		t.Fatal(err)
	}
	if got := len(r.Relations()); got != 2 {
		t.Fatalf("relations = %d, want 2 (runs_on kept once)", got)
	}
	if s, _ := r.SourceOfRelation("runs_on"); s != SourceAWS {
		t.Fatalf("runs_on source = %s, want first in source order", s)
	}
	if c, ok := r.CategoryOfType("ec2:vpc"); !ok || c != "network" {
		t.Fatalf("CategoryOfType = %q, %v", c, ok)
	}
	if s, _ := r.SourceOfKind("host"); s != SourceCore {
		t.Fatalf("host source = %s", s)
	}
}

func TestMergeIsOrderIndependent(t *testing.T) {
	a, b := coreDecl(), awsDecl()
	b.Kinds[0].Identity = []string{"arn", "connection"}
	b.Kinds = append(b.Kinds, KindDeclaration{Name: "host", Identity: []string{"x"}, Description: "d"})
	_, e1 := Merge(a, b)
	_, e2 := Merge(b, a)
	if e1 == nil || e1.Error() != e2.Error() {
		t.Fatalf("errors differ:\n%v\n%v", e1, e2)
	}
}

func TestCheckReportsEveryFailure(t *testing.T) {
	d := coreDecl()
	d.Kinds = append(d.Kinds,
		KindDeclaration{Name: "Bad-Name", Identity: []string{"a", "a", ""}, Description: " "},
		KindDeclaration{Name: strings.Repeat("a", 65), Identity: []string{"api_token"}, Description: "d"},
		KindDeclaration{Name: "data_kind", Identity: []string{"data"}, Description: "d"},
	)
	d.Relations = append(d.Relations,
		RelationDeclaration{Name: "r", Direction: 5, Confidence: "maybe", Description: "d"},
		RelationDeclaration{Name: "runs_on", Direction: Reverse, Confidence: Extracted, Description: "dup"},
	)
	_, err := Merge(d)
	fs := failures(t, err)
	for _, want := range [][2]string{
		{"name-pattern", "Bad-Name"}, {"identity-duplicate", "Bad-Name"}, {"identity-empty", "Bad-Name"},
		{"description-blank", "Bad-Name"}, {"name-pattern", strings.Repeat("a", 65)},
		{"attribute-secret", strings.Repeat("a", 65)}, {"attribute-secret", "data_kind"},
		{"direction", "r"}, {"confidence", "r"}, {"duplicate-name", "runs_on"},
	} {
		if !hasRule(fs, want[0], want[1]) {
			t.Errorf("missing failure %v in:\n%v", want, err)
		}
	}
}

func TestCrossSourceConflicts(t *testing.T) {
	core := coreDecl()
	a := SourceDeclaration{Source: SourceAWS, Prefix: "aws_",
		Kinds:     []KindDeclaration{{Name: "host", Identity: []string{"id"}, Description: "d"}},
		Relations: []RelationDeclaration{{Name: "runs_on", Direction: Forward, Confidence: Extracted, Description: "d"}},
	}
	_, err := Merge(core, a)
	fs := failures(t, err)
	if !hasRule(fs, "identity-conflict", "host") || !hasRule(fs, "direction-conflict", "runs_on") {
		t.Fatalf("got %v", err)
	}

	a.Relations[0].Direction = Reverse
	a.Relations[0].Confidence = Inferred
	a.Kinds = nil
	_, err = Merge(core, a)
	fs = failures(t, err)
	if len(fs) != 1 || fs[0].Rule != "confidence-conflict" || !strings.Contains(fs[0].Detail, "extracted") || !strings.Contains(fs[0].Detail, "inferred") {
		t.Fatalf("got %v", err)
	}
	if fs[0].Source != SourceAWS || fs[0].Other != SourceCore {
		t.Fatalf("pair not in sorted source order: %+v", fs[0])
	}
}

func TestPrefixRule(t *testing.T) {
	d := awsDecl()
	d.Kinds = append(d.Kinds, KindDeclaration{Name: "package", Identity: []string{"p"}, Description: "legacy"},
		KindDeclaration{Name: "widget", Identity: []string{"p"}, Description: "no prefix"})
	_, err := Merge(d, coreDecl())
	fs := failures(t, err)
	if len(fs) != 1 || !hasRule(fs, "prefix", "widget") || !strings.Contains(fs[0].Detail, "aws_") {
		t.Fatalf("got %v", err)
	}
}

func TestReferencesResolveInBuildNotAdd(t *testing.T) {
	var b Builder
	// aws refers to core's kind "host", added later: Add must not care.
	if err := b.Add(awsDecl()); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Build(); !hasRule(failures(t, err), "unknown-endpoint", "aws_in_vpc") {
		t.Fatalf("want unknown-endpoint, got %v", err)
	}
	if err := b.Add(coreDecl()); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Build(); err != nil {
		t.Fatal(err)
	}
}

func TestAddRejectionLeavesBuilderUnchanged(t *testing.T) {
	var b Builder
	if err := b.Add(coreDecl()); err != nil {
		t.Fatal(err)
	}
	bad := awsDecl()
	bad.Relations[0].Confidence = "x"
	if err := b.Add(bad); err == nil {
		t.Fatal("want error")
	}
	if err := b.Add(coreDecl()); !hasRule(failures(t, err), "duplicate-source", "core") {
		t.Fatalf("want duplicate-source, got %v", err)
	}
	r, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Kinds()) != 1 || len(r.Relations()) != 1 {
		t.Fatalf("builder changed: %d kinds, %d relations", len(r.Kinds()), len(r.Relations()))
	}
}

func TestRequiredNamesReportedOnePerMissing(t *testing.T) {
	var b Builder
	b.Require(SourceAWS, Requirement{Kinds: []string{"aws_resource", "aws_cidr"}, Types: []string{"ec2:vpc", "ec2:eni"}, Relations: []string{"aws_nope"}, Categories: []string{"dns"}})
	fs := failures(t, b.Add(awsDecl()))
	if len(fs) != 4 {
		t.Fatalf("want 4 missing-required failures, got %v", fs)
	}
	for _, n := range []string{"aws_cidr", "ec2:eni", "aws_nope", "dns"} {
		if !hasRule(fs, "missing-required", n) {
			t.Errorf("missing %s", n)
		}
	}
}

func TestRegistryIsImmutable(t *testing.T) {
	r, err := Merge(coreDecl(), awsDecl())
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Register(coreDecl()); !errors.Is(err, ErrImmutable) {
		t.Fatalf("Register = %v", err)
	}
	r.Kinds()[0].Identity[0] = "changed"
	k, _ := r.Kind("aws_resource")
	k.Identity[0] = "changed"
	k.Types[0].Name = "changed"
	if k2, _ := r.Kind("aws_resource"); k2.Identity[0] != "connection" || k2.Types[0].Name != "ec2:vpc" {
		t.Fatalf("registry mutated through accessor: %+v", k2)
	}
}

func TestRegisteredOnly(t *testing.T) {
	d := awsDecl()
	d.Categories = append(d.Categories, CategoryDeclaration{ID: "dns", Name: "DNS", Status: RegisteredOnly})
	r, err := Merge(coreDecl(), d)
	if err != nil {
		t.Fatal(err)
	}
	got := r.RegisteredOnly([]string{"network", "dns", "zzz", "dns"})
	if strings.Join(got, ",") != "dns,zzz" {
		t.Fatalf("got %v", got)
	}
	if got := r.RegisteredOnly(nil); got == nil || len(got) != 0 {
		t.Fatalf("want empty non-nil, got %#v", got)
	}
}

func TestIsSecretName(t *testing.T) {
	for n, want := range map[string]bool{"API_Token": true, "password": true, "arn": false, "hash": true, "hostname": false} {
		if IsSecretName(n) != want {
			t.Errorf("IsSecretName(%q) != %v", n, want)
		}
	}
}
