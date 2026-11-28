package aws

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestGenerateExternalIDUniqueAndLong(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		id, err := GenerateExternalID()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(id, ExternalIDPrefix) || len(id) < 32 {
			t.Fatalf("bad id %q", id)
		}
		if seen[id] {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = true
	}
}

func TestTemplatesEmbedValues(t *testing.T) {
	id, _ := GenerateExternalID()
	p := TrustParams{RoleName: "bellu-read", Principal: "arn:aws:iam::123456789012:role/bellu", ExternalID: id}
	cfn, err := CloudFormationTemplate(p)
	if err != nil {
		t.Fatal(err)
	}
	tf, err := TerraformSnippet(p)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(cfn), &doc); err != nil {
		t.Fatalf("cfn not valid yaml: %v", err)
	}
	for name, out := range map[string]string{"cfn": cfn, "tf": tf} {
		for _, want := range []string{id, p.Principal, "ReadOnlyAccess", "SecurityAudit", "iam:SimulatePrincipalPolicy", "role/bellu-read"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s missing %q", name, want)
			}
		}
		if strings.Contains(out, "{{") {
			t.Errorf("%s has unreplaced placeholder", name)
		}
	}
}

func TestTemplatesRejectInjection(t *testing.T) {
	good := TrustParams{RoleName: "r", Principal: "arn:aws:iam::123456789012:root", ExternalID: "BELLU-ABC"}
	if _, err := CloudFormationTemplate(good); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []TrustParams{
		{RoleName: "r\"\nx: y", Principal: good.Principal, ExternalID: good.ExternalID},
		{RoleName: "r", Principal: "arn:aws:iam::1:root", ExternalID: good.ExternalID},
		{RoleName: "r", Principal: good.Principal, ExternalID: "a\"b"},
	} {
		if _, err := TerraformSnippet(bad); err == nil {
			t.Errorf("expected rejection for %+v", bad)
		}
	}
}
