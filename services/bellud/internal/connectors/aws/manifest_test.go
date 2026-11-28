package aws

import (
	"slices"
	"strings"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/manifest"
)

// networkReadOps are the read operations of Requirement 11.5.
var networkReadOps = []string{
	"ec2:DescribeSubnets", "ec2:DescribeNetworkInterfaces", "ec2:DescribeRouteTables",
	"ec2:DescribeInternetGateways", "ec2:DescribeNatGateways", "ec2:DescribeSecurityGroupRules",
	"ec2:DescribeNetworkAcls", "ec2:DescribeVpcEndpoints", "ec2:DescribeVpcPeeringConnections",
	"ec2:DescribeAddresses", "ec2:DescribeTransitGateways", "ec2:DescribeTransitGatewayAttachments",
	"elasticloadbalancing:DescribeLoadBalancers", "elasticloadbalancing:DescribeTargetGroups",
	"elasticloadbalancing:DescribeListeners", "elasticloadbalancing:DescribeTargetHealth",
}

func TestManifestNetworkReadOperations(t *testing.T) {
	m := Manifest()
	ops := map[string]manifest.Operation{}
	for _, op := range m.Operations {
		ops[op.Name] = op
	}
	for _, name := range networkReadOps {
		op, ok := ops[name]
		switch {
		case !ok:
			t.Errorf("%s is missing", name)
		case op.Class != manifest.ClassRead:
			t.Errorf("%s has class %v, want read", name, op.Class)
		case op.Host == "":
			t.Errorf("%s has no host", name)
		}
		verb := name[strings.IndexByte(name, ':')+1:]
		if !strings.HasPrefix(verb, "Describe") && !strings.HasPrefix(verb, "List") && !strings.HasPrefix(verb, "Get") {
			t.Errorf("%s does not use a Describe, List, or Get verb", name)
		}
	}
	if !slices.Contains(m.Egress, hostELB) {
		t.Errorf("egress %v lacks %s", m.Egress, hostELB)
	}
}

func TestTemplatesAttachManagedReadPolicies(t *testing.T) {
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
	for name, doc := range map[string]string{"cloudformation": cfn, "terraform": tf, "parameterized": CloudFormationTemplateParameterized()} {
		for _, arn := range []string{"arn:aws:iam::aws:policy/ReadOnlyAccess", "arn:aws:iam::aws:policy/SecurityAudit"} {
			if !strings.Contains(doc, arn) {
				t.Errorf("%s template lacks %s", name, arn)
			}
		}
	}
}
