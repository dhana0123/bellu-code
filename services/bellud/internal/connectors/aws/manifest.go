package aws

import (
	"github.com/bellu/bellucode/services/bellud/internal/connectors/manifest"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/registry"
)

// ConnectorID is the registry id of the AWS connector.
const ConnectorID = "aws"

// Auth method ids.
const (
	MethodSSO        = "sso"
	MethodAssumeRole = "assume_role"
	MethodStaticKeys = "static_keys"
)

// Host patterns. {region} is filled from the connection's selected regions,
// so a request to any other region is blocked by the policy.
const (
	hostSTS      = "sts.{region}.amazonaws.com"
	hostIAM      = "iam.amazonaws.com"
	hostEC2      = "ec2.{region}.amazonaws.com"
	hostS3       = "s3.{region}.amazonaws.com"
	hostS3Bucket = "*.s3.{region}.amazonaws.com"
	hostLambda   = "lambda.{region}.amazonaws.com"
	hostRDS      = "rds.{region}.amazonaws.com"
	hostELB      = "elasticloadbalancing.{region}.amazonaws.com"
)

// Manifest returns the built-in AWS Connector_Manifest.
func Manifest() manifest.Manifest {
	read := func(name, host string) manifest.Operation {
		return manifest.Operation{Name: name, Class: manifest.ClassRead, Host: host}
	}
	ops := []manifest.Operation{
		read("ec2:DescribeInstances", hostEC2),
		read("ec2:DescribeSecurityGroups", hostEC2),
		read("ec2:DescribeVpcs", hostEC2),
		read("ec2:DescribeRegions", hostEC2),
		read("s3:ListBuckets", hostS3),
		read("s3:GetBucketLocation", hostS3Bucket),
		read("iam:ListRoles", hostIAM),
		read("iam:SimulatePrincipalPolicy", hostIAM),
		read("lambda:ListFunctions", hostLambda),
		read("rds:DescribeDBInstances", hostRDS),
		read("ec2:DescribeSubnets", hostEC2),
		read("ec2:DescribeNetworkInterfaces", hostEC2),
		read("ec2:DescribeRouteTables", hostEC2),
		read("ec2:DescribeInternetGateways", hostEC2),
		read("ec2:DescribeNatGateways", hostEC2),
		read("ec2:DescribeSecurityGroupRules", hostEC2),
		read("ec2:DescribeNetworkAcls", hostEC2),
		read("ec2:DescribeVpcEndpoints", hostEC2),
		read("ec2:DescribeVpcPeeringConnections", hostEC2),
		read("ec2:DescribeAddresses", hostEC2),
		read("ec2:DescribeTransitGateways", hostEC2),
		read("ec2:DescribeTransitGatewayAttachments", hostEC2),
		read("elasticloadbalancing:DescribeLoadBalancers", hostELB),
		read("elasticloadbalancing:DescribeTargetGroups", hostELB),
		read("elasticloadbalancing:DescribeListeners", hostELB),
		read("elasticloadbalancing:DescribeTargetHealth", hostELB),
		read("sts:GetCallerIdentity", hostSTS),
		// manifest.IsWrite treats sts:AssumeRole as a write, so it is listed
		// as a POST query. Class auth keeps it to lifecycle callers.
		{Name: "sts:AssumeRole", Class: manifest.ClassAuth, Method: "POST", Query: true, Host: hostSTS},
	}
	perms := make([]manifest.Permission, 0, len(ops))
	for _, op := range ops {
		if op.Class == manifest.ClassRead {
			perms = append(perms, manifest.Permission{Name: op.Name, ReadOnly: true})
		}
	}
	return manifest.Manifest{
		ID: ConnectorID, Version: "1.0.0", Name: "AWS", Icon: "aws", Builtin: true,
		AuthMethods: []manifest.AuthMethod{
			{ID: MethodSSO, Name: "IAM Identity Center (SSO)", Enabled: false, DisabledReason: "Coming soon"},
			{ID: MethodAssumeRole, Name: "AssumeRole with external ID", Enabled: true},
			{ID: MethodStaticKeys, Name: "Static access keys", Enabled: true},
		},
		Permissions: perms,
		Operations:  ops,
		Egress:      []string{hostSTS, hostIAM, hostEC2, hostS3, hostS3Bucket, hostLambda, hostRDS, hostELB},
		Entities:    []string{kindAccount, kindResource, kindSGRule, kindCIDR},
	}
}

// Register adds the AWS manifest to r. The registry validates it against the
// manifest rules.
func Register(r registry.Registry) error { return r.Register(Manifest()) }
