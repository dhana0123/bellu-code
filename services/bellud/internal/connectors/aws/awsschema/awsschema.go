// Package awsschema declares the kinds, resource types, and categories that
// the aws source owns. It imports only the standard library and schema.
//
// Relation declarations are in relations.go.
package awsschema

import "github.com/bellu/bellucode/services/bellud/internal/graph/schema"

// Kind names.
const (
	KindAccount         = "aws_account"
	KindResource        = "aws_resource"
	KindSGRule          = "aws_sg_rule"
	KindCIDR            = "aws_cidr"
	KindPolicyStatement = "aws_policy_statement"
)

// Category ids.
const (
	CatOwnership = "ownership"
	CatNetwork   = "network"
	CatCompute   = "compute"
	CatIdentity  = "identity"
	CatData      = "data"
	CatControls  = "controls"
	CatDNS       = "dns"
)

// Discriminator attributes.
const (
	DiscriminatorResourceType  = "resource_type"
	DiscriminatorStatementKind = "statement_kind"
)

// aws_policy_statement discriminator values.
const (
	TypeStatement = "statement"
	TypeTrust     = "trust"
	TypeBoundary  = "boundary"
)

// Resource type names.
const (
	// ownership
	TypeOrgOrganization = "organizations:organization"
	TypeOrgRoot         = "organizations:root"
	TypeOrgOU           = "organizations:ou"
	TypeOrgSCP          = "organizations:scp"
	TypeRegion          = "aws:region"
	// network
	TypeVPC             = "ec2:vpc"
	TypeSubnet          = "ec2:subnet"
	TypeENI             = "ec2:eni"
	TypeRouteTable      = "ec2:route-table"
	TypeRoute           = "ec2:route"
	TypeInternetGateway = "ec2:internet-gateway"
	TypeNATGateway      = "ec2:nat-gateway"
	TypeSecurityGroup   = "ec2:security-group"
	TypeNetworkACL      = "ec2:network-acl"
	TypeVPCEndpoint     = "ec2:vpc-endpoint"
	TypeVPCPeering      = "ec2:vpc-peering"
	TypeEIP             = "ec2:eip"
	TypeTransitGateway  = "ec2:transit-gateway"
	TypeTGWAttachment   = "ec2:tgw-attachment"
	TypePrefixList      = "ec2:prefix-list"
	TypeLoadBalancer    = "elbv2:load-balancer"
	TypeTargetGroup     = "elbv2:target-group"
	TypeListener        = "elbv2:listener"
	// compute
	TypeInstance         = "ec2:instance"
	TypeAutoScalingGroup = "autoscaling:group"
	TypeLaunchTemplate   = "ec2:launch-template"
	TypeImage            = "ec2:image"
	TypeECSCluster       = "ecs:cluster"
	TypeECSService       = "ecs:service"
	TypeECSTask          = "ecs:task"
	TypeEKSCluster       = "eks:cluster"
	TypeEKSNodegroup     = "eks:nodegroup"
	TypeLambda           = "lambda:function"
	TypeLambdaLayer      = "lambda:layer"
	// identity
	TypeUser            = "iam:user"
	TypeGroup           = "iam:group"
	TypeRole            = "iam:role"
	TypeInstanceProfile = "iam:instance-profile"
	TypePolicy          = "iam:policy"
	TypeInlinePolicy    = "iam:inline-policy"
	// data
	TypeBucket        = "s3:bucket"
	TypeRDSInstance   = "rds:instance"
	TypeRDSCluster    = "rds:cluster"
	TypeDynamoDBTable = "dynamodb:table"
	TypeVolume        = "ec2:volume"
	TypeSnapshot      = "ec2:snapshot"
	TypeEFSFileSystem = "efs:file-system"
	TypeKMSKey        = "kms:key"
	TypeKMSAlias      = "kms:alias"
	TypeSecret        = "secretsmanager:secret"
	TypeSSMParameter  = "ssm:parameter"
	// controls
	TypeGuardDutyDetector  = "guardduty:detector"
	TypeGuardDutyFinding   = "guardduty:finding"
	TypeConfigRecorder     = "config:recorder"
	TypeConfigRule         = "config:rule"
	TypeCloudTrail         = "cloudtrail:trail"
	TypeWebACL             = "wafv2:web-acl"
	TypeSecurityHubFinding = "securityhub:finding"
	TypeInspectorFinding   = "inspector2:finding"
	// dns
	TypeHostedZone = "route53:hosted-zone"
	TypeRecord     = "route53:record"
)

const dataStoreAttrs = " Data store attributes (s3:bucket and rds:instance): encryption_at_rest, encryption_in_transit, public_access, backup and logging, each enabled, disabled or unknown; unknown means the data was not readable. missing_data (string, comma-separated API calls that were denied or failed)."

// Documented scalar attributes read by lenses and Authorization_Analysis.
const (
	resourceAttrs = " Scalar attributes read by lenses: resource_type (string, the service type name, one of the declared types); region (string, an AWS region id such as us-east-1); " +
		"internet_exposed (string: true, partial, or false); truncated (string: true, set only when collection of this resource was cut short)."
	sgRuleAttrs = " Attributes: direction (ingress or egress); from_port and to_port (integer 0..65535); internet_open (true or false); prefix_list (string, a prefix list id)."
)

// typ declares a resource type. The registry matches type values exactly, so
// the iam:*, rds:* and similar overrides of the design table are enumerated
// from the collected types; ovTyp carries the override.
func typ(name, category, desc string) schema.TypeDeclaration {
	return schema.TypeDeclaration{Name: name, Category: category, Description: desc}
}

func ovTyp(name, category, desc string, ov schema.OverviewCategory) schema.TypeDeclaration {
	t := typ(name, category, desc)
	t.Overview = ov
	return t
}

// Declaration returns the aws source declaration.
func Declaration() schema.SourceDeclaration {
	return schema.SourceDeclaration{
		Source: schema.SourceAWS,
		Prefix: "aws_",
		Kinds: []schema.KindDeclaration{
			{
				Name:        KindAccount,
				Overview:    schema.OvCloud,
				Identity:    []string{"connection", "account_id"},
				Description: "An AWS account that a connection reads. Attribute rules_truncated (string: true) marks an account whose security group rules were cut short; truncated (string: true) marks a cut-short collection.",
			},
			{
				Name:          KindResource,
				Overview:      schema.OvCloud,
				Identity:      []string{"connection", "arn"},
				Description:   "An AWS resource identified by its ARN. The resource_type attribute says which service type it is." + resourceAttrs + " rules_truncated (string: true) marks a security group whose rules were cut short.",
				Discriminator: DiscriminatorResourceType,
				Types: []schema.TypeDeclaration{
					typ(TypeOrgOrganization, CatOwnership, "An AWS Organizations organization."),
					typ(TypeOrgRoot, CatOwnership, "An organization root."),
					typ(TypeOrgOU, CatOwnership, "An organizational unit."),
					typ(TypeOrgSCP, CatOwnership, "A service control policy."),
					typ(TypeRegion, CatOwnership, "An AWS region."),
					typ(TypeVPC, CatNetwork, "A virtual private cloud."),
					typ(TypeSubnet, CatNetwork, "A VPC subnet."),
					typ(TypeENI, CatNetwork, "An elastic network interface."),
					typ(TypeRouteTable, CatNetwork, "A route table."),
					typ(TypeRoute, CatNetwork, "A route in a route table."),
					typ(TypeInternetGateway, CatNetwork, "An internet gateway."),
					typ(TypeNATGateway, CatNetwork, "A NAT gateway."),
					typ(TypeSecurityGroup, CatNetwork, "A security group that filters network traffic."),
					typ(TypeNetworkACL, CatNetwork, "A network ACL."),
					typ(TypeVPCEndpoint, CatNetwork, "A VPC endpoint."),
					typ(TypeVPCPeering, CatNetwork, "A VPC peering connection."),
					typ(TypeEIP, CatNetwork, "An elastic IP address."),
					typ(TypeTransitGateway, CatNetwork, "A transit gateway."),
					typ(TypeTGWAttachment, CatNetwork, "A transit gateway attachment."),
					typ(TypePrefixList, CatNetwork, "A managed prefix list. Registered but not collected."),
					typ(TypeLoadBalancer, CatNetwork, "An Elastic Load Balancing v2 load balancer."),
					typ(TypeTargetGroup, CatNetwork, "A load balancer target group."),
					typ(TypeListener, CatNetwork, "A load balancer listener."),
					typ(TypeInstance, CatCompute, "An EC2 instance."),
					typ(TypeAutoScalingGroup, CatCompute, "An Auto Scaling group."),
					typ(TypeLaunchTemplate, CatCompute, "An EC2 launch template."),
					typ(TypeImage, CatCompute, "An Amazon machine image."),
					typ(TypeECSCluster, CatCompute, "An ECS cluster."),
					typ(TypeECSService, CatCompute, "An ECS service."),
					typ(TypeECSTask, CatCompute, "An ECS task."),
					typ(TypeEKSCluster, CatCompute, "An EKS cluster."),
					typ(TypeEKSNodegroup, CatCompute, "An EKS node group."),
					typ(TypeLambda, CatCompute, "A Lambda function."),
					typ(TypeLambdaLayer, CatCompute, "A Lambda layer."),
					ovTyp(TypeUser, CatIdentity, "An IAM user.", schema.OvIdentity),
					ovTyp(TypeGroup, CatIdentity, "An IAM group.", schema.OvIdentity),
					ovTyp(TypeRole, CatIdentity, "An IAM role.", schema.OvIdentity),
					ovTyp(TypeInstanceProfile, CatIdentity, "An IAM instance profile.", schema.OvIdentity),
					ovTyp(TypePolicy, CatIdentity, "A managed IAM policy.", schema.OvIdentity),
					ovTyp(TypeInlinePolicy, CatIdentity, "An inline IAM policy.", schema.OvIdentity),
					ovTyp(TypeBucket, CatData, "An S3 bucket."+dataStoreAttrs, schema.OvData),
					ovTyp(TypeRDSInstance, CatData, "An RDS database instance."+dataStoreAttrs, schema.OvData),
					ovTyp(TypeRDSCluster, CatData, "An RDS database cluster.", schema.OvData),
					ovTyp(TypeDynamoDBTable, CatData, "A DynamoDB table.", schema.OvData),
					typ(TypeVolume, CatData, "An EBS volume."),
					typ(TypeSnapshot, CatData, "An EBS snapshot."),
					typ(TypeEFSFileSystem, CatData, "An EFS file system."),
					typ(TypeKMSKey, CatData, "A KMS key."),
					typ(TypeKMSAlias, CatData, "A KMS key alias."),
					typ(TypeSecret, CatData, "A Secrets Manager secret."),
					typ(TypeSSMParameter, CatData, "An SSM parameter."),
					typ(TypeGuardDutyDetector, CatControls, "A GuardDuty detector."),
					typ(TypeGuardDutyFinding, CatControls, "A GuardDuty finding."),
					typ(TypeConfigRecorder, CatControls, "An AWS Config recorder."),
					typ(TypeConfigRule, CatControls, "An AWS Config rule."),
					typ(TypeCloudTrail, CatControls, "A CloudTrail trail."),
					typ(TypeWebACL, CatControls, "A WAFv2 web ACL."),
					typ(TypeSecurityHubFinding, CatControls, "A Security Hub finding."),
					typ(TypeInspectorFinding, CatControls, "An Inspector finding."),
					typ(TypeHostedZone, CatDNS, "A Route 53 hosted zone."),
					typ(TypeRecord, CatDNS, "A Route 53 record."),
				},
			},
			{
				Name:        KindSGRule,
				Overview:    schema.OvNetwork,
				Identity:    []string{"connection", "sg", "rule_id"},
				Description: "One security group rule. sg is the security group ARN." + sgRuleAttrs,
			},
			{
				Name:        KindCIDR,
				Overview:    schema.OvNetwork,
				Identity:    []string{"connection", "cidr"},
				Description: "A CIDR block that a security group rule names as its peer. internet_open (true or false) is true for 0.0.0.0/0 and ::/0.",
			},
			{
				Name:          KindPolicyStatement,
				Overview:      schema.OvIdentity,
				Identity:      []string{"connection", "policy", "statement_id"},
				Description:   "One statement of an IAM policy or role. policy is the policy or role ARN. statement_kind is statement, trust, or boundary. Registered only; no collector emits it yet.",
				Discriminator: DiscriminatorStatementKind,
				Types: []schema.TypeDeclaration{
					typ(TypeStatement, CatIdentity, "A permission statement of a policy."),
					typ(TypeTrust, CatIdentity, "A trust statement of a role."),
					typ(TypeBoundary, CatIdentity, "A permissions boundary statement."),
				},
			},
		},
		Relations: relations(),
		Categories: []schema.CategoryDeclaration{
			{ID: CatOwnership, Name: "Ownership", Status: schema.RegisteredOnly, ReadOps: []string{
				"organizations:DescribeOrganization",
				"organizations:ListRoots",
				"organizations:ListOrganizationalUnitsForParent",
				"organizations:ListAccountsForParent",
				"organizations:ListPolicies",
				"organizations:ListTargetsForPolicy",
			}},
			{ID: CatNetwork, Name: "Network", Status: schema.Implemented},
			{ID: CatCompute, Name: "Compute", Status: schema.RegisteredOnly, ReadOps: []string{
				"ec2:DescribeLaunchTemplates",
				"ec2:DescribeImages",
				"autoscaling:DescribeAutoScalingGroups",
				"ecs:ListClusters",
				"ecs:DescribeServices",
				"ecs:ListTasks",
				"ecs:DescribeTasks",
				"eks:ListClusters",
				"eks:DescribeCluster",
				"eks:ListNodegroups",
				"lambda:ListLayers",
				"iam:ListInstanceProfiles",
			}},
			{ID: CatIdentity, Name: "Identity", Status: schema.RegisteredOnly, ReadOps: []string{
				"iam:GetAccountAuthorizationDetails",
				"iam:ListUsers",
				"iam:ListGroups",
				"iam:ListPolicies",
				"iam:GetPolicyVersion",
				"iam:GetRole",
			}},
			{ID: CatData, Name: "Data", Status: schema.RegisteredOnly, ReadOps: []string{
				"s3:GetBucketEncryption",
				"s3:GetBucketPolicy",
				"rds:DescribeDBClusters",
				"dynamodb:ListTables",
				"dynamodb:DescribeTable",
				"ec2:DescribeVolumes",
				"ec2:DescribeSnapshots",
				"elasticfilesystem:DescribeFileSystems",
				"kms:ListKeys",
				"kms:DescribeKey",
				"kms:ListAliases",
				"secretsmanager:ListSecrets",
				"ssm:DescribeParameters",
			}},
			{ID: CatControls, Name: "Controls", Status: schema.RegisteredOnly, ReadOps: []string{
				"guardduty:ListDetectors",
				"guardduty:ListFindings",
				"guardduty:GetFindings",
				"config:DescribeConfigurationRecorders",
				"config:DescribeConfigRules",
				"cloudtrail:DescribeTrails",
				"wafv2:ListWebACLs",
				"securityhub:GetFindings",
				"inspector2:ListFindings",
			}},
			{ID: CatDNS, Name: "DNS", Status: schema.RegisteredOnly, ReadOps: []string{
				"route53:ListHostedZones",
				"route53:ListResourceRecordSets",
			}},
		},
	}
}

// Required lists every name that the aws declaration must contain
// (requirements 10.1 to 10.7). schemaall passes it to the merge, which fails
// the declaration with one failure per missing name.
var Required = schema.Requirement{
	Kinds:      []string{KindAccount, KindResource, KindSGRule, KindCIDR, KindPolicyStatement},
	Categories: []string{CatOwnership, CatNetwork, CatCompute, CatIdentity, CatData, CatControls, CatDNS},
	Types: []string{
		TypeStatement,
		TypeTrust,
		TypeBoundary,
		TypeOrgOrganization,
		TypeOrgRoot,
		TypeOrgOU,
		TypeOrgSCP,
		TypeRegion,
		TypeVPC,
		TypeSubnet,
		TypeENI,
		TypeRouteTable,
		TypeRoute,
		TypeInternetGateway,
		TypeNATGateway,
		TypeSecurityGroup,
		TypeNetworkACL,
		TypeVPCEndpoint,
		TypeVPCPeering,
		TypeEIP,
		TypeTransitGateway,
		TypeTGWAttachment,
		TypePrefixList,
		TypeLoadBalancer,
		TypeTargetGroup,
		TypeListener,
		TypeInstance,
		TypeAutoScalingGroup,
		TypeLaunchTemplate,
		TypeImage,
		TypeECSCluster,
		TypeECSService,
		TypeECSTask,
		TypeEKSCluster,
		TypeEKSNodegroup,
		TypeLambda,
		TypeLambdaLayer,
		TypeUser,
		TypeGroup,
		TypeRole,
		TypeInstanceProfile,
		TypePolicy,
		TypeInlinePolicy,
		TypeBucket,
		TypeRDSInstance,
		TypeRDSCluster,
		TypeDynamoDBTable,
		TypeVolume,
		TypeSnapshot,
		TypeEFSFileSystem,
		TypeKMSKey,
		TypeKMSAlias,
		TypeSecret,
		TypeSSMParameter,
		TypeGuardDutyDetector,
		TypeGuardDutyFinding,
		TypeConfigRecorder,
		TypeConfigRule,
		TypeCloudTrail,
		TypeWebACL,
		TypeSecurityHubFinding,
		TypeInspectorFinding,
		TypeHostedZone,
		TypeRecord,
	},
	Relations: []string{
		"aws_member_of",
		"aws_child_of",
		"aws_scp_attached",
		"aws_in_vpc",
		"aws_in_subnet",
		"aws_has_eni",
		"aws_member_of_sg",
		"aws_routes_to",
		"aws_route_of",
		"aws_associated_subnet",
		"aws_attached_igw",
		"aws_nat_in_subnet",
		"aws_peers_with",
		"aws_tgw_attached",
		"aws_lb_forwards_to",
		"aws_lb_listener_of",
		"aws_targets",
		"aws_rule_of",
		"aws_rule_peer",
		"aws_assigned_to",
		"aws_exposed_via",
		"aws_allows_ingress_from",
		"aws_allows_egress_to",
		"aws_uses_image",
		"aws_in_asg",
		"aws_launched_from",
		"aws_has_instance_profile",
		"aws_profile_has_role",
		"aws_task_role",
		"aws_exec_role",
		"aws_lambda_role",
		"aws_cluster_role",
		"aws_in_cluster",
		"aws_service_of",
		"aws_uses_layer",
		"aws_uses_subnet",
		"aws_in_nodegroup",
		"aws_member_of_group",
		"aws_attached_policy",
		"aws_trusts",
		"aws_can_assume",
		"aws_can_pass_role",
		"aws_has_boundary",
		"aws_statement_of",
		"aws_can_access",
		"aws_encrypted_by",
		"aws_stores_in",
		"aws_reads_from",
		"aws_writes_to",
		"aws_attached_volume",
		"aws_mounts_fs",
		"aws_snapshot_of",
		"aws_alias_of",
		"aws_monitors",
		"aws_logs_to",
		"aws_protects",
		"aws_finding_affects",
		"aws_record_in_zone",
		"aws_dns_points_to",
	},
}
