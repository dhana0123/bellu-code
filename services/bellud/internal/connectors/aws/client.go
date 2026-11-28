package aws

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

// This file builds every AWS service client. Collectors depend on the Client
// interface and its typed projections only; no SDK type leaves this package.
// auth.go additionally uses the SDK core and STS types it needs for session
// credentials. All SDK clients are built on an *http.Client from
// broker.HTTPClient, so the policy transport sees every request.

// Typed errors. They carry an AWS error code at most, never a message that may
// echo request data or credentials.
var (
	ErrAccessDenied      = errors.New("aws: access denied")
	ErrInvalidCredential = errors.New("aws: invalid credential")
	ErrExpired           = errors.New("aws: credentials expired")
	ErrThrottled         = errors.New("aws: throttled")
)

// maxPages bounds every paginated listing.
const maxPages = 100

// maxItems caps one listing. A listing that stops here sets Listing.Truncated.
const maxItems = 10000

// Listing is a capped API listing. Truncated is true when the listing stopped
// at maxItems although the API had more.
//
// Decision (task 9.1): Instances, SecurityGroups and VPCs return Listing
// directly. Only three fakes construct them, so a sibling method per listing
// would cost more than updating those fakes once.
type Listing[T any] struct {
	Items     []T
	Truncated bool
}

// Identity is the result of sts:GetCallerIdentity.
type Identity struct {
	Account string
	ARN     string
	UserID  string
	// PrincipalARN is ARN with an assumed-role session ARN converted to the
	// role ARN. For non-session ARNs it equals ARN.
	PrincipalARN string
}

// AllowedAction is a write action the policy simulation reports as allowed.
type AllowedAction struct{ Action string }

// Instance is an EC2 instance projection.
type Instance struct {
	ID               string
	Region           string
	Name             string
	State            string
	Type             string
	VPCID            string
	SubnetID         string
	SecurityGroupIDs []string
	PublicIP         string
	ENIIDs           []string
	LaunchTime       time.Time
	TagCount         int
}

// Bucket is an S3 bucket projection.
type Bucket struct {
	Name      string
	Region    string
	CreatedAt time.Time
}

// Data store attribute values. A value is unknown when the data was not
// readable, never a guess in either direction.
const (
	StateEnabled  = "enabled"
	StateDisabled = "disabled"
	StateUnknown  = "unknown"
)

// DataSecurity holds the five security attributes of one data store. Gaps
// lists the API calls that were denied or failed (e.g. "s3:GetBucketLogging");
// the attributes they feed are unknown.
type DataSecurity struct {
	EncryptionAtRest, EncryptionInTransit, PublicAccess, Backup, Logging string
	Gaps                                                                 []string
}

// unknownSecurity is the starting point: nothing proven.
func unknownSecurity() DataSecurity {
	return DataSecurity{EncryptionAtRest: StateUnknown, EncryptionInTransit: StateUnknown,
		PublicAccess: StateUnknown, Backup: StateUnknown, Logging: StateUnknown}
}

func state(b bool) string {
	if b {
		return StateEnabled
	}
	return StateDisabled
}

// SecurityGroup is an EC2 security group projection.
type SecurityGroup struct {
	ID       string
	Region   string
	Name     string
	VPCID    string
	TagCount int
}

// SGRule is one security group rule projection. ID is the provider rule
// identifier (sgr-...) and may be empty.
type SGRule struct {
	ID, GroupID, Direction, Protocol string
	From, To                         int
	HasPorts                         bool
	CIDR, PeerGroupID, PrefixListID  string
	Description                      string
}

// VPC is an EC2 VPC projection.
type VPC struct {
	ID       string
	Region   string
	Name     string
	State    string
	TagCount int
}

// Role is an IAM role projection.
type Role struct {
	ARN       string
	Name      string
	CreatedAt time.Time
}

// Function is a Lambda function projection.
type Function struct {
	ARN     string
	Name    string
	Region  string
	Runtime string
}

// DBInstance is an RDS instance projection.
type DBInstance struct {
	ARN       string
	ID        string
	Region    string
	Engine    string
	Status    string
	CreatedAt time.Time

	StorageEncrypted   bool
	PubliclyAccessible bool
	BackupRetention    int32
	LogExports         []string
}

// Client is the typed AWS wrapper used by the provider and the collector.
type Client interface {
	Identity(ctx context.Context) (Identity, error)
	// SimulateWrites returns the subset of actions the principal is allowed.
	SimulateWrites(ctx context.Context, principalARN string, actions []string) ([]AllowedAction, error)
	Regions(ctx context.Context) ([]string, error)
	Instances(ctx context.Context, region string) (Listing[Instance], error)
	Buckets(ctx context.Context) ([]Bucket, error)
	// BucketSecurity reads the security attributes of one bucket. A denied or
	// failed call is recorded in Gaps and leaves its attributes unknown; only a
	// credential rejection returns an error.
	BucketSecurity(ctx context.Context, bucket, region string) (DataSecurity, error)
	SecurityGroups(ctx context.Context, region string) (Listing[SecurityGroup], error)
	VPCs(ctx context.Context, region string) (Listing[VPC], error)
	Roles(ctx context.Context) ([]Role, error)
	Functions(ctx context.Context, region string) ([]Function, error)
	DBInstances(ctx context.Context, region string) ([]DBInstance, error)

	Subnets(ctx context.Context, region string) (Listing[Subnet], error)
	ENIs(ctx context.Context, region string) (Listing[ENI], error)
	RouteTables(ctx context.Context, region string) (Listing[RouteTable], error)
	InternetGateways(ctx context.Context, region string) (Listing[InternetGateway], error)
	NATGateways(ctx context.Context, region string) (Listing[NATGateway], error)
	SGRules(ctx context.Context, region string) (Listing[SGRule], error)
	NetworkACLs(ctx context.Context, region string) (Listing[NetworkACL], error)
	VPCEndpoints(ctx context.Context, region string) (Listing[VPCEndpoint], error)
	PeeringConnections(ctx context.Context, region string) (Listing[PeeringConnection], error)
	ElasticIPs(ctx context.Context, region string) (Listing[ElasticIP], error)
	TransitGateways(ctx context.Context, region string) (Listing[TransitGateway], error)
	TGWAttachments(ctx context.Context, region string) (Listing[TGWAttachment], error)
	LoadBalancers(ctx context.Context, region string) (Listing[LoadBalancer], error)
	TargetGroups(ctx context.Context, region string) (Listing[TargetGroup], error)
	// Listeners and TargetHealth are per parent. The API caps them per parent.
	Listeners(ctx context.Context, region, lbARN string) ([]Listener, error)
	TargetHealth(ctx context.Context, region, tgARN string) ([]TargetHealth, error)
}

// Config configures NewClient.
type Config struct {
	// HTTPClient must come from broker.HTTPClient.
	HTTPClient *http.Client
	// Credentials signs requests (vault-backed or an assume-role provider).
	Credentials awssdk.CredentialsProvider
	// HomeRegion hosts global calls (STS, IAM, S3 listing, region listing).
	// Defaults to the first of Regions.
	HomeRegion string
}

type client struct {
	cfg  Config
	home string

	mu  sync.Mutex
	ec2 map[string]*ec2.Client
	lam map[string]*lambda.Client
	rds map[string]*rds.Client
	elb map[string]*elasticloadbalancingv2.Client
}

// NewClient returns a Client. It fails when HTTPClient or Credentials is nil
// or no home region is given, so an SDK client can never fall back to its
// default HTTP client or credential chain.
func NewClient(cfg Config) (Client, error) {
	if cfg.HTTPClient == nil || cfg.Credentials == nil || cfg.HomeRegion == "" {
		return nil, errors.New("aws: client requires an http client, credentials and a region")
	}
	return &client{cfg: cfg, home: cfg.HomeRegion,
		ec2: map[string]*ec2.Client{}, lam: map[string]*lambda.Client{}, rds: map[string]*rds.Client{},
		elb: map[string]*elasticloadbalancingv2.Client{}}, nil
}

func (c *client) base(region string) awssdk.Config {
	return awssdk.Config{
		Region: region, HTTPClient: c.cfg.HTTPClient, Credentials: c.cfg.Credentials,
		RetryMaxAttempts: 3,
	}
}

func (c *client) sts() *sts.Client { return sts.NewFromConfig(c.base(c.home)) }
func (c *client) iam() *iam.Client { return iam.NewFromConfig(c.base("us-east-1")) }
func (c *client) s3() *s3.Client   { return s3.NewFromConfig(c.base(c.home)) }

func (c *client) s3At(r string) *s3.Client { return s3.NewFromConfig(c.base(r)) }

func (c *client) ec2At(r string) *ec2.Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := c.ec2[r]; ok {
		return v
	}
	v := ec2.NewFromConfig(c.base(r))
	c.ec2[r] = v
	return v
}

func (c *client) lambdaAt(r string) *lambda.Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := c.lam[r]; ok {
		return v
	}
	v := lambda.NewFromConfig(c.base(r))
	c.lam[r] = v
	return v
}

func (c *client) rdsAt(r string) *rds.Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := c.rds[r]; ok {
		return v
	}
	v := rds.NewFromConfig(c.base(r))
	c.rds[r] = v
	return v
}

func (c *client) elbv2At(r string) *elasticloadbalancingv2.Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := c.elb[r]; ok {
		return v
	}
	v := elasticloadbalancingv2.NewFromConfig(c.base(r))
	c.elb[r] = v
	return v
}

// mapErr converts SDK errors to typed, message-free errors. Errors that are
// not AWS API errors (broker blocks, credential, network errors) pass through
// so callers can inspect them with errors.As.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	var ae smithy.APIError
	if !errors.As(err, &ae) {
		return err
	}
	code := ae.ErrorCode()
	switch code {
	case "AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "AuthFailure", "UnauthorizedAccess":
		return fmt.Errorf("%w (%s)", ErrAccessDenied, code)
	case "ExpiredToken", "ExpiredTokenException", "RequestExpired":
		return fmt.Errorf("%w (%s)", ErrExpired, code)
	case "InvalidClientTokenId", "SignatureDoesNotMatch", "InvalidAccessKeyId", "UnrecognizedClientException", "IncompleteSignature":
		return fmt.Errorf("%w (%s)", ErrInvalidCredential, code)
	case "Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyRequestsException", "SlowDown", "Throttled":
		return fmt.Errorf("%w (%s)", ErrThrottled, code)
	}
	return fmt.Errorf("aws: api error (%s)", code)
}

// pager drives a paginator for at most maxPages pages.
func pager(ctx context.Context, more func() bool, next func(context.Context) error) error {
	for i := 0; more(); i++ {
		if i >= maxPages {
			return errors.New("aws: too many result pages")
		}
		if err := next(ctx); err != nil {
			return mapErr(err)
		}
	}
	return nil
}

// listAll drives a paginator and caps the result at maxItems. On an error it
// returns the items read so far with the mapped error.
func listAll[T any](ctx context.Context, more func() bool, next func(context.Context) ([]T, error)) (Listing[T], error) {
	var out Listing[T]
	for i := 0; more(); i++ {
		if i >= maxPages {
			return out, errors.New("aws: too many result pages")
		}
		items, err := next(ctx)
		if err != nil {
			return out, mapErr(err)
		}
		out.Items = append(out.Items, items...)
		if len(out.Items) >= maxItems {
			out.Truncated = len(out.Items) > maxItems || more()
			out.Items = out.Items[:min(len(out.Items), maxItems)]
			break
		}
	}
	return out, nil
}

func (c *client) Identity(ctx context.Context) (Identity, error) {
	out, err := c.sts().GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return Identity{}, mapErr(err)
	}
	id := Identity{Account: awssdk.ToString(out.Account), ARN: awssdk.ToString(out.Arn), UserID: awssdk.ToString(out.UserId)}
	id.PrincipalARN = PrincipalFromARN(id.ARN)
	return id, nil
}

func (c *client) SimulateWrites(ctx context.Context, principalARN string, actions []string) ([]AllowedAction, error) {
	var allowed []AllowedAction
	p := iam.NewSimulatePrincipalPolicyPaginator(c.iam(), &iam.SimulatePrincipalPolicyInput{
		PolicySourceArn: awssdk.String(principalARN), ActionNames: actions,
	})
	err := pager(ctx, p.HasMorePages, func(ctx context.Context) error {
		page, err := p.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, r := range page.EvaluationResults {
			if r.EvalDecision == iamtypes.PolicyEvaluationDecisionTypeAllowed {
				allowed = append(allowed, AllowedAction{Action: awssdk.ToString(r.EvalActionName)})
			}
		}
		return nil
	})
	return allowed, err
}

func (c *client) Regions(ctx context.Context) ([]string, error) {
	out, err := c.ec2At(c.home).DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		return nil, mapErr(err)
	}
	var rs []string
	for _, r := range out.Regions {
		rs = append(rs, awssdk.ToString(r.RegionName))
	}
	return rs, nil
}

func ec2Name(tags []ec2types.Tag) string {
	for _, t := range tags {
		if awssdk.ToString(t.Key) == "Name" {
			return awssdk.ToString(t.Value)
		}
	}
	return ""
}

func (c *client) Instances(ctx context.Context, region string) (Listing[Instance], error) {
	p := ec2.NewDescribeInstancesPaginator(c.ec2At(region), &ec2.DescribeInstancesInput{})
	return listAll(ctx, p.HasMorePages, func(ctx context.Context) ([]Instance, error) {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		var res []Instance
		for _, r := range page.Reservations {
			for _, i := range r.Instances {
				in := Instance{
					ID: awssdk.ToString(i.InstanceId), Region: region, Name: ec2Name(i.Tags),
					Type: string(i.InstanceType), VPCID: awssdk.ToString(i.VpcId),
					SubnetID: awssdk.ToString(i.SubnetId), TagCount: len(i.Tags),
				}
				in.PublicIP = awssdk.ToString(i.PublicIpAddress)
				if i.State != nil {
					in.State = string(i.State.Name)
				}
				if i.LaunchTime != nil {
					in.LaunchTime = *i.LaunchTime
				}
				for _, g := range i.SecurityGroups {
					in.SecurityGroupIDs = append(in.SecurityGroupIDs, awssdk.ToString(g.GroupId))
				}
				for _, n := range i.NetworkInterfaces {
					in.ENIIDs = append(in.ENIIDs, awssdk.ToString(n.NetworkInterfaceId))
				}
				res = append(res, in)
			}
		}
		return res, nil
	})
}

func (c *client) Buckets(ctx context.Context) ([]Bucket, error) {
	var res []Bucket
	p := s3.NewListBucketsPaginator(c.s3(), &s3.ListBucketsInput{})
	err := pager(ctx, p.HasMorePages, func(ctx context.Context) error {
		page, err := p.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, b := range page.Buckets {
			bk := Bucket{Name: awssdk.ToString(b.Name), Region: awssdk.ToString(b.BucketRegion)}
			if b.CreationDate != nil {
				bk.CreatedAt = *b.CreationDate
			}
			res = append(res, bk)
		}
		return nil
	})
	return res, err
}

func (c *client) BucketSecurity(ctx context.Context, bucket, region string) (DataSecurity, error) {
	cl, name := c.s3At(region), awssdk.String(bucket)
	sec := unknownSecurity()
	// gap records a failed call. A rejected credential ends the read.
	gap := func(op string, err error) error {
		err = mapErr(err)
		if isRejected(err) {
			return err
		}
		sec.Gaps = append(sec.Gaps, op)
		return nil
	}
	code := func(err error) string {
		var ae smithy.APIError
		if errors.As(err, &ae) {
			return ae.ErrorCode()
		}
		return ""
	}

	enc, err := cl.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: name})
	switch {
	case err == nil:
		sec.EncryptionAtRest = state(enc.ServerSideEncryptionConfiguration != nil && len(enc.ServerSideEncryptionConfiguration.Rules) > 0)
	case code(err) == "ServerSideEncryptionConfigurationNotFoundError":
		sec.EncryptionAtRest = StateDisabled
	default:
		if e := gap("s3:GetBucketEncryption", err); e != nil {
			return sec, e
		}
	}

	allBlocked, pabKnown := false, false
	pab, err := cl.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: name})
	switch {
	case err == nil && pab.PublicAccessBlockConfiguration != nil:
		cfg := pab.PublicAccessBlockConfiguration
		allBlocked, pabKnown = awssdk.ToBool(cfg.BlockPublicAcls) && awssdk.ToBool(cfg.IgnorePublicAcls) &&
			awssdk.ToBool(cfg.BlockPublicPolicy) && awssdk.ToBool(cfg.RestrictPublicBuckets), true
	case code(err) == "NoSuchPublicAccessBlockConfiguration":
		pabKnown = true
	case err != nil:
		if e := gap("s3:GetPublicAccessBlock", err); e != nil {
			return sec, e
		}
	}
	policyPublic, policyKnown := false, false
	ps, err := cl.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{Bucket: name})
	switch {
	case err == nil && ps.PolicyStatus != nil:
		policyPublic, policyKnown = awssdk.ToBool(ps.PolicyStatus.IsPublic), true
	case code(err) == "NoSuchBucketPolicy":
		policyKnown = true
	case err != nil:
		if e := gap("s3:GetBucketPolicyStatus", err); e != nil {
			return sec, e
		}
	}
	// Public ACLs are not read, so only a full block proves the bucket private.
	switch {
	case policyKnown && policyPublic:
		sec.PublicAccess = StateEnabled
	case pabKnown && allBlocked:
		sec.PublicAccess = StateDisabled
	}

	lg, err := cl.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{Bucket: name})
	if err == nil {
		sec.Logging = state(lg.LoggingEnabled != nil)
	} else if e := gap("s3:GetBucketLogging", err); e != nil {
		return sec, e
	}

	ver, err := cl.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: name})
	if err == nil {
		// Versioning stands in for backup.
		sec.Backup = state(ver.Status == s3types.BucketVersioningStatusEnabled)
	} else if e := gap("s3:GetBucketVersioning", err); e != nil {
		return sec, e
	}
	return sec, nil
}

func (c *client) SecurityGroups(ctx context.Context, region string) (Listing[SecurityGroup], error) {
	p := ec2.NewDescribeSecurityGroupsPaginator(c.ec2At(region), &ec2.DescribeSecurityGroupsInput{})
	return listAll(ctx, p.HasMorePages, func(ctx context.Context) ([]SecurityGroup, error) {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		var res []SecurityGroup
		for _, g := range page.SecurityGroups {
			res = append(res, SecurityGroup{
				ID: awssdk.ToString(g.GroupId), Region: region, Name: awssdk.ToString(g.GroupName),
				VPCID: awssdk.ToString(g.VpcId), TagCount: len(g.Tags),
			})
		}
		return res, nil
	})
}

func (c *client) VPCs(ctx context.Context, region string) (Listing[VPC], error) {
	p := ec2.NewDescribeVpcsPaginator(c.ec2At(region), &ec2.DescribeVpcsInput{})
	return listAll(ctx, p.HasMorePages, func(ctx context.Context) ([]VPC, error) {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		var res []VPC
		for _, v := range page.Vpcs {
			res = append(res, VPC{
				ID: awssdk.ToString(v.VpcId), Region: region, Name: ec2Name(v.Tags),
				State: string(v.State), TagCount: len(v.Tags),
			})
		}
		return res, nil
	})
}

func (c *client) Roles(ctx context.Context) ([]Role, error) {
	var res []Role
	p := iam.NewListRolesPaginator(c.iam(), &iam.ListRolesInput{})
	err := pager(ctx, p.HasMorePages, func(ctx context.Context) error {
		page, err := p.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, r := range page.Roles {
			role := Role{ARN: awssdk.ToString(r.Arn), Name: awssdk.ToString(r.RoleName)}
			if r.CreateDate != nil {
				role.CreatedAt = *r.CreateDate
			}
			res = append(res, role)
		}
		return nil
	})
	return res, err
}

func (c *client) Functions(ctx context.Context, region string) ([]Function, error) {
	var res []Function
	p := lambda.NewListFunctionsPaginator(c.lambdaAt(region), &lambda.ListFunctionsInput{})
	err := pager(ctx, p.HasMorePages, func(ctx context.Context) error {
		page, err := p.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, f := range page.Functions {
			res = append(res, Function{
				ARN: awssdk.ToString(f.FunctionArn), Name: awssdk.ToString(f.FunctionName),
				Region: region, Runtime: string(f.Runtime),
			})
		}
		return nil
	})
	return res, err
}

func (c *client) DBInstances(ctx context.Context, region string) ([]DBInstance, error) {
	var res []DBInstance
	p := rds.NewDescribeDBInstancesPaginator(c.rdsAt(region), &rds.DescribeDBInstancesInput{})
	err := pager(ctx, p.HasMorePages, func(ctx context.Context) error {
		page, err := p.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, d := range page.DBInstances {
			db := DBInstance{
				ARN: awssdk.ToString(d.DBInstanceArn), ID: awssdk.ToString(d.DBInstanceIdentifier),
				Region: region, Engine: awssdk.ToString(d.Engine), Status: awssdk.ToString(d.DBInstanceStatus),
				StorageEncrypted: awssdk.ToBool(d.StorageEncrypted), PubliclyAccessible: awssdk.ToBool(d.PubliclyAccessible),
				BackupRetention: awssdk.ToInt32(d.BackupRetentionPeriod), LogExports: d.EnabledCloudwatchLogsExports,
			}
			if d.InstanceCreateTime != nil {
				db.CreatedAt = *d.InstanceCreateTime
			}
			res = append(res, db)
		}
		return nil
	})
	return res, err
}

// PrincipalFromARN converts an assumed-role session ARN
// (arn:aws:sts::123456789012:assumed-role/Role/session) into the role ARN
// (arn:aws:iam::123456789012:role/Role). Other ARNs are returned unchanged.
// Role paths are not part of a session ARN and cannot be recovered.
func PrincipalFromARN(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[2] != "sts" || !strings.HasPrefix(parts[5], "assumed-role/") {
		return arn
	}
	seg := strings.Split(strings.TrimPrefix(parts[5], "assumed-role/"), "/")
	if len(seg) < 2 || seg[0] == "" {
		return arn
	}
	return strings.Join([]string{parts[0], parts[1], "iam", "", parts[4], "role/" + seg[0]}, ":")
}

// IsRootARN reports whether arn is an account root principal
// (arn:aws*:iam::<12 digits>:root).
func IsRootARN(arn string) bool {
	parts := strings.Split(arn, ":")
	if len(parts) != 6 || !strings.HasPrefix(parts[0]+":"+parts[1], "arn:aws") || parts[2] != "iam" ||
		parts[3] != "" || parts[5] != "root" || len(parts[4]) != 12 {
		return false
	}
	for _, r := range parts[4] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// Network projections. They hold identifiers and structure only: no tag
// values, user data, or environment values.

// Subnet is an EC2 subnet projection.
type Subnet struct {
	ID, Region, VPCID, AZ, CIDR, Name string
	TagCount                          int
}

// ENI is an elastic network interface projection.
type ENI struct {
	ID, Region, SubnetID, VPCID, Description, InterfaceType, InstanceID string
	SecurityGroupIDs                                                    []string
	PublicIP, PrivateIP, AssociationID, AllocationID                    string
	RequesterManaged                                                    bool
}

// Route is one route of a route table. TargetKind is igw, nat, tgw, pcx,
// vpce, eni, or local.
type Route struct{ Destination, TargetKind, TargetID, State string }

// RouteAssoc associates a route table with a subnet or marks it as main.
type RouteAssoc struct {
	SubnetID string
	Main     bool
}

// RouteTable is a route table projection.
type RouteTable struct {
	ID, Region, VPCID string
	Routes            []Route
	Associations      []RouteAssoc
	TagCount          int
}

// InternetGateway is an internet gateway projection.
type InternetGateway struct {
	ID, Region string
	VPCIDs     []string
}

// NATGateway is a NAT gateway projection.
type NATGateway struct {
	ID, Region, SubnetID, VPCID, State string
	ENIIDs, AllocationIDs              []string
}

// NetworkACL is a network ACL projection. Entries are the inbound entries.
type NetworkACL struct {
	ID, Region, VPCID string
	Entries           []NACLEntry
	SubnetIDs         []string
}

// VPCEndpoint is a VPC endpoint projection.
type VPCEndpoint struct {
	ID, Region, VPCID, Type, ServiceName string
	SubnetIDs, SecurityGroupIDs, ENIIDs  []string
}

// PeeringConnection is a VPC peering connection projection.
type PeeringConnection struct{ ID, Region, Status, RequesterVPC, AccepterVPC string }

// ElasticIP is an Elastic IP projection.
type ElasticIP struct {
	AllocationID, Region, PublicIP, AssociationID, ENIID, InstanceID, NATGatewayID string
}

// TransitGateway is a transit gateway projection.
type TransitGateway struct{ ID, Region, ARN, State string }

// TGWAttachment is a transit gateway attachment projection.
type TGWAttachment struct{ ID, Region, TransitGatewayID, ResourceType, ResourceID, State string }

// LoadBalancer is an ELBv2 load balancer projection.
type LoadBalancer struct {
	ARN, Name, Region, Scheme, Type, VPCID string
	SubnetIDs, SecurityGroupIDs            []string
}

// TargetGroup is an ELBv2 target group projection.
type TargetGroup struct {
	ARN, Name, Region, VPCID, TargetType string
	LoadBalancerARNs                     []string
}

// Listener is an ELBv2 listener projection.
type Listener struct {
	ARN, LoadBalancerARN, Protocol string
	Port                           int
	TargetGroupARNs                []string
}

// TargetHealth is one registered target of a target group.
type TargetHealth struct{ TargetGroupARN, TargetID, State string }
