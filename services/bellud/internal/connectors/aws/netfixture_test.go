package aws

import (
	"context"
	"fmt"
)

// netClient is a fixture Client for one account with a small VPC network:
// one VPC, subnet, ENI, instance, security group with rules, route table to
// an internet gateway, network ACL, and an internet-facing load balancer. Every
// call can fail through fail (keyed by step name).
type netClient struct {
	fail      map[string]error
	instances []Instance
	sgRules   []SGRule
	groups    []SecurityGroup
	peerings  []PeeringConnection
	truncate  map[string]bool // step -> listing reports Truncated
	calls     []string
}

func newNetClient() *netClient {
	return &netClient{
		fail:     map[string]error{},
		truncate: map[string]bool{},
		instances: []Instance{{
			ID: "i-1", Region: "eu-west-1", VPCID: "vpc-1", SubnetID: "subnet-1", State: "running",
			SecurityGroupIDs: []string{"sg-1"}, ENIIDs: []string{"eni-1"}, PublicIP: "203.0.113.10",
		}},
		groups: []SecurityGroup{
			{ID: "sg-1", Region: "eu-west-1", VPCID: "vpc-1", Name: "web"},
			{ID: "sg-2", Region: "eu-west-1", VPCID: "vpc-1", Name: "admin"},
		},
		sgRules: []SGRule{
			{ID: "sgr-1", GroupID: "sg-1", Direction: "ingress", Protocol: "tcp", From: 443, To: 443, HasPorts: true, CIDR: "0.0.0.0/0"},
			{ID: "sgr-2", GroupID: "sg-1", Direction: "ingress", Protocol: "tcp", From: 22, To: 22, HasPorts: true, PeerGroupID: "sg-2"},
			{ID: "sgr-3", GroupID: "sg-1", Direction: "egress", Protocol: "-1", CIDR: "0.0.0.0/0"},
		},
	}
}

func (n *netClient) err(step, region string) error {
	n.calls = append(n.calls, step+":"+region)
	return n.fail[step]
}

func list[T any](n *netClient, step, region string, items ...T) (Listing[T], error) {
	if err := n.err(step, region); err != nil {
		return Listing[T]{}, err
	}
	return Listing[T]{Items: items, Truncated: n.truncate[step]}, nil
}

func (n *netClient) Identity(context.Context) (Identity, error) {
	if err := n.fail["identity"]; err != nil {
		return Identity{}, err
	}
	return Identity{Account: "123456789012"}, nil
}
func (n *netClient) SimulateWrites(context.Context, string, []string) ([]AllowedAction, error) {
	return nil, nil
}
func (n *netClient) Regions(context.Context) ([]string, error) { return []string{"eu-west-1"}, nil }
func (n *netClient) Instances(_ context.Context, r string) (Listing[Instance], error) {
	return list(n, "ec2", r, n.instances...)
}
func (n *netClient) Buckets(context.Context) ([]Bucket, error) { return nil, n.err("s3", "") }
func (n *netClient) SecurityGroups(_ context.Context, r string) (Listing[SecurityGroup], error) {
	return list(n, "security-groups", r, n.groups...)
}
func (n *netClient) VPCs(_ context.Context, r string) (Listing[VPC], error) {
	return list(n, "vpc", r, VPC{ID: "vpc-1", Region: r}, VPC{ID: "vpc-2", Region: r})
}
func (n *netClient) Roles(context.Context) ([]Role, error) { return nil, n.err("iam", "") }
func (n *netClient) Functions(_ context.Context, r string) ([]Function, error) {
	return nil, n.err("lambda", r)
}
func (n *netClient) DBInstances(_ context.Context, r string) ([]DBInstance, error) {
	return nil, n.err("rds", r)
}
func (n *netClient) Subnets(_ context.Context, r string) (Listing[Subnet], error) {
	return list(n, "subnet", r, Subnet{ID: "subnet-1", Region: r, VPCID: "vpc-1", CIDR: "10.0.1.0/24"})
}
func (n *netClient) ENIs(_ context.Context, r string) (Listing[ENI], error) {
	return list(n, "eni", r,
		ENI{ID: "eni-1", Region: r, SubnetID: "subnet-1", VPCID: "vpc-1", InstanceID: "i-1",
			SecurityGroupIDs: []string{"sg-1"}, PublicIP: "203.0.113.10"},
		ENI{ID: "eni-lb", Region: r, SubnetID: "subnet-1", VPCID: "vpc-1", Description: "ELB app/web/abc"})
}
func (n *netClient) RouteTables(_ context.Context, r string) (Listing[RouteTable], error) {
	return list(n, "route-table", r, RouteTable{
		ID: "rtb-1", Region: r, VPCID: "vpc-1",
		Routes: []Route{
			{Destination: "10.0.0.0/16", TargetKind: "local", TargetID: "local", State: "active"},
			{Destination: "0.0.0.0/0", TargetKind: "igw", TargetID: "igw-1", State: "active"},
		},
		Associations: []RouteAssoc{{SubnetID: "subnet-1"}, {Main: true}},
	})
}
func (n *netClient) InternetGateways(_ context.Context, r string) (Listing[InternetGateway], error) {
	return list(n, "igw", r, InternetGateway{ID: "igw-1", Region: r, VPCIDs: []string{"vpc-1"}})
}
func (n *netClient) NATGateways(_ context.Context, r string) (Listing[NATGateway], error) {
	return list[NATGateway](n, "nat", r)
}
func (n *netClient) SGRules(_ context.Context, r string) (Listing[SGRule], error) {
	return list(n, "sg-rules", r, n.sgRules...)
}
func (n *netClient) NetworkACLs(_ context.Context, r string) (Listing[NetworkACL], error) {
	return list(n, "nacl", r, NetworkACL{ID: "acl-1", Region: r, VPCID: "vpc-1", SubnetIDs: []string{"subnet-1"},
		Entries: []NACLEntry{{Number: 100, Allow: true, Protocol: "-1", CIDR: "0.0.0.0/0", AllPorts: true}}})
}
func (n *netClient) VPCEndpoints(_ context.Context, r string) (Listing[VPCEndpoint], error) {
	return list[VPCEndpoint](n, "vpc-endpoint", r)
}
func (n *netClient) PeeringConnections(_ context.Context, r string) (Listing[PeeringConnection], error) {
	return list(n, "peering", r, n.peerings...)
}
func (n *netClient) ElasticIPs(_ context.Context, r string) (Listing[ElasticIP], error) {
	return list(n, "eip", r, ElasticIP{AllocationID: "eipalloc-1", Region: r, PublicIP: "203.0.113.10", ENIID: "eni-1", InstanceID: "i-1"})
}
func (n *netClient) TransitGateways(_ context.Context, r string) (Listing[TransitGateway], error) {
	return list[TransitGateway](n, "tgw", r)
}
func (n *netClient) TGWAttachments(_ context.Context, r string) (Listing[TGWAttachment], error) {
	return list[TGWAttachment](n, "tgw-attachment", r)
}

const (
	fixtureLB = "arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/app/web/abc"
	fixtureTG = "arn:aws:elasticloadbalancing:eu-west-1:123456789012:targetgroup/web/def"
	fixtureLi = "arn:aws:elasticloadbalancing:eu-west-1:123456789012:listener/app/web/abc/ghi"
)

func (n *netClient) LoadBalancers(_ context.Context, r string) (Listing[LoadBalancer], error) {
	return list(n, "lb", r, LoadBalancer{ARN: fixtureLB, Name: "web", Region: r, Scheme: "internet-facing",
		Type: "application", VPCID: "vpc-1", SubnetIDs: []string{"subnet-1"}, SecurityGroupIDs: []string{"sg-1"}})
}
func (n *netClient) TargetGroups(_ context.Context, r string) (Listing[TargetGroup], error) {
	return list(n, "target-group", r, TargetGroup{ARN: fixtureTG, Name: "web", Region: r, VPCID: "vpc-1", TargetType: "instance"})
}
func (n *netClient) Listeners(_ context.Context, r, lb string) ([]Listener, error) {
	if err := n.err("listener", r); err != nil {
		return nil, err
	}
	return []Listener{{ARN: fixtureLi, LoadBalancerARN: lb, Protocol: "HTTPS", Port: 443, TargetGroupARNs: []string{fixtureTG}}}, nil
}
func (n *netClient) TargetHealth(_ context.Context, r, tg string) ([]TargetHealth, error) {
	if err := n.err("target-health", r); err != nil {
		return nil, err
	}
	return []TargetHealth{{TargetGroupARN: tg, TargetID: "i-1", State: "healthy"}}, nil
}

// arnOf builds the collector's ARN for an ec2 resource of the fixture.
func arnOf(res string) string { return fmt.Sprintf("arn:aws:ec2:eu-west-1:123456789012:%s", res) }
