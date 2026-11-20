package aws

import (
	"context"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
)

// This file holds the network and load balancer calls of the SDK adapter.
// Every call goes through listAll or mapErr, so the typed errors keep their
// meaning and each listing is capped.

func i32(p *int32) int { return int(awssdk.ToInt32(p)) }

func (c *client) Subnets(ctx context.Context, region string) (Listing[Subnet], error) {
	p := ec2.NewDescribeSubnetsPaginator(c.ec2At(region), &ec2.DescribeSubnetsInput{})
	return listAll(ctx, p.HasMorePages, func(ctx context.Context) ([]Subnet, error) {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		var out []Subnet
		for _, s := range page.Subnets {
			out = append(out, Subnet{
				ID: awssdk.ToString(s.SubnetId), Region: region, VPCID: awssdk.ToString(s.VpcId),
				AZ: awssdk.ToString(s.AvailabilityZone), CIDR: awssdk.ToString(s.CidrBlock),
				Name: ec2Name(s.Tags), TagCount: len(s.Tags),
			})
		}
		return out, nil
	})
}

func (c *client) ENIs(ctx context.Context, region string) (Listing[ENI], error) {
	p := ec2.NewDescribeNetworkInterfacesPaginator(c.ec2At(region), &ec2.DescribeNetworkInterfacesInput{})
	return listAll(ctx, p.HasMorePages, func(ctx context.Context) ([]ENI, error) {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		var out []ENI
		for _, n := range page.NetworkInterfaces {
			e := ENI{
				ID: awssdk.ToString(n.NetworkInterfaceId), Region: region, SubnetID: awssdk.ToString(n.SubnetId),
				VPCID: awssdk.ToString(n.VpcId), Description: awssdk.ToString(n.Description),
				InterfaceType: string(n.InterfaceType), RequesterManaged: awssdk.ToBool(n.RequesterManaged),
				PrivateIP: awssdk.ToString(n.PrivateIpAddress),
			}
			if n.Attachment != nil {
				e.InstanceID = awssdk.ToString(n.Attachment.InstanceId)
			}
			if n.Association != nil {
				e.PublicIP = awssdk.ToString(n.Association.PublicIp)
				e.AssociationID = awssdk.ToString(n.Association.AssociationId)
				e.AllocationID = awssdk.ToString(n.Association.AllocationId)
			}
			for _, g := range n.Groups {
				e.SecurityGroupIDs = append(e.SecurityGroupIDs, awssdk.ToString(g.GroupId))
			}
			out = append(out, e)
		}
		return out, nil
	})
}

// routeTarget picks the one target a route names.
func routeTarget(r ec2types.Route) (kind, id string) {
	switch {
	case r.NatGatewayId != nil:
		return "nat", *r.NatGatewayId
	case r.TransitGatewayId != nil:
		return "tgw", *r.TransitGatewayId
	case r.VpcPeeringConnectionId != nil:
		return "pcx", *r.VpcPeeringConnectionId
	case r.NetworkInterfaceId != nil:
		return "eni", *r.NetworkInterfaceId
	case r.GatewayId != nil:
		g := *r.GatewayId
		switch {
		case g == "local":
			return "local", g
		case strings.HasPrefix(g, "igw-"):
			return "igw", g
		case strings.HasPrefix(g, "vpce-"):
			return "vpce", g
		}
		return "", g
	}
	return "", ""
}

func (c *client) RouteTables(ctx context.Context, region string) (Listing[RouteTable], error) {
	p := ec2.NewDescribeRouteTablesPaginator(c.ec2At(region), &ec2.DescribeRouteTablesInput{})
	return listAll(ctx, p.HasMorePages, func(ctx context.Context) ([]RouteTable, error) {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		var out []RouteTable
		for _, t := range page.RouteTables {
			rt := RouteTable{ID: awssdk.ToString(t.RouteTableId), Region: region, VPCID: awssdk.ToString(t.VpcId), TagCount: len(t.Tags)}
			for _, r := range t.Routes {
				dest := awssdk.ToString(r.DestinationCidrBlock)
				if dest == "" {
					dest = awssdk.ToString(r.DestinationIpv6CidrBlock)
				}
				if dest == "" {
					dest = awssdk.ToString(r.DestinationPrefixListId)
				}
				k, id := routeTarget(r)
				rt.Routes = append(rt.Routes, Route{Destination: dest, TargetKind: k, TargetID: id, State: string(r.State)})
			}
			for _, a := range t.Associations {
				rt.Associations = append(rt.Associations, RouteAssoc{SubnetID: awssdk.ToString(a.SubnetId), Main: awssdk.ToBool(a.Main)})
			}
			out = append(out, rt)
		}
		return out, nil
	})
}

func (c *client) InternetGateways(ctx context.Context, region string) (Listing[InternetGateway], error) {
	p := ec2.NewDescribeInternetGatewaysPaginator(c.ec2At(region), &ec2.DescribeInternetGatewaysInput{})
	return listAll(ctx, p.HasMorePages, func(ctx context.Context) ([]InternetGateway, error) {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		var out []InternetGateway
		for _, g := range page.InternetGateways {
			ig := InternetGateway{ID: awssdk.ToString(g.InternetGatewayId), Region: region}
			for _, a := range g.Attachments {
				ig.VPCIDs = append(ig.VPCIDs, awssdk.ToString(a.VpcId))
			}
			out = append(out, ig)
		}
		return out, nil
	})
}

func (c *client) NATGateways(ctx context.Context, region string) (Listing[NATGateway], error) {
	p := ec2.NewDescribeNatGatewaysPaginator(c.ec2At(region), &ec2.DescribeNatGatewaysInput{})
	return listAll(ctx, p.HasMorePages, func(ctx context.Context) ([]NATGateway, error) {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		var out []NATGateway
		for _, n := range page.NatGateways {
			g := NATGateway{
				ID: awssdk.ToString(n.NatGatewayId), Region: region, SubnetID: awssdk.ToString(n.SubnetId),
				VPCID: awssdk.ToString(n.VpcId), State: string(n.State),
			}
			for _, a := range n.NatGatewayAddresses {
				if v := awssdk.ToString(a.NetworkInterfaceId); v != "" {
					g.ENIIDs = append(g.ENIIDs, v)
				}
				if v := awssdk.ToString(a.AllocationId); v != "" {
					g.AllocationIDs = append(g.AllocationIDs, v)
				}
			}
			out = append(out, g)
		}
		return out, nil
	})
}

func (c *client) SGRules(ctx context.Context, region string) (Listing[SGRule], error) {
	p := ec2.NewDescribeSecurityGroupRulesPaginator(c.ec2At(region), &ec2.DescribeSecurityGroupRulesInput{})
	return listAll(ctx, p.HasMorePages, func(ctx context.Context) ([]SGRule, error) {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		var out []SGRule
		for _, r := range page.SecurityGroupRules {
			rule := SGRule{
				ID: awssdk.ToString(r.SecurityGroupRuleId), GroupID: awssdk.ToString(r.GroupId),
				Direction: "ingress", Protocol: awssdk.ToString(r.IpProtocol),
				CIDR: awssdk.ToString(r.CidrIpv4), PrefixListID: awssdk.ToString(r.PrefixListId),
				Description: awssdk.ToString(r.Description),
			}
			if awssdk.ToBool(r.IsEgress) {
				rule.Direction = "egress"
			}
			if rule.CIDR == "" {
				rule.CIDR = awssdk.ToString(r.CidrIpv6)
			}
			if r.ReferencedGroupInfo != nil {
				rule.PeerGroupID = awssdk.ToString(r.ReferencedGroupInfo.GroupId)
			}
			if rule.Protocol == "tcp" || rule.Protocol == "udp" {
				rule.HasPorts, rule.From, rule.To = true, i32(r.FromPort), i32(r.ToPort)
			}
			out = append(out, rule)
		}
		return out, nil
	})
}

func (c *client) NetworkACLs(ctx context.Context, region string) (Listing[NetworkACL], error) {
	p := ec2.NewDescribeNetworkAclsPaginator(c.ec2At(region), &ec2.DescribeNetworkAclsInput{})
	return listAll(ctx, p.HasMorePages, func(ctx context.Context) ([]NetworkACL, error) {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		var out []NetworkACL
		for _, a := range page.NetworkAcls {
			acl := NetworkACL{ID: awssdk.ToString(a.NetworkAclId), Region: region, VPCID: awssdk.ToString(a.VpcId)}
			for _, e := range a.Entries {
				if awssdk.ToBool(e.Egress) {
					continue
				}
				ne := NACLEntry{
					Number: i32(e.RuleNumber), Allow: e.RuleAction == ec2types.RuleActionAllow,
					Protocol: awssdk.ToString(e.Protocol), CIDR: awssdk.ToString(e.CidrBlock), AllPorts: e.PortRange == nil,
				}
				if ne.CIDR == "" {
					ne.CIDR = awssdk.ToString(e.Ipv6CidrBlock)
				}
				if e.PortRange != nil {
					ne.From, ne.To = i32(e.PortRange.From), i32(e.PortRange.To)
				}
				acl.Entries = append(acl.Entries, ne)
			}
			for _, as := range a.Associations {
				acl.SubnetIDs = append(acl.SubnetIDs, awssdk.ToString(as.SubnetId))
			}
			out = append(out, acl)
		}
		return out, nil
	})
}

func (c *client) VPCEndpoints(ctx context.Context, region string) (Listing[VPCEndpoint], error) {
	p := ec2.NewDescribeVpcEndpointsPaginator(c.ec2At(region), &ec2.DescribeVpcEndpointsInput{})
	return listAll(ctx, p.HasMorePages, func(ctx context.Context) ([]VPCEndpoint, error) {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		var out []VPCEndpoint
		for _, v := range page.VpcEndpoints {
			e := VPCEndpoint{
				ID: awssdk.ToString(v.VpcEndpointId), Region: region, VPCID: awssdk.ToString(v.VpcId),
				Type: string(v.VpcEndpointType), ServiceName: awssdk.ToString(v.ServiceName),
				SubnetIDs: v.SubnetIds, ENIIDs: v.NetworkInterfaceIds,
			}
			for _, g := range v.Groups {
				e.SecurityGroupIDs = append(e.SecurityGroupIDs, awssdk.ToString(g.GroupId))
			}
			out = append(out, e)
		}
		return out, nil
	})
}

func (c *client) PeeringConnections(ctx context.Context, region string) (Listing[PeeringConnection], error) {
	p := ec2.NewDescribeVpcPeeringConnectionsPaginator(c.ec2At(region), &ec2.DescribeVpcPeeringConnectionsInput{})
	return listAll(ctx, p.HasMorePages, func(ctx context.Context) ([]PeeringConnection, error) {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		var out []PeeringConnection
		for _, v := range page.VpcPeeringConnections {
			pc := PeeringConnection{ID: awssdk.ToString(v.VpcPeeringConnectionId), Region: region}
			if v.Status != nil {
				pc.Status = string(v.Status.Code)
			}
			if v.RequesterVpcInfo != nil {
				pc.RequesterVPC = awssdk.ToString(v.RequesterVpcInfo.VpcId)
			}
			if v.AccepterVpcInfo != nil {
				pc.AccepterVPC = awssdk.ToString(v.AccepterVpcInfo.VpcId)
			}
			out = append(out, pc)
		}
		return out, nil
	})
}

// ElasticIPs reads one page: DescribeAddresses has no paginator.
func (c *client) ElasticIPs(ctx context.Context, region string) (Listing[ElasticIP], error) {
	out, err := c.ec2At(region).DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
	if err != nil {
		return Listing[ElasticIP]{}, mapErr(err)
	}
	var res Listing[ElasticIP]
	for _, a := range out.Addresses {
		res.Items = append(res.Items, ElasticIP{
			AllocationID: awssdk.ToString(a.AllocationId), Region: region, PublicIP: awssdk.ToString(a.PublicIp),
			AssociationID: awssdk.ToString(a.AssociationId), ENIID: awssdk.ToString(a.NetworkInterfaceId),
			InstanceID: awssdk.ToString(a.InstanceId),
		})
	}
	if len(res.Items) > maxItems {
		res.Items, res.Truncated = res.Items[:maxItems], true
	}
	return res, nil
}

func (c *client) TransitGateways(ctx context.Context, region string) (Listing[TransitGateway], error) {
	p := ec2.NewDescribeTransitGatewaysPaginator(c.ec2At(region), &ec2.DescribeTransitGatewaysInput{})
	return listAll(ctx, p.HasMorePages, func(ctx context.Context) ([]TransitGateway, error) {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		var out []TransitGateway
		for _, g := range page.TransitGateways {
			out = append(out, TransitGateway{
				ID: awssdk.ToString(g.TransitGatewayId), Region: region,
				ARN: awssdk.ToString(g.TransitGatewayArn), State: string(g.State),
			})
		}
		return out, nil
	})
}

func (c *client) TGWAttachments(ctx context.Context, region string) (Listing[TGWAttachment], error) {
	p := ec2.NewDescribeTransitGatewayAttachmentsPaginator(c.ec2At(region), &ec2.DescribeTransitGatewayAttachmentsInput{})
	return listAll(ctx, p.HasMorePages, func(ctx context.Context) ([]TGWAttachment, error) {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		var out []TGWAttachment
		for _, a := range page.TransitGatewayAttachments {
			out = append(out, TGWAttachment{
				ID: awssdk.ToString(a.TransitGatewayAttachmentId), Region: region,
				TransitGatewayID: awssdk.ToString(a.TransitGatewayId), ResourceType: string(a.ResourceType),
				ResourceID: awssdk.ToString(a.ResourceId), State: string(a.State),
			})
		}
		return out, nil
	})
}

func (c *client) LoadBalancers(ctx context.Context, region string) (Listing[LoadBalancer], error) {
	p := elasticloadbalancingv2.NewDescribeLoadBalancersPaginator(c.elbv2At(region), &elasticloadbalancingv2.DescribeLoadBalancersInput{})
	return listAll(ctx, p.HasMorePages, func(ctx context.Context) ([]LoadBalancer, error) {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		var out []LoadBalancer
		for _, l := range page.LoadBalancers {
			lb := LoadBalancer{
				ARN: awssdk.ToString(l.LoadBalancerArn), Name: awssdk.ToString(l.LoadBalancerName), Region: region,
				Scheme: string(l.Scheme), Type: string(l.Type), VPCID: awssdk.ToString(l.VpcId),
				SecurityGroupIDs: l.SecurityGroups,
			}
			for _, az := range l.AvailabilityZones {
				lb.SubnetIDs = append(lb.SubnetIDs, awssdk.ToString(az.SubnetId))
			}
			out = append(out, lb)
		}
		return out, nil
	})
}

func (c *client) TargetGroups(ctx context.Context, region string) (Listing[TargetGroup], error) {
	p := elasticloadbalancingv2.NewDescribeTargetGroupsPaginator(c.elbv2At(region), &elasticloadbalancingv2.DescribeTargetGroupsInput{})
	return listAll(ctx, p.HasMorePages, func(ctx context.Context) ([]TargetGroup, error) {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		var out []TargetGroup
		for _, g := range page.TargetGroups {
			out = append(out, TargetGroup{
				ARN: awssdk.ToString(g.TargetGroupArn), Name: awssdk.ToString(g.TargetGroupName), Region: region,
				VPCID: awssdk.ToString(g.VpcId), TargetType: string(g.TargetType), LoadBalancerARNs: g.LoadBalancerArns,
			})
		}
		return out, nil
	})
}

// Listeners reads the listeners of one load balancer, at most maxPages pages.
func (c *client) Listeners(ctx context.Context, region, lbARN string) ([]Listener, error) {
	p := elasticloadbalancingv2.NewDescribeListenersPaginator(c.elbv2At(region),
		&elasticloadbalancingv2.DescribeListenersInput{LoadBalancerArn: awssdk.String(lbARN)})
	l, err := listAll(ctx, p.HasMorePages, func(ctx context.Context) ([]Listener, error) {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		var out []Listener
		for _, l := range page.Listeners {
			li := Listener{
				ARN: awssdk.ToString(l.ListenerArn), LoadBalancerARN: awssdk.ToString(l.LoadBalancerArn),
				Protocol: string(l.Protocol), Port: i32(l.Port),
			}
			for _, a := range l.DefaultActions {
				if a.TargetGroupArn != nil {
					li.TargetGroupARNs = append(li.TargetGroupARNs, *a.TargetGroupArn)
				}
				if a.ForwardConfig != nil {
					for _, t := range a.ForwardConfig.TargetGroups {
						if v := awssdk.ToString(t.TargetGroupArn); v != "" && !contains(li.TargetGroupARNs, v) {
							li.TargetGroupARNs = append(li.TargetGroupARNs, v)
						}
					}
				}
			}
			out = append(out, li)
		}
		return out, nil
	})
	return l.Items, err
}

func (c *client) TargetHealth(ctx context.Context, region, tgARN string) ([]TargetHealth, error) {
	out, err := c.elbv2At(region).DescribeTargetHealth(ctx,
		&elasticloadbalancingv2.DescribeTargetHealthInput{TargetGroupArn: awssdk.String(tgARN)})
	if err != nil {
		return nil, mapErr(err)
	}
	var res []TargetHealth
	for _, d := range out.TargetHealthDescriptions {
		th := TargetHealth{TargetGroupARN: tgARN}
		if d.Target != nil {
			th.TargetID = awssdk.ToString(d.Target.Id)
		}
		if d.TargetHealth != nil {
			th.State = string(d.TargetHealth.State)
		}
		res = append(res, th)
	}
	return res, nil
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
