package aws

import (
	"context"
	"sort"
	"strings"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/aws/awsschema"
)

// This file holds the steps that collect VPC networking: vpc, subnet, ENI,
// routing, gateways, endpoints, peering, and transit gateways. Every relation
// is queued and resolved after all steps, so a relation to an entity that was
// not collected is skipped.

func (r *run) vpc(ctx context.Context, rg string) error {
	l, err := r.c.client.VPCs(ctx, rg)
	r.truncate("vpc", rg, l.Truncated)
	r.vpcs[rg] = l.Items
	for _, v := range l.Items {
		r.add(r.vpcARN(rg, v.ID), "ec2", awsschema.TypeVPC, rg, map[string]any{
			"name": v.Name, "state": v.State, "tag_count": v.TagCount})
	}
	return err
}

func (r *run) subnet(ctx context.Context, rg string) error {
	l, err := r.c.client.Subnets(ctx, rg)
	r.truncate("subnet", rg, l.Truncated)
	r.subnets[rg] = l.Items
	for _, s := range l.Items {
		arn := r.subnetARN(rg, s.ID)
		r.add(arn, "ec2", awsschema.TypeSubnet, rg, map[string]any{
			"name": s.Name, "tag_count": s.TagCount, "availability_zone": s.AZ, "cidr": s.CIDR})
		r.b.rel("aws_in_vpc", arn, r.vpcARN(rg, s.VPCID), nil)
	}
	return err
}

func (r *run) securityGroups(ctx context.Context, rg string) error {
	l, err := r.c.client.SecurityGroups(ctx, rg)
	r.truncate("security-groups", rg, l.Truncated)
	r.sgs[rg] = map[string]SecurityGroup{}
	for _, g := range l.Items {
		r.sgs[rg][g.ID] = g
		arn := r.sgARN(rg, g.ID)
		r.add(arn, "ec2", awsschema.TypeSecurityGroup, rg, map[string]any{"name": g.Name, "tag_count": g.TagCount})
		r.b.rel("aws_in_vpc", arn, r.vpcARN(rg, g.VPCID), nil)
	}
	return err
}

func (r *run) eni(ctx context.Context, rg string) error {
	l, err := r.c.client.ENIs(ctx, rg)
	r.truncate("eni", rg, l.Truncated)
	r.enis[rg] = map[string]ENI{}
	for _, e := range l.Items {
		r.enis[rg][e.ID] = e
		arn := r.eniARN(rg, e.ID)
		r.add(arn, "ec2", awsschema.TypeENI, rg, map[string]any{"interface_type": e.InterfaceType})
		r.b.rel("aws_in_subnet", arn, r.subnetARN(rg, e.SubnetID), nil)
		for _, g := range e.SecurityGroupIDs {
			r.b.rel("aws_member_of_sg", arn, r.sgARN(rg, g), nil)
		}
	}
	return err
}

func (r *run) routeTable(ctx context.Context, rg string) error {
	l, err := r.c.client.RouteTables(ctx, rg)
	r.truncate("route-table", rg, l.Truncated)
	r.routeTbls[rg] = l.Items
	for _, t := range l.Items {
		arn := r.ec2ARN(rg, "route-table/"+t.ID)
		r.add(arn, "ec2", awsschema.TypeRouteTable, rg, map[string]any{"tag_count": t.TagCount})
		r.b.rel("aws_in_vpc", arn, r.vpcARN(rg, t.VPCID), nil)
		for _, a := range t.Associations {
			if a.SubnetID != "" {
				r.b.rel("aws_associated_subnet", arn, r.subnetARN(rg, a.SubnetID), nil)
			}
		}
		dests := map[string][]string{} // target arn -> destinations
		for _, rt := range t.Routes {
			rarn := arn + "/route/" + rt.Destination
			r.add(rarn, "ec2", awsschema.TypeRoute, rg, map[string]any{"state": rt.State, "destination": rt.Destination})
			r.b.rel("aws_route_of", rarn, arn, nil)
			if target := r.routeTargetARN(rg, rt); target != "" {
				dests[target] = append(dests[target], rt.Destination)
			}
		}
		targets := make([]string, 0, len(dests))
		for k := range dests {
			targets = append(targets, k)
		}
		sort.Strings(targets)
		for _, target := range targets {
			ds := dests[target]
			sort.Strings(ds)
			r.b.rel("aws_routes_to", arn, target, map[string]any{"evidence": cut512("destinations: " + strings.Join(ds, ", "))})
		}
	}
	return err
}

// routeTargetARN returns the ARN of the entity a route points to, or "" for a
// local route or a target kind the collector does not model.
func (r *run) routeTargetARN(rg string, rt Route) string {
	switch rt.TargetKind {
	case "igw":
		return r.igwARN(rg, rt.TargetID)
	case "nat":
		return r.ec2ARN(rg, "natgateway/"+rt.TargetID)
	case "tgw":
		return r.ec2ARN(rg, "transit-gateway/"+rt.TargetID)
	case "pcx":
		return r.ec2ARN(rg, "vpc-peering-connection/"+rt.TargetID)
	case "vpce":
		return r.ec2ARN(rg, "vpc-endpoint/"+rt.TargetID)
	case "eni":
		return r.eniARN(rg, rt.TargetID)
	}
	return ""
}

func (r *run) igw(ctx context.Context, rg string) error {
	l, err := r.c.client.InternetGateways(ctx, rg)
	r.truncate("igw", rg, l.Truncated)
	r.igws[rg] = l.Items
	for _, g := range l.Items {
		arn := r.igwARN(rg, g.ID)
		r.add(arn, "ec2", awsschema.TypeInternetGateway, rg, nil)
		for _, v := range g.VPCIDs {
			r.b.rel("aws_attached_igw", arn, r.vpcARN(rg, v), nil)
		}
	}
	return err
}

func (r *run) nat(ctx context.Context, rg string) error {
	l, err := r.c.client.NATGateways(ctx, rg)
	r.truncate("nat", rg, l.Truncated)
	r.nats[rg] = l.Items
	for _, n := range l.Items {
		arn := r.ec2ARN(rg, "natgateway/"+n.ID)
		r.add(arn, "ec2", awsschema.TypeNATGateway, rg, map[string]any{"state": n.State})
		r.b.rel("aws_nat_in_subnet", arn, r.subnetARN(rg, n.SubnetID), nil)
		for _, e := range n.ENIIDs {
			r.b.rel("aws_has_eni", arn, r.eniARN(rg, e), nil)
		}
	}
	return err
}

func (r *run) nacl(ctx context.Context, rg string) error {
	l, err := r.c.client.NetworkACLs(ctx, rg)
	r.truncate("nacl", rg, l.Truncated)
	r.nacls[rg] = l.Items
	for _, a := range l.Items {
		arn := r.ec2ARN(rg, "network-acl/"+a.ID)
		r.add(arn, "ec2", awsschema.TypeNetworkACL, rg, nil)
		r.b.rel("aws_in_vpc", arn, r.vpcARN(rg, a.VPCID), nil)
		for _, s := range a.SubnetIDs {
			r.b.rel("aws_associated_subnet", arn, r.subnetARN(rg, s), nil)
		}
	}
	return err
}

func (r *run) eip(ctx context.Context, rg string) error {
	l, err := r.c.client.ElasticIPs(ctx, rg)
	r.truncate("eip", rg, l.Truncated)
	r.eips[rg] = l.Items
	for _, e := range l.Items {
		id := e.AllocationID
		if id == "" {
			id = e.PublicIP
		}
		arn := r.ec2ARN(rg, "elastic-ip/"+id)
		r.add(arn, "ec2", awsschema.TypeEIP, rg, nil)
		if e.ENIID != "" {
			r.b.rel("aws_assigned_to", arn, r.eniARN(rg, e.ENIID), nil)
		}
		if e.InstanceID != "" {
			r.b.rel("aws_assigned_to", arn, r.instARN(rg, e.InstanceID), nil)
		}
		for _, n := range r.nats[rg] {
			for _, al := range n.AllocationIDs {
				if al != "" && al == e.AllocationID {
					r.b.rel("aws_assigned_to", arn, r.ec2ARN(rg, "natgateway/"+n.ID), nil)
				}
			}
		}
	}
	return err
}

func (r *run) vpcEndpoint(ctx context.Context, rg string) error {
	l, err := r.c.client.VPCEndpoints(ctx, rg)
	r.truncate("vpc-endpoint", rg, l.Truncated)
	for _, e := range l.Items {
		arn := r.ec2ARN(rg, "vpc-endpoint/"+e.ID)
		r.add(arn, "ec2", awsschema.TypeVPCEndpoint, rg, map[string]any{"endpoint_type": e.Type, "service_name": e.ServiceName})
		r.b.rel("aws_in_vpc", arn, r.vpcARN(rg, e.VPCID), nil)
		for _, n := range e.ENIIDs {
			r.b.rel("aws_has_eni", arn, r.eniARN(rg, n), nil)
		}
	}
	return err
}

func (r *run) peering(ctx context.Context, rg string) error {
	l, err := r.c.client.PeeringConnections(ctx, rg)
	r.truncate("peering", rg, l.Truncated)
	for _, p := range l.Items {
		arn := r.ec2ARN(rg, "vpc-peering-connection/"+p.ID)
		r.add(arn, "ec2", awsschema.TypeVPCPeering, rg, map[string]any{"state": p.Status})
		if p.Status == "active" {
			a, b := r.vpcARN(rg, p.RequesterVPC), r.vpcARN(rg, p.AccepterVPC)
			r.b.rel("aws_peers_with", a, b, nil)
			r.b.rel("aws_peers_with", b, a, nil)
		}
	}
	return err
}

func (r *run) tgw(ctx context.Context, rg string) error {
	l, err := r.c.client.TransitGateways(ctx, rg)
	r.truncate("tgw", rg, l.Truncated)
	for _, g := range l.Items {
		r.add(r.ec2ARN(rg, "transit-gateway/"+g.ID), "ec2", awsschema.TypeTransitGateway, rg, map[string]any{"state": g.State})
	}
	return err
}

func (r *run) tgwAttachment(ctx context.Context, rg string) error {
	l, err := r.c.client.TGWAttachments(ctx, rg)
	r.truncate("tgw-attachment", rg, l.Truncated)
	for _, a := range l.Items {
		arn := r.ec2ARN(rg, "transit-gateway-attachment/"+a.ID)
		r.add(arn, "ec2", awsschema.TypeTGWAttachment, rg, map[string]any{"state": a.State, "attached_type": a.ResourceType})
		r.b.rel("aws_tgw_attached", arn, r.ec2ARN(rg, "transit-gateway/"+a.TransitGatewayID), nil)
		if a.ResourceType == "vpc" {
			r.b.rel("aws_tgw_attached", arn, r.vpcARN(rg, a.ResourceID), nil)
		}
	}
	return err
}

// cut512 cuts s to at most 512 bytes at a UTF-8 character boundary.
func cut512(s string) string {
	if len(s) <= 512 {
		return s
	}
	n := 512
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}
