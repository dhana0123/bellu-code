package aws

import (
	"sort"
	"strings"
)

// This file derives ExposureInput for each instance and load balancer from
// the collected facts, sets internet_exposed, and emits aws_exposed_via.

// exposureView is the facts of one network attachment (an ENI, or a subnet of
// a load balancer).
type exposureView struct {
	publicIP string
	groups   []string
	subnetID string
	vpcID    string
}

func (r *run) exposure() {
	for _, rg := range r.c.regions {
		for _, i := range r.instances[rg] {
			r.exposeEntity(rg, r.instARN(rg, i.ID), r.instanceViews(rg, i), false, No, "")
		}
		for _, lb := range r.lbs[rg] {
			addr, fact := No, ""
			if lb.Scheme == "internet-facing" {
				addr, fact = Yes, "lb-scheme:internet-facing"
			}
			var views []exposureView
			for _, s := range lb.SubnetIDs {
				views = append(views, exposureView{groups: lb.SecurityGroupIDs, subnetID: s, vpcID: lb.VPCID})
			}
			r.exposeEntity(rg, lb.ARN, views, true, addr, fact)
		}
	}
}

// instanceViews returns one view per ENI, or the instance itself when the
// ENIs are not known.
func (r *run) instanceViews(rg string, i Instance) []exposureView {
	var views []exposureView
	for _, id := range i.ENIIDs {
		e, ok := r.enis[rg][id]
		if !ok {
			continue
		}
		v := exposureView{publicIP: e.PublicIP, groups: e.SecurityGroupIDs, subnetID: e.SubnetID, vpcID: e.VPCID}
		if v.publicIP == "" && len(i.ENIIDs) == 1 {
			v.publicIP = i.PublicIP
		}
		views = append(views, v)
	}
	if len(views) == 0 {
		views = []exposureView{{publicIP: i.PublicIP, groups: i.SecurityGroupIDs, subnetID: i.SubnetID, vpcID: i.VPCID}}
	}
	return views
}

// exposeEntity evaluates every view, keeps the best state, and writes it.
// For a load balancer the scheme decides the address fact (lbAddr, lbFact);
// for an instance it comes from each view.
func (r *run) exposeEntity(rg, arn string, views []exposureView, isLB bool, lbAddr Tri, lbFact string) {
	attrs := r.b.attrs[arn]
	if attrs == nil {
		return
	}
	best, bestIGW := Exposure{State: stateFalse, Confidence: confExtr}, ""
	for _, v := range views {
		in, igw := r.exposureInput(rg, v)
		if isLB {
			in.Address, in.AddressFact = lbAddr, lbFact
		}
		ex := Evaluate(in)
		if rank(ex.State) > rank(best.State) {
			best, bestIGW = ex, igw
		}
	}
	attrs["internet_exposed"] = best.State
	if best.State == stateFalse || bestIGW == "" {
		return
	}
	r.b.rel("aws_exposed_via", arn, bestIGW, map[string]any{
		"evidence":   cut512(strings.Join(best.Evidence, "; ")),
		"confidence": best.Confidence,
	})
}

func rank(s string) int {
	switch s {
	case stateTrue:
		return 2
	case statePartial:
		return 1
	}
	return 0
}

// exposureInput builds the input of one view and returns the ARN of the
// internet gateway that the route names (or the only gateway of the VPC when
// the route is unknown).
func (r *run) exposureInput(rg string, v exposureView) (ExposureInput, string) {
	var in ExposureInput
	failed := func(step string) bool {
		if r.failedAt[step+"@"+rg] {
			in.FailedCalls = append(in.FailedCalls, step)
			return true
		}
		return false
	}

	// a: public address.
	switch {
	case v.publicIP != "":
		in.Address, in.AddressFact = Yes, "public-ip:"+v.publicIP
	case failed("eni") || failed("ec2"):
		in.Address = Unknown
	default:
		in.Address = No
	}

	// b: an attached group has an ingress rule open to the internet.
	for _, g := range v.groups {
		for _, x := range r.sgRules[rg][g] {
			if x.Direction == "ingress" && internetOpen(x.CIDR) {
				in.OpenRules = append(in.OpenRules, OpenRule{ID: RuleID(x), Protocol: x.Protocol, From: x.From, To: x.To, AllPorts: !x.HasPorts})
			}
		}
	}
	sort.Slice(in.OpenRules, func(i, j int) bool { return in.OpenRules[i].ID < in.OpenRules[j].ID })
	switch {
	case len(in.OpenRules) > 0:
		in.Ingress = Yes
	case failed("sg-rules"):
		in.Ingress = Unknown
	default:
		in.Ingress = No
	}

	// c: the subnet's route table routes the internet to a gateway.
	igw := ""
	tbl, derived := r.routeTableFor(rg, v.subnetID, v.vpcID)
	switch {
	case tbl == nil && failed("route-table"):
		in.Route = Unknown
	case tbl == nil:
		in.Route = Unknown
	default:
		in.Route, in.RouteDerived = No, derived
		for _, rt := range tbl.Routes {
			if rt.TargetKind == "igw" && (rt.Destination == "0.0.0.0/0" || rt.Destination == "::/0") && rt.State != "blackhole" {
				in.Route = Yes
				in.RouteFact = tbl.ID + " " + rt.Destination + " -> " + rt.TargetID
				igw = r.igwARN(rg, rt.TargetID)
				break
			}
		}
	}
	if igw == "" && in.Route == Unknown {
		igw = r.onlyIGW(rg, v.vpcID)
	}

	// d: the subnet's network ACL.
	if acl := r.naclFor(rg, v.subnetID); acl != nil {
		in.NACLKnown, in.NACLID, in.NACLEntries = true, acl.ID, acl.Entries
	} else {
		failed("nacl")
		in.NACL = Unknown
	}
	return in, igw
}

// routeTableFor returns the table associated with the subnet, else the main
// table of the VPC with derived set.
func (r *run) routeTableFor(rg, subnet, vpc string) (*RouteTable, bool) {
	tbls := r.routeTbls[rg]
	for i := range tbls {
		for _, a := range tbls[i].Associations {
			if subnet != "" && a.SubnetID == subnet {
				return &tbls[i], false
			}
		}
	}
	for i := range tbls {
		if tbls[i].VPCID != vpc {
			continue
		}
		for _, a := range tbls[i].Associations {
			if a.Main {
				return &tbls[i], true
			}
		}
	}
	return nil, false
}

func (r *run) naclFor(rg, subnet string) *NetworkACL {
	acls := r.nacls[rg]
	for i := range acls {
		for _, s := range acls[i].SubnetIDs {
			if subnet != "" && s == subnet {
				return &acls[i]
			}
		}
	}
	return nil
}

func (r *run) onlyIGW(rg, vpc string) string {
	found := ""
	for _, g := range r.igws[rg] {
		for _, v := range g.VPCIDs {
			if v == vpc {
				if found != "" {
					return ""
				}
				found = r.igwARN(rg, g.ID)
			}
		}
	}
	return found
}
