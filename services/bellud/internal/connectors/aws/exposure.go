package aws

import (
	"fmt"
	"slices"
	"sort"
)

// Tri is a three-valued fact: known false, known true, or not known because
// the API call that supplies it failed or was denied.
type Tri uint8

const (
	No Tri = iota
	Yes
	Unknown
)

// OpenRule is an ingress rule whose source is 0.0.0.0/0 or ::/0.
type OpenRule struct {
	ID, Protocol string
	From, To     int
	AllPorts     bool
}

// NACLEntry is one inbound network ACL entry.
type NACLEntry struct {
	Number   int
	Allow    bool
	Protocol string // "-1" or a protocol name or number
	CIDR     string
	From, To int
	AllPorts bool
}

// ExposureInput holds the facts that decide internet exposure. The collector
// turns every failed call into Unknown before it calls Evaluate.
type ExposureInput struct {
	Address      Tri    // a: public IP, Elastic IP association, or internet-facing load balancer
	AddressFact  string // evidence text for a
	Ingress      Tri    // b: an attached group has an open ingress rule
	OpenRules    []OpenRule
	Route        Tri    // c: the subnet's route table has a route to an internet gateway
	RouteFact    string // evidence text for c
	RouteDerived bool   // the main route table was assumed for an unassociated subnet
	NACL         Tri    // d, used when NACLKnown is false
	NACLID       string
	NACLEntries  []NACLEntry
	NACLKnown    bool // when true, d comes from NACLEntries and OpenRules
	FailedCalls  []string
}

// Exposure is the result of Evaluate.
type Exposure struct {
	State      string   // "true", "partial", or "false"
	Confidence string   // "extracted" or "inferred"
	Evidence   []string // sorted and unique
	Reason     string   // "", "route-unknown", "nacl-denies", "nacl-unknown", "call-failed"
}

const (
	stateTrue    = "true"
	statePartial = "partial"
	stateFalse   = "false"
	confExtr     = "extracted"
	confInf      = "inferred"
)

// Evaluate applies the truth table of the design, top to bottom.
func Evaluate(in ExposureInput) Exposure {
	d, aclFact := naclResult(in)
	ev := evidenceOf(in, aclFact)
	switch {
	case in.Address == No || in.Ingress == No:
		return Exposure{State: stateFalse, Confidence: confExtr, Evidence: ev}
	case in.Address == Unknown || in.Ingress == Unknown:
		return Exposure{State: statePartial, Confidence: confInf, Evidence: ev, Reason: "call-failed"}
	case in.Route == No:
		return Exposure{State: stateFalse, Confidence: routeConf(in), Evidence: ev}
	case in.Route == Unknown:
		reason := "route-unknown"
		if len(in.FailedCalls) > 0 {
			reason = "call-failed"
		}
		return Exposure{State: statePartial, Confidence: confInf, Evidence: ev, Reason: reason}
	case d == Unknown:
		return Exposure{State: statePartial, Confidence: confInf, Evidence: ev, Reason: "nacl-unknown"}
	case d == No:
		return Exposure{State: statePartial, Confidence: confExtr, Evidence: ev, Reason: "nacl-denies"}
	}
	return Exposure{State: stateTrue, Confidence: routeConf(in), Evidence: ev}
}

func routeConf(in ExposureInput) string {
	if in.RouteDerived {
		return confInf
	}
	return confExtr
}

// naclResult returns d and the evidence string of the deciding ACL entry.
func naclResult(in ExposureInput) (Tri, string) {
	if !in.NACLKnown {
		return in.NACL, ""
	}
	rules := in.OpenRules
	if len(rules) == 0 {
		rules = []OpenRule{{Protocol: "-1", AllPorts: true}}
	}
	best, bestFact, sawUnknown := No, "", false
	var denyFact string
	for _, r := range rules {
		res, e, found := naclDecide(in.NACLEntries, r)
		switch res {
		case Yes:
			if best != Yes {
				best, bestFact = Yes, fmt.Sprintf("acl:%s#%d allow", in.NACLID, e.Number)
			}
		case Unknown:
			sawUnknown = true
		default:
			if found && denyFact == "" {
				denyFact = fmt.Sprintf("acl:%s#%d deny", in.NACLID, e.Number)
			}
		}
	}
	switch {
	case best == Yes:
		return Yes, bestFact
	case sawUnknown:
		return Unknown, ""
	}
	return No, denyFact
}

func evidenceOf(in ExposureInput, aclFact string) []string {
	var ev []string
	if in.AddressFact != "" {
		ev = append(ev, in.AddressFact)
	}
	for _, r := range in.OpenRules {
		ev = append(ev, "sg-rule:"+r.ID)
	}
	if in.RouteFact != "" {
		ev = append(ev, in.RouteFact)
	}
	if aclFact != "" {
		ev = append(ev, aclFact)
	}
	sort.Strings(ev)
	return slices.Compact(ev)
}

// NACLAllows evaluates the entries for one open ingress rule. The lowest
// numbered entry that names the whole internet and covers the rule's protocol
// and port range decides. An entry that overlaps the range without covering it
// makes the result Unknown. No match is the implicit final deny.
func NACLAllows(entries []NACLEntry, r OpenRule) Tri {
	t, _, _ := naclDecide(entries, r)
	return t
}

func naclDecide(entries []NACLEntry, r OpenRule) (Tri, NACLEntry, bool) {
	sorted := slices.Clone(entries)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Number < sorted[j].Number })
	rf, rt := portRange(r.AllPorts, r.From, r.To, r.Protocol)
	for _, e := range sorted {
		if e.CIDR != "0.0.0.0/0" && e.CIDR != "::/0" {
			continue
		}
		covers, overlaps := protoMatch(e.Protocol, r.Protocol)
		if !overlaps {
			continue
		}
		if covers {
			ef, et := portRange(e.AllPorts, e.From, e.To, e.Protocol)
			switch {
			case ef <= rf && rt <= et:
				return allowTri(e.Allow), e, true
			case ef <= rt && rf <= et:
				return Unknown, e, true
			}
			continue
		}
		return Unknown, e, true // the entry names only part of the rule's protocols
	}
	return No, NACLEntry{}, false
}

func allowTri(a bool) Tri {
	if a {
		return Yes
	}
	return No
}

// portRange returns the inclusive range. Protocols without ports (anything but
// tcp, udp, and all) and AllPorts cover 0..65535.
func portRange(all bool, from, to int, proto string) (int, int) {
	if all || proto == "-1" || (proto != "tcp" && proto != "udp" && proto != "6" && proto != "17") {
		return 0, 65535
	}
	return from, to
}

// protoMatch reports whether the entry protocol covers the rule protocol and
// whether the two overlap at all.
func protoMatch(entry, rule string) (covers, overlaps bool) {
	switch {
	case entry == "-1":
		return true, true
	case rule == "-1":
		return false, true
	}
	e, r := canonProto(entry), canonProto(rule)
	return e == r, e == r
}

func canonProto(p string) string {
	switch p {
	case "6":
		return "tcp"
	case "17":
		return "udp"
	case "1":
		return "icmp"
	case "58":
		return "icmpv6"
	}
	return p
}
