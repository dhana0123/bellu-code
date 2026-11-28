package gcp

import (
	"net/url"
	"slices"
	"strings"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/exposure"
)

// Rule is the part of a Compute firewall rule that decides exposure.
type Rule struct {
	ID           string // Entity_ID of the firewall
	Network      string // network self link
	Disabled     bool
	Ingress      bool
	Allow        bool
	Priority     int
	SourceRanges []string
	TargetTags   []string
	Protocols    []RuleProtocol
}

// RuleProtocol is one allowed or denied protocol with its ports.
type RuleProtocol struct {
	Protocol string
	Ports    []string
}

// Instance is the part of a Compute instance that decides exposure.
type Instance struct {
	ID         string
	Network    string
	Tags       []string
	ExternalIP bool // some network interface has an access config with an external address
	NetworkErr bool // network data for this instance could not be collected
}

// Analysis is the gcp implementation of exposure.Analyzer.
type Analysis struct {
	Instances []Instance
	Rules     []Rule
	// RulesFailed is true when firewalls could not be listed. Every instance is then unknown.
	RulesFailed bool
}

var _ exposure.Analyzer = Analysis{}

func (r Rule) applies(i Instance) bool {
	open := slices.Contains(r.SourceRanges, "0.0.0.0/0") || slices.Contains(r.SourceRanges, "::/0")
	if r.Disabled || !r.Ingress || !open || !sameNetwork(r.Network, i.Network) {
		return false
	}
	if len(r.TargetTags) == 0 {
		return true
	}
	return slices.ContainsFunc(r.TargetTags, func(t string) bool { return slices.Contains(i.Tags, t) })
}

func (r Rule) ranges() []exposure.PortRange {
	var out []exposure.PortRange
	for _, p := range r.Protocols {
		if pr, ok := exposure.ParsePorts(strings.ToLower(p.Protocol), p.Ports); ok {
			out = append(out, pr...)
		}
	}
	return out
}

func sameNetwork(a, b string) bool {
	if a == b {
		return true
	}
	ua, ea := url.Parse(a)
	ub, eb := url.Parse(b)
	return ea == nil && eb == nil && ua.Path != "" && ua.Path == ub.Path
}

// Analyze decides each instance. The implied VPC rule denies all ingress, so
// an instance without an external address, or without a matching open allow
// rule, is internal. A deny rule with an equal or lower priority number wins.
func (a Analysis) Analyze() (map[string]exposure.Exposure, []string) {
	res := map[string]exposure.Exposure{}
	var failed []string
	for _, i := range a.Instances {
		if a.RulesFailed || i.NetworkErr {
			failed = append(failed, i.ID)
			continue
		}
		var ports []exposure.PortRange
		var ev []string
		for _, r := range a.Rules {
			if !i.ExternalIP || !r.Allow || !r.applies(i) {
				continue
			}
			var denied []exposure.PortRange
			for _, d := range a.Rules {
				if !d.Allow && d.Priority <= r.Priority && d.applies(i) {
					denied = append(denied, d.ranges()...)
				}
			}
			if rp := exposure.Subtract(r.ranges(), denied); len(rp) > 0 {
				ports = append(ports, rp...)
				ev = append(ev, r.ID)
			}
		}
		if len(ports) == 0 {
			res[i.ID] = exposure.Exposure{Value: exposure.Internal}
			continue
		}
		res[i.ID] = exposure.Exposure{Value: exposure.Internet, Ports: exposure.Union(ports), Evidence: ev}
	}
	return res, failed
}
