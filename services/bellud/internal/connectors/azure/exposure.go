package azure

import (
	"strings"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/exposure"
)

// NSGRule is one network security group rule.
type NSGRule struct {
	ID       string // Entity_ID of the NSG
	Inbound  bool
	Allow    bool
	Priority int
	Source   string // "*", "Internet", "0.0.0.0/0", or other
	Protocol string // "Tcp", "Udp", "*"
	Ports    []string
}

// NIC is a network interface with its attached NSG rules (subnet and NIC level merged by the caller).
type NIC struct {
	ID         string // Entity_ID of the resource using the interface
	PublicIP   bool
	Rules      []NSGRule
	NetworkErr bool
}

// Analysis is the azure implementation of exposure.Analyzer.
type Analysis struct{ NICs []NIC }

var _ exposure.Analyzer = Analysis{}

func internetSource(s string) bool {
	switch strings.ToLower(s) {
	case "*", "internet", "any", "0.0.0.0/0", "::/0":
		return true
	}
	return false
}

func ranges(r NSGRule) []exposure.PortRange {
	protos := []string{strings.ToLower(r.Protocol)}
	if r.Protocol == "*" {
		protos = []string{"tcp", "udp"}
	}
	specs := r.Ports
	if len(specs) == 1 && specs[0] == "*" {
		specs = nil
	}
	var out []exposure.PortRange
	for _, p := range protos {
		if pr, ok := exposure.ParsePorts(p, specs); ok {
			out = append(out, pr...)
		}
	}
	return out
}

// Analyze decides each interface. Rules are evaluated by priority, lowest
// number first; a port is open when the first matching rule allows it.
func (a Analysis) Analyze() (map[string]exposure.Exposure, []string) {
	res := map[string]exposure.Exposure{}
	var failed []string
	for _, n := range a.NICs {
		if n.NetworkErr {
			failed = append(failed, n.ID)
			continue
		}
		if !n.PublicIP {
			res[n.ID] = exposure.Exposure{Value: exposure.Internal}
			continue
		}
		rules := append([]NSGRule(nil), n.Rules...)
		for i := 1; i < len(rules); i++ {
			for j := i; j > 0 && rules[j].Priority < rules[j-1].Priority; j-- {
				rules[j], rules[j-1] = rules[j-1], rules[j]
			}
		}
		var open, decided []exposure.PortRange
		var ev []string
		for _, r := range rules {
			if !r.Inbound || !internetSource(r.Source) {
				continue
			}
			rp := exposure.Subtract(ranges(r), decided)
			if len(rp) == 0 {
				continue
			}
			if r.Allow {
				open = append(open, rp...)
				ev = append(ev, r.ID)
			}
			decided = append(decided, rp...)
		}
		if len(open) == 0 {
			res[n.ID] = exposure.Exposure{Value: exposure.Internal}
			continue
		}
		res[n.ID] = exposure.Exposure{Value: exposure.Internet, Ports: exposure.Union(open), Evidence: ev}
	}
	return res, failed
}
