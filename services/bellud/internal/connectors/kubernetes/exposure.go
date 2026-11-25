package kubernetes

import (
	"strconv"
	"strings"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/exposure"
)

// SvcPort is one Service port. TargetPort is the pod port that a NetworkPolicy sees.
type SvcPort struct {
	Port, NodePort, TargetPort int
	Protocol                   string // TCP, UDP; empty means TCP
}

// Service is the part of a Service that decides exposure.
type Service struct {
	ID        string // Entity_ID
	Name      string
	Namespace string
	Type      string // ClusterIP, NodePort, LoadBalancer
	Selector  map[string]string
	Ports     []SvcPort
}

// Ingress routes HTTP and HTTPS to Services in its namespace.
type Ingress struct {
	ID        string
	Namespace string
	Backends  []string // names of backend Services
	TLS       bool
}

// PolicyPort is one port in a NetworkPolicy ingress rule; Port 0 means every port.
type PolicyPort struct {
	Port     int
	Protocol string
}

// PolicyRule is one ingress rule. Internet is true when the rule has no `from`
// (every source) or has an ipBlock covering 0.0.0.0/0. Rules whose sources
// are only pods or namespaces do not admit the internet.
type PolicyRule struct {
	Internet bool
	Ports    []PolicyPort // empty means every port
}

// NetPol is a NetworkPolicy that selects pods by labels.
type NetPol struct {
	ID        string
	Namespace string
	Selector  map[string]string // empty selects every pod in the namespace
	Ingress   bool              // policyTypes includes Ingress
	Rules     []PolicyRule
}

// Analysis is the kubernetes implementation of exposure.Analyzer.
type Analysis struct {
	Services  []Service
	Ingresses []Ingress
	Policies  []NetPol
	// NodesPublic is true when nodes have public addresses, which makes NodePort reachable.
	NodesPublic bool
	// Failed lists namespaces whose network objects could not be collected.
	// Services in them are unknown. FailedAll marks every namespace.
	Failed    map[string]bool
	FailedAll bool
}

var _ exposure.Analyzer = Analysis{}

func subset(sel, labels map[string]string) bool {
	for k, v := range sel {
		if labels[k] != v {
			return false
		}
	}
	return true
}

func proto(p string) string {
	if p == "" {
		return "tcp"
	}
	return strings.ToLower(p)
}

// Analyze decides each Service. Ports reachable from the internet come from
// LoadBalancer ports, NodePorts (when nodes are public) and Ingress 80/443.
// An ingress NetworkPolicy that selects the Service's pods removes every
// port that no internet-admitting rule allows.
func (a Analysis) Analyze() (map[string]exposure.Exposure, []string) {
	res := map[string]exposure.Exposure{}
	var failed []string
	for _, s := range a.Services {
		if a.FailedAll || a.Failed[s.Namespace] {
			failed = append(failed, s.ID)
			continue
		}
		var open []exposure.PortRange
		ev := []string{}
		target := map[string]int{} // external range key -> pod port
		add := func(pr exposure.PortRange, tp int, id string) {
			open = append(open, pr)
			target[pr.Protocol+":"+strconv.Itoa(pr.From)] = tp
			ev = append(ev, id)
		}
		for _, p := range s.Ports {
			tp := p.TargetPort
			if tp == 0 {
				tp = p.Port
			}
			switch {
			case s.Type == "LoadBalancer" && p.Port > 0:
				add(exposure.PortRange{Protocol: proto(p.Protocol), From: p.Port, To: p.Port}, tp, s.ID)
			case (s.Type == "NodePort" || s.Type == "LoadBalancer") && a.NodesPublic && p.NodePort > 0:
				add(exposure.PortRange{Protocol: proto(p.Protocol), From: p.NodePort, To: p.NodePort}, tp, s.ID)
			}
		}
		for _, in := range a.Ingresses {
			if in.Namespace != s.Namespace || !contains(in.Backends, s.Name) {
				continue
			}
			for _, port := range []int{80, 443} {
				if port == 80 && in.TLS {
					continue
				}
				add(exposure.PortRange{Protocol: "tcp", From: port, To: port}, firstTarget(s), in.ID)
			}
		}
		// NetworkPolicy: remove external ports whose pod port is not admitted.
		var policies []NetPol
		for _, np := range a.Policies {
			if np.Ingress && np.Namespace == s.Namespace && subset(np.Selector, s.Selector) {
				policies = append(policies, np)
				ev = append(ev, np.ID)
			}
		}
		var kept []exposure.PortRange
		for _, pr := range open {
			if len(policies) == 0 || admitted(policies, target[pr.Protocol+":"+strconv.Itoa(pr.From)], pr.Protocol) {
				kept = append(kept, pr)
			}
		}
		if len(kept) == 0 {
			res[s.ID] = exposure.Exposure{Value: exposure.Internal}
			continue
		}
		res[s.ID] = exposure.Exposure{Value: exposure.Internet, Ports: exposure.Union(kept), Evidence: ev}
	}
	return res, failed
}

func firstTarget(s Service) int {
	if len(s.Ports) == 0 {
		return 0
	}
	if s.Ports[0].TargetPort != 0 {
		return s.Ports[0].TargetPort
	}
	return s.Ports[0].Port
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

// admitted reports whether any policy rule admits the internet on the pod port.
// Policies are additive: a pod is open on a port when any selecting policy allows it.
func admitted(policies []NetPol, port int, protocol string) bool {
	for _, np := range policies {
		for _, r := range np.Rules {
			if !r.Internet {
				continue
			}
			if len(r.Ports) == 0 {
				return true
			}
			for _, p := range r.Ports {
				if (p.Port == 0 || p.Port == port) && proto(p.Protocol) == protocol {
					return true
				}
			}
		}
	}
	return false
}
