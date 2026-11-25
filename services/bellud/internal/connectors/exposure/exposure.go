// Package exposure holds the result type shared by the per-cloud exposure
// analysers. Each analyser is a pure function over already collected facts.
package exposure

import (
	"encoding/json"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Values of the `exposure` attribute.
const (
	Internet = "internet"
	Internal = "internal"
	Unknown  = "unknown"
)

// PortRange is a protocol and an inclusive port range within 1..65535.
type PortRange struct {
	Protocol string `json:"protocol"`
	From     int    `json:"from"`
	To       int    `json:"to"`
}

// Exposure is the result written to a resource.
type Exposure struct {
	Value    string      // internet, internal, unknown
	Ports    []PortRange // ports reachable from the internet
	Evidence []string    // Entity_IDs of rules, routes, gateways; at least one for internet
}

// Analyzer is implemented by each cloud's exposure analysis.
type Analyzer interface {
	// Analyze returns the exposure of every resource it can decide, keyed by
	// Entity_ID. Resources in failed could not be decided.
	Analyze() (results map[string]Exposure, failed []string)
}

// Attrs returns the `exposure`, `exposed_ports` and `exposure_evidence`
// attributes. Ports and evidence are JSON lists.
func (e Exposure) Attrs() map[string]any {
	ports := slices.Clone(e.Ports)
	sort.Slice(ports, func(i, j int) bool {
		a, b := ports[i], ports[j]
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		return a.From < b.From
	})
	if ports == nil {
		ports = []PortRange{}
	}
	ev := slices.Clone(e.Evidence)
	sort.Strings(ev)
	ev = slices.Compact(ev)
	if ev == nil {
		ev = []string{}
	}
	p, _ := json.Marshal(ports)
	v, _ := json.Marshal(ev)
	return map[string]any{"exposure": e.Value, "exposed_ports": string(p), "exposure_evidence": string(v)}
}

// Valid reports whether an internet result carries evidence and ports lie in 1..65535.
func (e Exposure) Valid() bool {
	if e.Value == Internet && len(e.Evidence) == 0 {
		return false
	}
	for _, p := range e.Ports {
		if p.From < 1 || p.To > 65535 || p.From > p.To {
			return false
		}
	}
	return e.Value == Internet || e.Value == Internal || e.Value == Unknown
}

// Apply merges a run into the previous values. Failed resources become
// unknown. Resources that are neither decided nor failed keep their last good value.
func Apply(prev map[string]Exposure, results map[string]Exposure, failed []string) map[string]Exposure {
	out := make(map[string]Exposure, len(prev)+len(results))
	for k, v := range prev {
		out[k] = v
	}
	for k, v := range results {
		out[k] = v
	}
	for _, k := range failed {
		out[k] = Exposure{Value: Unknown}
	}
	return out
}

// Union merges overlapping port ranges per protocol.
func Union(in []PortRange) []PortRange {
	s := slices.Clone(in)
	sort.Slice(s, func(i, j int) bool {
		if s[i].Protocol != s[j].Protocol {
			return s[i].Protocol < s[j].Protocol
		}
		return s[i].From < s[j].From
	})
	var out []PortRange
	for _, r := range s {
		if n := len(out); n > 0 && out[n-1].Protocol == r.Protocol && r.From <= out[n-1].To+1 {
			out[n-1].To = max(out[n-1].To, r.To)
			continue
		}
		out = append(out, r)
	}
	return out
}

// Subtract removes the denied ranges from ranges, per protocol.
func Subtract(ranges, denied []PortRange) []PortRange {
	out := Union(ranges)
	for _, d := range Union(denied) {
		var next []PortRange
		for _, r := range out {
			if r.Protocol != d.Protocol || d.To < r.From || d.From > r.To {
				next = append(next, r)
				continue
			}
			if d.From > r.From {
				next = append(next, PortRange{r.Protocol, r.From, d.From - 1})
			}
			if d.To < r.To {
				next = append(next, PortRange{r.Protocol, d.To + 1, r.To})
			}
		}
		out = next
	}
	return out
}

// ParsePorts converts cloud port specs ("80", "1000-2000"; none means all)
// into ranges for one protocol. ok is false when a spec is malformed.
func ParsePorts(proto string, specs []string) ([]PortRange, bool) {
	if len(specs) == 0 {
		return []PortRange{{proto, 1, 65535}}, true
	}
	var out []PortRange
	for _, s := range specs {
		from, to, err := parseSpec(s)
		if err != nil || from < 0 || to > 65535 || from > to {
			return nil, false
		}
		out = append(out, PortRange{proto, max(from, 1), to})
	}
	return out, true
}

func parseSpec(s string) (int, int, error) {
	lo, hi, found := strings.Cut(s, "-")
	from, err := strconv.Atoi(lo)
	if err != nil || !found {
		return from, from, err
	}
	to, err := strconv.Atoi(hi)
	return from, to, err
}
