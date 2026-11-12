// Package resolve computes Endpoint_Resolution: the join of an endpoint
// entity to the live listening ports and processes that serve it. It is pure
// over a graph state and writes nothing.
package resolve

import (
	"sort"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/graph"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/query"
)

// Entity and relation vocabulary used by the join.
const (
	KindEndpoint = "endpoint"
	KindProcess  = "process"
	KindHost     = "host"
	RelDependsOn = "depends_on"
	RelOwnedBy   = "owned_by"
	// RelResolvesTo is the type of the derived edges.
	RelResolvesTo = "resolves_to"
)

// Reader is the read-only part of the Projection used here. *graph.Graph
// implements it.
type Reader interface {
	Entity(id graph.EntityID) (*graph.EntityState, bool)
	LiveIDsOfKind(kind string) []graph.EntityID
	RelationsFrom(id graph.EntityID) []graph.RelKey
	RelationsTo(id graph.EntityID) []graph.RelKey
	PortEntities(protocol, port string) []graph.EntityID
}

// Resolution is one listening port an endpoint resolves to and the processes
// that port is owned_by.
type Resolution struct {
	Port      graph.EntityID
	Processes []graph.EntityID
}

func live(g Reader, id graph.EntityID, kind string) (*graph.EntityState, bool) {
	e, ok := g.Entity(id)
	if !ok || !e.Live || e.Kind != kind {
		return nil, false
	}
	return e, true
}

func isWildcard(addr string) bool {
	switch addr {
	case "0.0.0.0", "::", "[::]", "*", "":
		return true
	}
	return false
}

// matches applies the matching rule of endpoint address a to listening port l.
func matches(g Reader, a string, l *graph.EntityState) bool {
	la := l.Identity["address"]
	if la == a {
		return true
	}
	if !isWildcard(la) {
		return false
	}
	host := l.Identity["host"]
	switch a {
	case host, "localhost", "127.0.0.1", "::1":
		return true
	}
	hid, err := ident.Hash(KindHost, map[string]string{"hostname": host})
	if err != nil {
		return false
	}
	h, ok := live(g, hid, KindHost)
	if !ok {
		return false
	}
	for _, s := range h.Attrs["addresses"].L {
		if s == a {
			return true
		}
	}
	return false
}

// processesOf returns the live processes that port is owned_by, sorted.
func processesOf(g Reader, port graph.EntityID) []graph.EntityID {
	var out []graph.EntityID
	for _, r := range g.RelationsFrom(port) {
		if r.Type != RelOwnedBy {
			continue
		}
		if _, ok := live(g, r.To, KindProcess); ok {
			out = append(out, r.To)
		}
	}
	sort.Strings(out)
	return out
}

// portsOf returns the live listening ports owned_by process, sorted.
func portsOf(g Reader, process graph.EntityID) []graph.EntityID {
	var out []graph.EntityID
	for _, r := range g.RelationsTo(process) {
		if r.Type != RelOwnedBy {
			continue
		}
		if _, ok := live(g, r.From, graph.KindListeningPort); ok {
			out = append(out, r.From)
		}
	}
	sort.Strings(out)
	return out
}

// Endpoint resolves a live endpoint entity. The result is sorted by port ID;
// it is nil for an unknown, removed or non-endpoint entity.
func Endpoint(g Reader, endpoint graph.EntityID) []Resolution {
	e, ok := live(g, endpoint, KindEndpoint)
	if !ok {
		return nil
	}
	var out []Resolution
	for _, pid := range g.PortEntities(e.Identity["protocol"], e.Identity["port"]) {
		l, ok := live(g, pid, graph.KindListeningPort)
		if !ok || !matches(g, e.Identity["address"], l) {
			continue
		}
		out = append(out, Resolution{Port: pid, Processes: processesOf(g, pid)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

// endpointsOfPort returns the live endpoints that resolve to port, sorted.
func endpointsOfPort(g Reader, port graph.EntityID) []graph.EntityID {
	l, ok := live(g, port, graph.KindListeningPort)
	if !ok {
		return nil
	}
	var out []graph.EntityID
	for _, id := range g.LiveIDsOfKind(KindEndpoint) {
		e, ok := live(g, id, KindEndpoint)
		if !ok || e.Identity["protocol"] != l.Identity["protocol"] || e.Identity["port"] != l.Identity["port"] {
			continue
		}
		if matches(g, e.Identity["address"], l) {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// endpointsOf returns the endpoints resolving to a listening port or, for a
// process, to any of its ports.
func endpointsOf(g Reader, x graph.EntityID) []graph.EntityID {
	e, ok := g.Entity(x)
	if !ok || !e.Live {
		return nil
	}
	switch e.Kind {
	case graph.KindListeningPort:
		return endpointsOfPort(g, x)
	case KindProcess:
		set := map[graph.EntityID]struct{}{}
		for _, p := range portsOf(g, x) {
			for _, ep := range endpointsOfPort(g, p) {
				set[ep] = struct{}{}
			}
		}
		out := make([]graph.EntityID, 0, len(set))
		for ep := range set {
			out = append(out, ep)
		}
		sort.Strings(out)
		return out
	}
	return nil
}

// Dependents returns, sorted, the entities whose depends_on endpoints resolve
// to the listening port or process. It is the exact inverse of Endpoint.
func Dependents(g Reader, portOrProcess graph.EntityID) []graph.EntityID {
	set := map[graph.EntityID]struct{}{}
	for _, ep := range endpointsOf(g, portOrProcess) {
		for _, r := range g.RelationsTo(ep) {
			if r.Type == RelDependsOn {
				set[r.From] = struct{}{}
			}
		}
	}
	out := make([]graph.EntityID, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// DerivedFn returns a query.DerivedFn over g producing the derived
// resolves_to(endpoint -> port|process) edges incident to the entity it is
// given: outgoing ones for an endpoint, incoming ones for a port or process.
// The returned function reads g on every call and must not outlive the read
// lock protecting g.
func DerivedFn(g Reader) query.DerivedFn {
	return func(id graph.EntityID) []query.Edge {
		e, ok := g.Entity(id)
		if !ok || !e.Live {
			return nil
		}
		var out []query.Edge
		add := func(from, to graph.EntityID) {
			out = append(out, query.Edge{Type: RelResolvesTo, From: from, To: to, Derived: true})
		}
		switch e.Kind {
		case KindEndpoint:
			for _, r := range Endpoint(g, id) {
				add(id, r.Port)
				for _, p := range r.Processes {
					add(id, p)
				}
			}
		case graph.KindListeningPort, KindProcess:
			for _, ep := range endpointsOf(g, id) {
				add(ep, id)
			}
		}
		return out
	}
}
