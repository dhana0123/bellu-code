package resolve

import (
	"fmt"
	"reflect"
	"sort"
	"testing"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/codec"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/graph"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
)

type mport struct {
	id                      string
	host, proto, addr, port string
	live                    bool
}

func sortedKeys(m map[string]bool) []string {
	o := []string{}
	for k := range m {
		o = append(o, k)
	}
	sort.Strings(o)
	return o
}

// Feature: bellu-graph-native, Property 18: Endpoint resolution matches the rule and writes nothing
//
// Validates: Requirements 12.2, 12.3, 12.4, 12.5
func TestPropEndpointResolution(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		g := graph.New()
		seq := uint64(0)
		fold := func(ev codec.Event) {
			seq++
			ev.Seq = seq
			ev.Collector = "c"
			g.Fold(ev)
		}
		hash := func(kind string, id map[string]string) string {
			h, err := ident.Hash(kind, id)
			if err != nil {
				t.Fatal(err)
			}
			return h
		}
		hostNames := []string{"h0", "h1"}
		ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
		listenAddrs := []string{"10.0.0.1", "10.0.0.2", "0.0.0.0", "::", "[::]", "*"}
		epAddrs := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "0.0.0.0", "::", "h0", "h1", "localhost", "127.0.0.1", "::1"}
		protos := []string{"tcp", "udp"}
		portNums := []string{"80", "81"}

		// Hosts: model records live state and addresses.
		hostLive := map[string]bool{}
		hostAddrs := map[string][]string{}
		for _, h := range hostNames {
			if !rapid.Bool().Draw(t, "hostExists-"+h) {
				continue
			}
			addrs := rapid.SliceOfNDistinct(rapid.SampledFrom(ips), 0, 3, func(s string) string { return s }).Draw(t, "addrs-"+h)
			fold(codec.Event{Type: codec.EntityCreated, Kind: "host", Identity: map[string]string{"hostname": h},
				Attrs: map[string]codec.Value{"addresses": {T: codec.TagList, L: addrs}}})
			hostLive[h] = true
			hostAddrs[h] = addrs
			if rapid.Bool().Draw(t, "hostRemoved-"+h) {
				fold(codec.Event{Type: codec.EntityRemoved, ID: hash("host", map[string]string{"hostname": h})})
				hostLive[h] = false
			}
		}

		// Processes.
		procLive := map[string]bool{}
		var procs []string
		for i := 0; i < rapid.IntRange(0, 3).Draw(t, "nProcs"); i++ {
			id := map[string]string{"host": "h0", "pid": fmt.Sprint(i + 1), "start_time": "0"}
			p := hash("process", id)
			fold(codec.Event{Type: codec.EntityCreated, Kind: "process", Identity: id})
			procLive[p] = true
			if rapid.Bool().Draw(t, "procRemoved") {
				fold(codec.Event{Type: codec.EntityRemoved, ID: p})
				procLive[p] = false
			}
			procs = append(procs, p)
		}

		// Listening ports and owned_by.
		var ports []*mport
		owned := map[string]map[string]bool{} // port -> processes (all, live or not)
		for i := 0; i < rapid.IntRange(0, 6).Draw(t, "nPorts"); i++ {
			mp := &mport{
				host:  rapid.SampledFrom(hostNames).Draw(t, "lhost"),
				proto: rapid.SampledFrom(protos).Draw(t, "lproto"),
				addr:  rapid.SampledFrom(listenAddrs).Draw(t, "laddr"),
				port:  rapid.SampledFrom(portNums).Draw(t, "lport"),
				live:  true,
			}
			id := map[string]string{"host": mp.host, "protocol": mp.proto, "address": mp.addr, "port": mp.port}
			mp.id = hash("listening_port", id)
			// Identities must be distinct: a repeated draw would reset the
			// model's ownership and liveness for an entity the graph keeps.
			if owned[mp.id] != nil {
				continue
			}
			fold(codec.Event{Type: codec.EntityCreated, Kind: "listening_port", Identity: id})
			if rapid.Bool().Draw(t, "portRemoved") {
				fold(codec.Event{Type: codec.EntityRemoved, ID: mp.id})
				mp.live = false
			}
			ports = append(ports, mp)
			owned[mp.id] = map[string]bool{}
			for _, p := range procs {
				if rapid.Bool().Draw(t, "owned") {
					fold(codec.Event{Type: codec.RelationAdded, RelType: "owned_by", From: mp.id, To: p})
					owned[mp.id][p] = true
				}
			}
		}

		// Endpoints and depends_on sources.
		type mep struct {
			id, proto, addr, port string
			live                  bool
		}
		var eps []*mep
		seenEp := map[string]bool{}
		for i := 0; i < rapid.IntRange(1, 5).Draw(t, "nEps"); i++ {
			e := &mep{
				proto: rapid.SampledFrom(protos).Draw(t, "eproto"),
				addr:  rapid.SampledFrom(epAddrs).Draw(t, "eaddr"),
				port:  rapid.SampledFrom(portNums).Draw(t, "eport"),
				live:  true,
			}
			id := map[string]string{"protocol": e.proto, "address": e.addr, "port": e.port}
			e.id = hash("endpoint", id)
			if seenEp[e.id] {
				continue
			}
			seenEp[e.id] = true
			fold(codec.Event{Type: codec.EntityCreated, Kind: "endpoint", Identity: id})
			if rapid.Bool().Draw(t, "epRemoved") {
				fold(codec.Event{Type: codec.EntityRemoved, ID: e.id})
				e.live = false
			}
			eps = append(eps, e)
		}
		deps := map[string]map[string]bool{} // endpoint -> dependents
		for i := 0; i < rapid.IntRange(0, 4).Draw(t, "nSrc"); i++ {
			src := hash("container", map[string]string{"id": fmt.Sprint("c", i)})
			fold(codec.Event{Type: codec.EntityCreated, Kind: "container", Identity: map[string]string{"id": fmt.Sprint("c", i)}})
			for _, e := range eps {
				if rapid.Bool().Draw(t, "dep") {
					fold(codec.Event{Type: codec.RelationAdded, RelType: "depends_on", From: src, To: e.id})
					if deps[e.id] == nil {
						deps[e.id] = map[string]bool{}
					}
					deps[e.id][src] = true
				}
			}
		}

		// Naive matching rule from Requirement 12.2.
		wildcard := func(a string) bool {
			for _, w := range []string{"0.0.0.0", "::", "[::]", "*"} {
				if a == w {
					return true
				}
			}
			return false
		}
		hostMatches := func(host, addr string) bool {
			if addr == host || addr == "localhost" || addr == "127.0.0.1" || addr == "::1" {
				return true
			}
			if !hostLive[host] {
				return false
			}
			for _, a := range hostAddrs[host] {
				if a == addr {
					return true
				}
			}
			return false
		}
		modelPorts := func(e *mep) map[string]bool {
			out := map[string]bool{}
			if !e.live {
				return out
			}
			for _, p := range ports {
				if !p.live || p.proto != e.proto || p.port != e.port {
					continue
				}
				if p.addr == e.addr || (wildcard(p.addr) && hostMatches(p.host, e.addr)) {
					out[p.id] = true
				}
			}
			return out
		}

		before := snapshotOf(g)

		portDeps := map[string]map[string]bool{} // port -> dependents
		procDeps := map[string]map[string]bool{} // process -> dependents
		add := func(m map[string]map[string]bool, k string, vs map[string]bool) {
			if m[k] == nil {
				m[k] = map[string]bool{}
			}
			for v := range vs {
				m[k][v] = true
			}
		}
		for _, e := range eps {
			want := modelPorts(e)
			got := Endpoint(g, e.id)
			if !e.live {
				if got != nil {
					t.Fatalf("removed endpoint resolved: %v", got)
				}
				continue
			}
			gotPorts := map[string]bool{}
			for _, r := range got {
				gotPorts[r.Port] = true
				wantProcs := map[string]bool{}
				for p := range owned[r.Port] {
					if procLive[p] {
						wantProcs[p] = true
					}
				}
				if !reflect.DeepEqual(sortedKeys(wantProcs), append([]string{}, r.Processes...)) {
					t.Fatalf("processes of %s = %v, want %v", r.Port, r.Processes, sortedKeys(wantProcs))
				}
			}
			if !reflect.DeepEqual(sortedKeys(gotPorts), sortedKeys(want)) {
				t.Fatalf("endpoint %+v ports %v, want %v", *e, sortedKeys(gotPorts), sortedKeys(want))
			}
			for p := range want {
				add(portDeps, p, deps[e.id])
				for q := range owned[p] {
					if procLive[q] {
						add(procDeps, q, deps[e.id])
					}
				}
			}
		}
		// Dependents is the exact inverse.
		for _, p := range ports {
			if !p.live {
				continue
			}
			if got := Dependents(g, p.id); !reflect.DeepEqual(got, sortedKeys(portDeps[p.id])) {
				t.Fatalf("dependents(port %s) = %v, want %v", p.id, got, sortedKeys(portDeps[p.id]))
			}
		}
		for _, q := range procs {
			if !procLive[q] {
				continue
			}
			if got := Dependents(g, q); !reflect.DeepEqual(got, sortedKeys(procDeps[q])) {
				t.Fatalf("dependents(process %s) = %v, want %v", q, got, sortedKeys(procDeps[q]))
			}
		}
		// Derived edges are read-only too.
		for _, e := range eps {
			DerivedFn(g)(e.id)
		}

		if after := snapshotOf(g); !reflect.DeepEqual(before, after) {
			t.Fatalf("resolution changed the graph: %v -> %v", before, after)
		}
	})
}

// snapshotOf captures what a read could disturb: the last sequence (no event
// appended), the entity and relation counts and the relation set.
func snapshotOf(g *graph.Graph) string {
	return fmt.Sprint(g.LastSeq, g.EntityCount(), g.LiveCount(), g.RelationCount(), g.AllRelations())
}
