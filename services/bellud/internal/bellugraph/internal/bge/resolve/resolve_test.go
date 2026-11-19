package resolve

import (
	"reflect"
	"sort"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/codec"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/graph"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/query"
)

type fake struct {
	ents map[string]*graph.EntityState
	rels []graph.RelKey
}

func (f *fake) Entity(id string) (*graph.EntityState, bool) { e, ok := f.ents[id]; return e, ok }
func (f *fake) LiveIDsOfKind(kind string) []string {
	var o []string
	for id, e := range f.ents {
		if e.Live && e.Kind == kind {
			o = append(o, id)
		}
	}
	sort.Strings(o)
	return o
}
func (f *fake) RelationsFrom(id string) []graph.RelKey {
	var o []graph.RelKey
	for _, r := range f.rels {
		if r.From == id {
			o = append(o, r)
		}
	}
	return o
}
func (f *fake) RelationsTo(id string) []graph.RelKey {
	var o []graph.RelKey
	for _, r := range f.rels {
		if r.To == id {
			o = append(o, r)
		}
	}
	return o
}
func (f *fake) PortEntities(protocol, port string) []string {
	var o []string
	for id, e := range f.ents {
		if e.Live && e.Kind == graph.KindListeningPort && e.Identity["protocol"] == protocol && e.Identity["port"] == port {
			o = append(o, id)
		}
	}
	sort.Strings(o)
	return o
}

func (f *fake) add(kind string, id map[string]string, attrs map[string]codec.Value) string {
	h, err := ident.Hash(kind, id)
	if err != nil {
		panic(err)
	}
	f.ents[h] = &graph.EntityState{ID: h, Kind: kind, Identity: id, Attrs: attrs, Live: true}
	return h
}
func (f *fake) rel(t, from, to string) {
	f.rels = append(f.rels, graph.RelKey{Type: t, From: from, To: to})
}

func ep(f *fake, proto, addr, port string) string {
	return f.add("endpoint", map[string]string{"protocol": proto, "address": addr, "port": port}, nil)
}
func lp(f *fake, host, proto, addr, port string) string {
	return f.add("listening_port", map[string]string{"host": host, "protocol": proto, "address": addr, "port": port}, nil)
}

func TestEndpointMatchingRule(t *testing.T) {
	f := &fake{ents: map[string]*graph.EntityState{}}
	f.add("host", map[string]string{"hostname": "web-1"},
		map[string]codec.Value{"addresses": {T: codec.TagList, L: []string{"10.0.0.5"}}})
	exact := lp(f, "web-1", "tcp", "10.0.0.9", "80")
	wild := lp(f, "web-1", "tcp", "0.0.0.0", "80")
	lp(f, "web-1", "udp", "0.0.0.0", "80")
	lp(f, "web-1", "tcp", "0.0.0.0", "81")
	proc := f.add("process", map[string]string{"host": "web-1", "pid": "1", "start_time": "0"}, nil)
	f.rel("owned_by", wild, proc)

	ports := func(e string) []string {
		o := []string{}
		for _, r := range Endpoint(f, e) {
			o = append(o, r.Port)
		}
		return o
	}
	// Exact address match only: 10.0.0.9 is not a host address.
	if got := ports(ep(f, "tcp", "10.0.0.9", "80")); !reflect.DeepEqual(got, []string{exact}) {
		t.Fatalf("exact = %v", got)
	}
	// Host address and loopback names match the wildcard listener.
	for _, a := range []string{"10.0.0.5", "web-1", "localhost", "127.0.0.1", "::1", "0.0.0.0"} {
		if got := ports(ep(f, "tcp", a, "80")); !reflect.DeepEqual(got, []string{wild}) {
			t.Fatalf("addr %s = %v", a, got)
		}
	}
	// Unknown address, wrong protocol or port: nothing.
	for _, e := range [][3]string{{"tcp", "10.9.9.9", "80"}, {"sctp", "10.0.0.5", "80"}, {"tcp", "10.0.0.5", "82"}} {
		if got := ports(ep(f, e[0], e[1], e[2])); len(got) != 0 {
			t.Fatalf("%v = %v", e, got)
		}
	}
	e := ep(f, "tcp", "10.0.0.5", "80")
	res := Endpoint(f, e)
	if len(res) != 1 || !reflect.DeepEqual(res[0].Processes, []string{proc}) {
		t.Fatalf("processes = %+v", res)
	}
	// Dependents is the inverse, through the port and through the process.
	svc := f.add("container", map[string]string{"id": "c1"}, nil)
	f.rel("depends_on", svc, e)
	for _, x := range []string{wild, proc} {
		if got := Dependents(f, x); !reflect.DeepEqual(got, []string{svc}) {
			t.Fatalf("Dependents(%s) = %v", x, got)
		}
	}
	if got := Dependents(f, exact); len(got) != 0 {
		t.Fatalf("Dependents(exact) = %v", got)
	}
	// Removed listeners do not resolve.
	f.ents[wild].Live = false
	if got := ports(e); len(got) != 0 {
		t.Fatalf("removed = %v", got)
	}
}

func TestDerivedFn(t *testing.T) {
	f := &fake{ents: map[string]*graph.EntityState{}}
	wild := lp(f, "h", "tcp", "*", "53")
	proc := f.add("process", map[string]string{"host": "h", "pid": "2", "start_time": "0"}, nil)
	f.rel("owned_by", wild, proc)
	e := ep(f, "tcp", "h", "53")
	d := DerivedFn(f)
	out := d(e)
	if len(out) != 2 || out[0].From != e || out[0].Type != RelResolvesTo || !out[0].Derived {
		t.Fatalf("endpoint edges = %+v", out)
	}
	in := d(wild)
	if len(in) != 1 || in[0].From != e || in[0].To != wild {
		t.Fatalf("port edges = %+v", in)
	}
	if in := d(proc); len(in) != 1 || in[0].To != proc {
		t.Fatalf("process edges = %+v", in)
	}
	// Incoming traversal from the port reaches the endpoint.
	edges := query.Neighbors(f2{f}, wild, query.DirIn, RelResolvesTo, 1, d)
	if len(edges) != 1 || edges[0].From != e || !edges[0].Derived {
		t.Fatalf("neighbors = %+v", edges)
	}
}

// f2 adds the query.Reader methods missing from fake.
type f2 struct{ *fake }

func (f f2) LiveIDs() []string {
	var o []string
	for id, e := range f.ents {
		if e.Live {
			o = append(o, id)
		}
	}
	sort.Strings(o)
	return o
}

func (f2) Relation(graph.RelKey) (*graph.RelState, bool) { return nil, false }
