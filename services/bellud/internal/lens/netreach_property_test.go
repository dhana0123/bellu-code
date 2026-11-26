package lens

import (
	"context"
	"fmt"
	"sort"
	"testing"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/facade"
)

// memSource is an in-memory Source for network graphs: Find by kind and
// string attributes, Entity, and one-hop Neighbors. It has no write method.
type memSource struct {
	Source
	ents map[string]facade.Entity
	rels []facade.Edge
}

func (m *memSource) entity(id, kind string, attrs map[string]any) {
	if m.ents == nil {
		m.ents = map[string]facade.Entity{}
	}
	m.ents[id] = facade.Entity{ID: facade.EntityID(id), Type: kind, Attributes: attrs}
}

func (m *memSource) rel(typ, from, to string) {
	m.rels = append(m.rels, facade.Edge{Type: typ, From: facade.EntityID(from), To: facade.EntityID(to)})
}

func (m *memSource) Entity(_ context.Context, id facade.EntityID) (facade.Entity, error) {
	if e, ok := m.ents[string(id)]; ok {
		return e, nil
	}
	return facade.Entity{}, facade.ErrNotFound
}

func (m *memSource) Find(_ context.Context, q facade.FindQuery) (facade.Page[facade.Entity], error) {
	var out []facade.Entity
	for _, e := range m.ents {
		if q.Type != "" && e.Type != q.Type {
			continue
		}
		ok := true
		for k, v := range q.Attributes {
			s, _ := e.Attributes[k].(string)
			ok = ok && s == v
		}
		if ok {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return facade.Page[facade.Entity]{Items: out}, nil
}

func (m *memSource) Neighbors(_ context.Context, id facade.EntityID, o facade.NeighborOpts) (facade.Page[facade.Edge], error) {
	var out []facade.Edge
	for _, e := range m.rels {
		if o.RelationType != "" && e.Type != o.RelationType {
			continue
		}
		if (o.Direction == facade.DirOut && e.From == id) || (o.Direction == facade.DirIn && e.To == id) {
			out = append(out, e)
		}
	}
	return facade.Page[facade.Edge]{Items: out}, nil
}

// genNet draws compute c*, ENIs e*, groups s*, ingress and egress rules r*,
// subnets n*, and route tables t*, with random links.
func genNet(t *rapid.T) *memSource {
	m := &memSource{}
	count := func(name string) int { return rapid.IntRange(1, 4).Draw(t, name) }
	nc, ne, ns, nn := count("compute"), count("enis"), count("groups"), count("subnets")
	id := func(p string, n int, label string) string {
		return fmt.Sprintf("%s%d", p, rapid.IntRange(0, n-1).Draw(t, label))
	}
	for i := range nc {
		m.entity(fmt.Sprintf("c%d", i), "aws_resource", map[string]any{"resource_type": "ec2:instance"})
	}
	for i := range ne {
		e := fmt.Sprintf("e%d", i)
		m.entity(e, "aws_resource", map[string]any{"resource_type": "ec2:eni"})
		if rapid.Bool().Draw(t, "owned") {
			m.rel("aws_has_eni", id("c", nc, "owner"), e)
		}
		for range rapid.IntRange(0, 2).Draw(t, "memberships") {
			m.rel("aws_member_of_sg", e, id("s", ns, "sg"))
		}
		m.rel("aws_in_subnet", e, id("n", nn, "subnet"))
	}
	for i := range ns {
		m.entity(fmt.Sprintf("s%d", i), "aws_resource", map[string]any{"resource_type": "ec2:security-group"})
	}
	for i := range nn {
		m.entity(fmt.Sprintf("n%d", i), "aws_resource", map[string]any{"resource_type": "ec2:subnet"})
		if rapid.Bool().Draw(t, "routed") {
			tb := fmt.Sprintf("t%d", i)
			m.entity(tb, "aws_resource", map[string]any{"resource_type": "ec2:route-table"})
			m.rel("aws_associated_subnet", tb, fmt.Sprintf("n%d", i))
		}
	}
	for i := range rapid.IntRange(0, 6).Draw(t, "rules") {
		r := fmt.Sprintf("r%d", i)
		m.entity(r, kindSGRule, map[string]any{
			"direction":     rapid.SampledFrom([]string{"ingress", "egress"}).Draw(t, "dir"),
			"internet_open": rapid.SampledFrom([]string{"true", "false"}).Draw(t, "open"),
		})
		m.rel("aws_rule_of", r, id("s", ns, "ruleOf"))
		if rapid.Bool().Draw(t, "peerGroup") {
			m.rel("aws_rule_peer", r, id("s", ns, "rulePeer"))
		}
	}
	return m
}

func (m *memSource) out(id, typ string) []string {
	var r []string
	for _, e := range m.rels {
		if e.Type == typ && string(e.From) == id {
			r = append(r, string(e.To))
		}
	}
	return r
}

func (m *memSource) in(id, typ string) []string {
	var r []string
	for _, e := range m.rels {
		if e.Type == typ && string(e.To) == id {
			r = append(r, string(e.From))
		}
	}
	return r
}

// closure is the fixpoint of the network chain from start, written as set
// equations rather than a staged walk.
func (m *memSource) closure(start string) map[string]bool {
	compute, enis, own, rules, peer, subnets, ctx := map[string]bool{start: true}, map[string]bool{}, map[string]bool{},
		map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for changed := true; changed; {
		changed = false
		add := func(set map[string]bool, ids []string) {
			for _, id := range ids {
				if !set[id] {
					set[id], changed = true, true
				}
			}
		}
		for c := range compute {
			add(enis, m.out(c, "aws_has_eni"))
		}
		for e := range enis {
			add(own, m.out(e, "aws_member_of_sg"))
			add(subnets, m.out(e, "aws_in_subnet"))
			add(compute, m.in(e, "aws_has_eni"))
		}
		for g := range own {
			for _, r := range m.in(g, "aws_rule_peer") {
				if m.ents[r].Attributes["direction"] == "ingress" {
					add(rules, []string{r})
				}
			}
		}
		for r := range rules {
			add(peer, m.out(r, "aws_rule_of"))
		}
		for g := range peer {
			add(enis, m.in(g, "aws_member_of_sg"))
		}
		for n := range subnets {
			add(ctx, m.in(n, "aws_associated_subnet"))
		}
	}
	all := map[string]bool{}
	for _, set := range []map[string]bool{compute, enis, own, rules, peer, subnets, ctx} {
		for id := range set {
			all[id] = true
		}
	}
	delete(all, start)
	return all
}

// Feature: aws-relationship-registry, Property 26: Network reach follows the network chain
//
// **Validates: Requirements 13.2, 13.8**
func TestPropertyNetworkReach(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		m := genNet(t)
		start := "c0"
		g := &sourceNet{ctx: context.Background(), src: m, attrs: map[string]map[string]any{}}
		got := NetworkReach(g, start, 100)
		want := m.closure(start)
		if len(got) != len(want) {
			t.Fatalf("reached %v, want %v", got, want)
		}
		for i, r := range got {
			if !want[r.ID] {
				t.Fatalf("%s reached outside the chain", r.ID)
			}
			if i > 0 && (got[i-1].Hops > r.Hops || got[i-1].Hops == r.Hops && got[i-1].ID >= r.ID) {
				t.Fatal("result is not in (hops, id) order")
			}
		}
		d := rapid.IntRange(0, 6).Draw(t, "depth")
		for _, r := range NetworkReach(g, start, d) {
			if r.Hops > d {
				t.Fatalf("%s at %d hops beyond depth %d", r.ID, r.Hops, d)
			}
		}

		// exposed_resources: owners of ENIs in a group with an open ingress rule.
		wantExp := map[string]bool{}
		for id, e := range m.ents {
			if e.Type != kindSGRule || e.Attributes["direction"] != "ingress" || e.Attributes["internet_open"] != "true" {
				continue
			}
			for _, sg := range m.out(id, "aws_rule_of") {
				for _, eni := range m.in(sg, "aws_member_of_sg") {
					for _, owner := range m.in(eni, "aws_has_eni") {
						wantExp[owner] = true
					}
				}
			}
		}
		s, err := NewEngine(m).Exposed(context.Background(), Params{MaxNodes: 1000, MaxEdges: 1000})
		if err != nil {
			t.Fatal(err)
		}
		gotExp := map[string]bool{}
		for _, n := range s.Nodes {
			if n.Hops == 0 {
				gotExp[n.ID] = true
			}
		}
		if fmt.Sprint(gotExp) != fmt.Sprint(wantExp) {
			t.Fatalf("exposed %v, want %v", gotExp, wantExp)
		}
		if s.MissingData == nil {
			t.Fatal("missing_data is nil")
		}
	})
}
