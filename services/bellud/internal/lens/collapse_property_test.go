package lens

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

type genRule struct {
	id, group, peer, dir, proto, from, to string
}

// genRuleSlice draws groups g*, peers p*, and rule nodes r* linking them.
func genRuleSlice(t *rapid.T) (Slice, []genRule) {
	var s Slice
	groups := rapid.IntRange(1, 3).Draw(t, "groups")
	peers := rapid.IntRange(1, 3).Draw(t, "peers")
	for i := range groups {
		s.Nodes = append(s.Nodes, Node{ID: fmt.Sprintf("g%d", i), Kind: "aws_resource", Attrs: map[string]string{}})
	}
	for i := range peers {
		s.Nodes = append(s.Nodes, Node{ID: fmt.Sprintf("p%d", i), Kind: "aws_cidr", Attrs: map[string]string{}})
	}
	var rules []genRule
	seen := map[string]bool{}
	for i := range rapid.IntRange(0, 8).Draw(t, "rules") {
		r := genRule{
			id:    fmt.Sprintf("r%d", i),
			group: fmt.Sprintf("g%d", rapid.IntRange(0, groups-1).Draw(t, "g")),
			peer:  fmt.Sprintf("p%d", rapid.IntRange(0, peers-1).Draw(t, "p")),
			dir:   rapid.SampledFrom([]string{"ingress", "egress"}).Draw(t, "dir"),
			proto: rapid.SampledFrom([]string{"tcp", "udp"}).Draw(t, "proto"),
			from:  fmt.Sprint(rapid.IntRange(0, 2).Draw(t, "from")),
		}
		r.to = r.from
		// Distinct rules differ in some field (identical rules share a node).
		k := strings.Join([]string{r.group, r.peer, r.dir, r.proto, r.from}, "|")
		if seen[k] {
			continue
		}
		seen[k] = true
		rules = append(rules, r)
		s.Nodes = append(s.Nodes, Node{ID: r.id, Kind: kindSGRule, Attrs: map[string]string{
			"direction": r.dir, "protocol": r.proto, "from_port": r.from, "to_port": r.to}})
		s.Edges = append(s.Edges,
			SliceEdge{From: r.id, To: r.group, Type: relRuleOf, Confidence: ConfExtracted},
			SliceEdge{From: r.id, To: r.peer, Type: relRulePeer, Confidence: ConfExtracted})
	}
	return s, rules
}

// Feature: aws-relationship-registry, Property 22: Collapsing rule nodes keeps distinct rules distinct
//
// **Validates: Requirements 8.8, 8.9**
func TestPropertyCollapseKeepsRulesDistinct(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		s, rules := genRuleSlice(t)
		out := Collapse(s)
		for _, n := range out.Nodes {
			if n.Kind == kindSGRule {
				t.Fatalf("rule node %s survived", n.ID)
			}
		}
		if len(out.Edges) != len(rules) {
			t.Fatalf("%d edges for %d distinct rules", len(out.Edges), len(rules))
		}
		ev := map[string]bool{}
		for _, e := range out.Edges {
			key := e.From + "|" + e.To + "|" + e.Type + "|" + e.Evidence
			if ev[key] {
				t.Fatalf("two rules collapsed to the same edge %+v", e)
			}
			ev[key] = true
		}
		for _, r := range rules {
			typ := relAllowsOut
			if r.dir == "ingress" {
				typ = relAllowsIn
			}
			want := r.dir + " " + r.proto + " " + r.from + "-" + r.to
			if !ev[r.group+"|"+r.peer+"|"+typ+"|"+want] {
				t.Fatalf("no edge for rule %+v in %v", r, out.Edges)
			}
		}
		if !reflect.DeepEqual(Collapse(s), out) {
			t.Fatal("collapse is not deterministic")
		}
	})
}
