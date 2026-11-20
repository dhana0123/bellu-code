package lens

import "strings"

// Kinds and relation types the collapse reads.
const (
	kindSGRule     = "aws_sg_rule"
	relRuleOf      = "aws_rule_of"
	relRulePeer    = "aws_rule_peer"
	relAllowsIn    = "aws_allows_ingress_from"
	relAllowsOut   = "aws_allows_egress_to"
	ruleDirIngress = "ingress"
)

// Collapse replaces every aws_sg_rule node that has both an aws_rule_of edge
// to its group and an aws_rule_peer edge to its peer by one edge from group
// to peer: aws_allows_ingress_from for an ingress rule, aws_allows_egress_to
// otherwise. The edge carries the weakest confidence of the two rule edges and
// the rule's direction, protocol, and ports as evidence, so distinct rules
// between the same group and peer stay distinct edges. Rule nodes are removed
// with their edges; a path through a rule (group, rule, peer) keeps the group
// and peer, and any other path through a rule is dropped. A rule without a
// peer in the slice counts in Counts.OmittedRules. s is not modified.
func Collapse(s Slice) Slice {
	rules := map[string]Node{}
	for _, n := range s.Nodes {
		if n.Kind == kindSGRule {
			rules[n.ID] = n
		}
	}
	if len(rules) == 0 {
		return s
	}
	group, peer := map[string]SliceEdge{}, map[string]SliceEdge{}
	var edges []SliceEdge
	for _, e := range s.Edges {
		_, fromRule := rules[e.From]
		_, toRule := rules[e.To]
		switch {
		case fromRule && e.Type == relRuleOf:
			group[e.From] = e
		case fromRule && e.Type == relRulePeer:
			peer[e.From] = e
		case fromRule || toRule:
			// Any other edge of a rule node goes with the node.
		default:
			edges = append(edges, e)
		}
	}
	seen := map[SliceEdge]bool{}
	for _, e := range edges {
		seen[e] = true
	}
	omitted := 0
	for id, r := range rules {
		g, okG := group[id]
		p, okP := peer[id]
		if !okG || !okP {
			omitted++
			continue
		}
		typ := relAllowsOut
		if r.Attrs["direction"] == ruleDirIngress {
			typ = relAllowsIn
		}
		e := SliceEdge{From: g.To, To: p.To, Type: typ, Confidence: PathConfidenceOfEdges([]SliceEdge{g, p}), Evidence: ruleEvidence(r)}
		if !seen[e] {
			seen[e] = true
			edges = append(edges, e)
		}
	}
	sortEdges(edges)

	out := s
	out.Nodes = make([]Node, 0, len(s.Nodes)-len(rules))
	for _, n := range s.Nodes {
		if _, ok := rules[n.ID]; !ok {
			out.Nodes = append(out.Nodes, n)
		}
	}
	out.Edges = edges
	out.Groups = make([]Group, 0, len(s.Groups))
	for _, g := range s.Groups {
		m := make([]string, 0, len(g.Members))
		for _, id := range g.Members {
			if _, ok := rules[id]; !ok {
				m = append(m, id)
			}
		}
		if len(m) > 0 {
			out.Groups = append(out.Groups, Group{ID: g.ID, Label: g.Label, Members: m})
		}
	}
	out.Paths = nil
	for _, p := range s.Paths {
		if np, ok := collapsePath(p, rules, group, peer); ok {
			out.Paths = append(out.Paths, np)
		}
	}
	out.Counts.Nodes, out.Counts.Edges = len(out.Nodes), len(out.Edges)
	out.Counts.OmittedRules += omitted
	return out
}

// collapsePath removes rule nodes that sit between their group and peer.
func collapsePath(p Path, rules map[string]Node, group, peer map[string]SliceEdge) (Path, bool) {
	nodes := make([]string, 0, len(p.Nodes))
	for i, id := range p.Nodes {
		if _, ok := rules[id]; !ok {
			nodes = append(nodes, id)
			continue
		}
		if i == 0 || i == len(p.Nodes)-1 {
			return Path{}, false
		}
		a, b := p.Nodes[i-1], p.Nodes[i+1]
		g, p2 := group[id].To, peer[id].To
		if g == "" || p2 == "" || !(a == g && b == p2 || a == p2 && b == g) {
			return Path{}, false
		}
	}
	return Path{Nodes: nodes, Confidence: p.Confidence}, true
}

// ruleEvidence is "<direction> <protocol> <from>-<to>", ports omitted when
// the rule has none.
func ruleEvidence(r Node) string {
	parts := []string{r.Attrs["direction"], r.Attrs["protocol"]}
	if f, t := r.Attrs["from_port"], r.Attrs["to_port"]; f != "" && t != "" {
		parts = append(parts, f+"-"+t)
	}
	return truncUTF8(strings.Join(parts, " "), MaxEvidence)
}
