package lens

import "sort"

// Budget cuts s to at most maxNodes nodes and maxEdges edges. Nodes are kept
// in this order: the root, higher risk score, lower hop count, Entity_ID.
// Edges, groups, and paths that reference a dropped node are removed. The
// result is deterministic and s is not modified. A negative limit counts as 0.
func Budget(s Slice, maxNodes, maxEdges int) Slice {
	if maxNodes < 0 {
		maxNodes = 0
	}
	if maxEdges < 0 {
		maxEdges = 0
	}
	nodes := append([]Node(nil), s.Nodes...)
	sort.SliceStable(nodes, func(i, j int) bool { return nodeLess(s.Root, nodes[i], nodes[j]) })
	omitted := 0
	if len(nodes) > maxNodes {
		omitted = len(nodes) - maxNodes
		nodes = nodes[:maxNodes]
	}
	edges := Prune(nodes, s.Edges)
	truncated := s.Truncated || omitted > 0
	if len(edges) > maxEdges {
		edges = edges[:maxEdges]
		truncated = true
	}

	keep := make(map[string]struct{}, len(nodes))
	for _, n := range nodes {
		keep[n.ID] = struct{}{}
	}
	groups := make([]Group, 0, len(s.Groups))
	for _, g := range s.Groups {
		m := make([]string, 0, len(g.Members))
		for _, id := range g.Members {
			if _, ok := keep[id]; ok {
				m = append(m, id)
			}
		}
		if len(m) > 0 {
			groups = append(groups, Group{ID: g.ID, Label: g.Label, Members: m})
		}
	}
	var paths []Path
	for _, p := range s.Paths {
		all := true
		for _, id := range p.Nodes {
			if _, ok := keep[id]; !ok {
				all = false
				break
			}
		}
		if all {
			paths = append(paths, p)
		}
	}

	out := s
	out.Nodes, out.Edges, out.Groups, out.Paths = nodes, edges, groups, paths
	out.Truncated = truncated
	out.Counts = Counts{Nodes: len(nodes), Edges: len(edges), OmittedNodes: s.Counts.OmittedNodes + omitted}
	return out
}

func nodeLess(root string, a, b Node) bool {
	if ar, br := a.ID == root, b.ID == root; ar != br {
		return ar
	}
	if as, bs := score(a), score(b); as != bs {
		return as > bs
	}
	if a.Hops != b.Hops {
		return a.Hops < b.Hops
	}
	return a.ID < b.ID
}

func score(n Node) float64 {
	if n.Risk == nil {
		return 0
	}
	return n.Risk.Score
}
