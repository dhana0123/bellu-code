package lens

import (
	"fmt"
	"reflect"
	"testing"

	"pgregory.net/rapid"
)

// Feature: unified-security-graph, Property 15: Budgeted answers are bounded and tagged.
// Validates: Requirements 7.2, 7.11.
func TestBudgetedAnswersAreBoundedAndTagged(t *testing.T) {
	relTypes := []string{"affected_by", "depends_on", "likely_same_as", "owns"}
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(0, 30).Draw(t, "nodeCount")
		ids := make([]string, n)
		nodes := make([]Node, n)
		for i := range nodes {
			ids[i] = "n" + string(rune('A'+i))
			node := Node{ID: ids[i], Hops: rapid.IntRange(0, 5).Draw(t, "hops")}
			if rapid.Bool().Draw(t, "hasRisk") {
				node.Risk = &Risk{Score: float64(rapid.IntRange(0, 100).Draw(t, "score"))}
			}
			nodes[i] = node
		}
		var edges []SliceEdge
		var groups []Group
		var paths []Path
		root := ""
		if n > 0 {
			root = rapid.SampledFrom(ids).Draw(t, "root")
			pick := rapid.SampledFrom(ids)
			for i, m := 0, rapid.IntRange(0, 60).Draw(t, "edgeCount"); i < m; i++ {
				typ := rapid.SampledFrom(relTypes).Draw(t, "type")
				edges = append(edges, SliceEdge{From: pick.Draw(t, "from"), To: pick.Draw(t, "to"), Type: typ, Confidence: Confidence(typ)})
			}
			for i, m := 0, rapid.IntRange(0, 4).Draw(t, "groupCount"); i < m; i++ {
				groups = append(groups, Group{ID: "g", Members: rapid.SliceOfN(pick, 0, 6).Draw(t, "members")})
			}
			for i, m := 0, rapid.IntRange(0, 4).Draw(t, "pathCount"); i < m; i++ {
				paths = append(paths, Path{Nodes: rapid.SliceOfN(pick, 1, 4).Draw(t, "path"), Confidence: ConfExtracted})
			}
		}
		s := Slice{Root: root, Nodes: nodes, Edges: edges, Groups: groups, Paths: paths}
		maxNodes := rapid.IntRange(-2, 35).Draw(t, "maxNodes")
		maxEdges := rapid.IntRange(-2, 70).Draw(t, "maxEdges")

		out := Budget(s, maxNodes, maxEdges)

		wantNodes, wantEdges := max(maxNodes, 0), max(maxEdges, 0)
		if len(out.Nodes) > wantNodes || len(out.Edges) > wantEdges {
			t.Fatalf("over limit: %d/%d nodes, %d/%d edges", len(out.Nodes), wantNodes, len(out.Edges), wantEdges)
		}
		kept := map[string]bool{}
		for _, nd := range out.Nodes {
			kept[nd.ID] = true
		}
		for _, e := range out.Edges {
			if !kept[e.From] || !kept[e.To] {
				t.Fatalf("dangling edge %+v", e)
			}
			if e.Confidence != ConfExtracted && e.Confidence != ConfInferred {
				t.Fatalf("untagged edge %+v", e)
			}
		}
		for _, g := range out.Groups {
			for _, id := range g.Members {
				if !kept[id] {
					t.Fatalf("dangling group member %q", id)
				}
			}
		}
		for _, p := range out.Paths {
			for _, id := range p.Nodes {
				if !kept[id] {
					t.Fatalf("dangling path node %q", id)
				}
			}
		}
		if dropped := n - len(out.Nodes); dropped > 0 {
			if !out.Truncated || out.Counts.OmittedNodes != dropped {
				t.Fatalf("dropped %d nodes: truncated=%v omitted=%d", dropped, out.Truncated, out.Counts.OmittedNodes)
			}
		}
		if out.Counts.Nodes != len(out.Nodes) || out.Counts.Edges != len(out.Edges) {
			t.Fatalf("counts %+v do not match output", out.Counts)
		}
		if !reflect.DeepEqual(out, Budget(s, maxNodes, maxEdges)) {
			t.Fatal("Budget is not deterministic")
		}
	})
}

// Feature: aws-relationship-registry, Property 23: Budget drops rule nodes first and keeps roots and paths
//
// **Validates: Requirements 8.10, 13.11, 16.11**
func TestPropertyBudgetDropsRuleNodesFirst(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(1, 20).Draw(t, "n")
		var nodes []Node
		var ids []string
		for i := range n {
			id := fmt.Sprintf("n%02d", i)
			ids = append(ids, id)
			nodes = append(nodes, Node{ID: id, Hops: rapid.IntRange(0, 4).Draw(t, "hops"),
				Kind: rapid.SampledFrom([]string{kindSGRule, "aws_resource", "aws_cidr"}).Draw(t, "kind")})
		}
		pick := rapid.SampledFrom(ids)
		root := pick.Draw(t, "root")
		var paths []Path
		for range rapid.IntRange(0, 2).Draw(t, "paths") {
			paths = append(paths, Path{Nodes: rapid.SliceOfNDistinct(pick, 1, 3, func(s string) string { return s }).Draw(t, "path"), Confidence: ConfExtracted})
		}
		var edges []SliceEdge
		for range rapid.IntRange(0, 30).Draw(t, "edges") {
			edges = append(edges, SliceEdge{From: pick.Draw(t, "from"), To: pick.Draw(t, "to"), Type: "depends_on", Confidence: ConfExtracted})
		}
		s := Slice{Root: root, Nodes: nodes, Edges: edges, Paths: paths}
		maxN := rapid.IntRange(0, n).Draw(t, "maxNodes")
		out := Budget(s, maxN, 100)
		kept := map[string]bool{}
		for _, nd := range out.Nodes {
			kept[nd.ID] = true
		}
		protected := map[string]bool{root: true}
		for _, p := range paths {
			for _, id := range p.Nodes {
				protected[id] = true
			}
		}
		keptRule, droppedOther, droppedProtected, keptUnprotected := false, false, false, false
		for _, nd := range nodes {
			switch {
			case protected[nd.ID] && !kept[nd.ID]:
				droppedProtected = true
			case !protected[nd.ID] && kept[nd.ID]:
				keptUnprotected = true
			}
			if protected[nd.ID] {
				continue
			}
			if nd.Kind == kindSGRule && kept[nd.ID] {
				keptRule = true
			}
			if nd.Kind != kindSGRule && !kept[nd.ID] {
				droppedOther = true
			}
		}
		if keptRule && droppedOther {
			t.Fatal("a non-rule node was dropped while an unprotected rule node was kept")
		}
		if droppedProtected && keptUnprotected {
			t.Fatal("a root or path node was dropped while another node was kept")
		}
		for _, e := range out.Edges {
			if !kept[e.From] || !kept[e.To] {
				t.Fatalf("dangling edge %+v", e)
			}
		}
		if !reflect.DeepEqual(Budget(s, maxN, 100), out) {
			t.Fatal("budget is not deterministic")
		}
	})
}
