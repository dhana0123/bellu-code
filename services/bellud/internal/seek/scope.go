package seek

import (
	"regexp"
	"sort"
	"strconv"
)

// scopeIDPattern matches the CWE ids accepted from upstream edge data.
var scopeIDPattern = regexp.MustCompile(`^CWE-[0-9]{1,5}$`)

// Scope is the set of CWEs searched for one predicted weakness.
type Scope struct {
	Predicted string         // first element of CWEs
	CWEs      []string       // unique, predicted first, then ascending numeric id, len <= MaxScope
	Expanded  bool           // grandchildren were added
	Depth     map[string]int // 0 predicted, 1 child, 2 grandchild
}

// BuildScope walks CHILD_OF edges downward from predicted (an edge whose
// Parent is x makes its Child the next level). Parents, grandparents and
// siblings are never reachable. A CWE reachable at several depths keeps the
// smallest. Edges with ids that do not match ^CWE-[0-9]{1,5}$ are ignored
// because upstream data is untrusted. The result is capped at MaxScope CWEs:
// the predicted CWE first, then the rest by ascending numeric id.
func BuildScope(predicted string, edges []Edge, maxDepth int) Scope {
	children := map[string][]string{}
	for _, edge := range edges {
		if scopeIDPattern.MatchString(edge.Child) && scopeIDPattern.MatchString(edge.Parent) {
			children[edge.Parent] = append(children[edge.Parent], edge.Child)
		}
	}

	depth := map[string]int{predicted: 0}
	frontier := []string{predicted}
	for level := 1; level <= maxDepth && len(frontier) > 0; level++ {
		var next []string
		for _, parent := range frontier {
			for _, child := range children[parent] {
				if _, seen := depth[child]; seen {
					continue
				}
				depth[child] = level
				next = append(next, child)
			}
		}
		frontier = next
	}

	rest := make([]string, 0, len(depth))
	for id := range depth {
		if id != predicted {
			rest = append(rest, id)
		}
	}
	sort.Slice(rest, func(i, j int) bool { return cweNumber(rest[i]) < cweNumber(rest[j]) })
	if len(rest) > MaxScope-1 {
		rest = rest[:MaxScope-1]
	}

	scope := Scope{
		Predicted: predicted,
		CWEs:      append([]string{predicted}, rest...),
		Depth:     map[string]int{predicted: 0},
	}
	for _, id := range rest {
		scope.Depth[id] = depth[id]
		if depth[id] >= 2 {
			scope.Expanded = true
		}
	}
	return scope
}

// cweNumber returns the numeric part of an id already matched by scopeIDPattern.
func cweNumber(id string) int {
	n, _ := strconv.Atoi(id[len("CWE-"):])
	return n
}
