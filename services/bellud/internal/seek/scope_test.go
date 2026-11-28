package seek

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

// e builds a CHILD_OF edge, child to parent.
func e(child, parent string) Edge { return Edge{Child: child, Parent: parent} }

func TestBuildScopeIncludesDirectChildren(t *testing.T) {
	edges := []Edge{e("CWE-89", "CWE-74"), e("CWE-79", "CWE-74")}
	got := BuildScope("CWE-74", edges, 1)

	if got.Predicted != "CWE-74" {
		t.Fatalf("Predicted = %q, want CWE-74", got.Predicted)
	}
	want := []string{"CWE-74", "CWE-79", "CWE-89"}
	if !reflect.DeepEqual(got.CWEs, want) {
		t.Fatalf("CWEs = %v, want %v", got.CWEs, want)
	}
	wantDepth := map[string]int{"CWE-74": 0, "CWE-79": 1, "CWE-89": 1}
	if !reflect.DeepEqual(got.Depth, wantDepth) {
		t.Fatalf("Depth = %v, want %v", got.Depth, wantDepth)
	}
}

func TestBuildScopeExcludesParentsGrandparentsAndSiblings(t *testing.T) {
	edges := []Edge{
		e("CWE-74", "CWE-707"),   // parent of predicted
		e("CWE-707", "CWE-1000"), // grandparent
		e("CWE-75", "CWE-707"),   // sibling
		e("CWE-76", "CWE-75"),    // child of sibling
		e("CWE-79", "CWE-74"),    // real child
	}
	got := BuildScope("CWE-74", edges, 2)

	want := []string{"CWE-74", "CWE-79"}
	if !reflect.DeepEqual(got.CWEs, want) {
		t.Fatalf("CWEs = %v, want %v", got.CWEs, want)
	}
}

func TestBuildScopeDepthLimit(t *testing.T) {
	edges := []Edge{e("CWE-79", "CWE-74"), e("CWE-80", "CWE-79")}

	d1 := BuildScope("CWE-74", edges, 1)
	if want := []string{"CWE-74", "CWE-79"}; !reflect.DeepEqual(d1.CWEs, want) {
		t.Fatalf("depth 1 CWEs = %v, want %v", d1.CWEs, want)
	}

	d2 := BuildScope("CWE-74", edges, 2)
	if want := []string{"CWE-74", "CWE-79", "CWE-80"}; !reflect.DeepEqual(d2.CWEs, want) {
		t.Fatalf("depth 2 CWEs = %v, want %v", d2.CWEs, want)
	}
	if d2.Depth["CWE-80"] != 2 {
		t.Fatalf("Depth[CWE-80] = %d, want 2", d2.Depth["CWE-80"])
	}
}

func TestBuildScopeChildAndGrandchildKeepsDepthOne(t *testing.T) {
	edges := []Edge{
		e("CWE-80", "CWE-74"), // child of predicted
		e("CWE-79", "CWE-74"), // child of predicted
		e("CWE-80", "CWE-79"), // also a grandchild through CWE-79
	}
	got := BuildScope("CWE-74", edges, 2)

	if got.Depth["CWE-80"] != 1 {
		t.Fatalf("Depth[CWE-80] = %d, want 1", got.Depth["CWE-80"])
	}
	if want := []string{"CWE-74", "CWE-79", "CWE-80"}; !reflect.DeepEqual(got.CWEs, want) {
		t.Fatalf("CWEs = %v, want %v (no duplicates)", got.CWEs, want)
	}
}

func TestBuildScopeIgnoresMalformedEdgeIDs(t *testing.T) {
	bad := []string{"", "CWE-", "cwe-79", "CWE-7x", "CWE-123456", "CWE--1", "CWE-79\n", " CWE-79", "CVE-2020-1234", "CWE-74/../x"}
	edges := []Edge{e("CWE-79", "CWE-74")}
	for _, b := range bad {
		edges = append(edges,
			e(b, "CWE-74"), // malformed child
			e("CWE-90", b), // malformed parent
			e("CWE-91", b), // would be a grandchild only through a malformed id
			e(b, "CWE-79"), // malformed grandchild
		)
	}
	got := BuildScope("CWE-74", edges, 2)

	want := []string{"CWE-74", "CWE-79"}
	if !reflect.DeepEqual(got.CWEs, want) {
		t.Fatalf("CWEs = %v, want %v", got.CWEs, want)
	}
}

func TestBuildScopeAcceptsBoundaryIDs(t *testing.T) {
	edges := []Edge{e("CWE-1", "CWE-74"), e("CWE-99999", "CWE-74")}
	got := BuildScope("CWE-74", edges, 1)

	want := []string{"CWE-74", "CWE-1", "CWE-99999"}
	if !reflect.DeepEqual(got.CWEs, want) {
		t.Fatalf("CWEs = %v, want %v", got.CWEs, want)
	}
}

func TestBuildScopeCapsAtFiftyPredictedFirstThenNumericAscending(t *testing.T) {
	// The predicted id is numerically larger than every child, so a plain
	// sort would put it last. Children are added in descending order, and
	// include 2 and 10 to catch lexical ordering.
	var edges []Edge
	for i := 60; i >= 1; i-- {
		edges = append(edges, e(fmt.Sprintf("CWE-%d", i), "CWE-9999"))
	}
	got := BuildScope("CWE-9999", edges, 1)

	if len(got.CWEs) != MaxScope {
		t.Fatalf("len(CWEs) = %d, want %d", len(got.CWEs), MaxScope)
	}
	if got.CWEs[0] != "CWE-9999" {
		t.Fatalf("CWEs[0] = %q, want the predicted CWE-9999", got.CWEs[0])
	}
	for i := 1; i < MaxScope; i++ {
		if want := fmt.Sprintf("CWE-%d", i); got.CWEs[i] != want {
			t.Fatalf("CWEs[%d] = %q, want %q", i, got.CWEs[i], want)
		}
	}
}

func TestBuildScopeCapOrdersAcrossDepths(t *testing.T) {
	// Ordering is by numeric id, not by depth: a depth-2 CWE with a small id
	// sorts before depth-1 CWEs with larger ids.
	edges := []Edge{e("CWE-500", "CWE-74"), e("CWE-501", "CWE-74"), e("CWE-3", "CWE-500")}
	got := BuildScope("CWE-74", edges, 2)

	want := []string{"CWE-74", "CWE-3", "CWE-500", "CWE-501"}
	if !reflect.DeepEqual(got.CWEs, want) {
		t.Fatalf("CWEs = %v, want %v", got.CWEs, want)
	}
}

func TestBuildScopeTerminatesOnCycles(t *testing.T) {
	edges := []Edge{
		e("CWE-2", "CWE-1"),
		e("CWE-3", "CWE-2"),
		e("CWE-1", "CWE-3"), // closes the loop back to the predicted CWE
		e("CWE-2", "CWE-2"), // self loop
		e("CWE-1", "CWE-1"), // self loop on the predicted CWE
	}

	done := make(chan Scope, 1)
	go func() { done <- BuildScope("CWE-1", edges, 1000) }()

	select {
	case got := <-done:
		want := []string{"CWE-1", "CWE-2", "CWE-3"}
		if !reflect.DeepEqual(got.CWEs, want) {
			t.Fatalf("CWEs = %v, want %v", got.CWEs, want)
		}
		if got.Depth["CWE-1"] != 0 {
			t.Fatalf("Depth[CWE-1] = %d, want 0", got.Depth["CWE-1"])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("BuildScope did not terminate on cyclic edges")
	}
}

func TestBuildScopeNoEdges(t *testing.T) {
	got := BuildScope("CWE-74", nil, 2)

	if want := []string{"CWE-74"}; !reflect.DeepEqual(got.CWEs, want) {
		t.Fatalf("CWEs = %v, want %v", got.CWEs, want)
	}
	if got.Expanded {
		t.Fatal("Expanded = true with no edges")
	}
}
