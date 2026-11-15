package lens

import "testing"

func TestConfidenceAndPath(t *testing.T) {
	if Confidence("likely_same_as") != ConfInferred || Confidence("affected_by") != ConfExtracted {
		t.Fatal("confidence by type")
	}
	if PathConfidence([]string{ConfExtracted, ConfInferred}) != ConfInferred || PathConfidence(nil) != ConfExtracted {
		t.Fatal("weakest hop")
	}
}

func TestBudgetOrderAndPrune(t *testing.T) {
	s := Slice{Root: "c", Nodes: []Node{
		{ID: "a", Hops: 1}, {ID: "b", Hops: 0, Risk: &Risk{Score: 50}}, {ID: "c", Hops: 5}, {ID: "d", Hops: 1},
	}, Edges: []SliceEdge{{From: "c", To: "b"}, {From: "a", To: "d"}}}
	o := Budget(s, 2, 10)
	if o.Nodes[0].ID != "c" || o.Nodes[1].ID != "b" || !o.Truncated || o.Counts.OmittedNodes != 2 || len(o.Edges) != 1 {
		t.Fatalf("%+v", o)
	}
}

func TestFilterAttrs(t *testing.T) {
	m := FilterAttrs("package", map[string]string{"purl": "p", "connection": "x"})
	if len(m) != 1 || m["purl"] != "p" {
		t.Fatal(m)
	}
}
