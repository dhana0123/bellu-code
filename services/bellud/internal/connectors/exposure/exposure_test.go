package exposure

import "testing"

func TestApplyKeepsLastGoodAndMarksFailedUnknown(t *testing.T) {
	prev := map[string]Exposure{"a": {Value: Internal}, "b": {Value: Internet, Evidence: []string{"r"}}}
	got := Apply(prev, nil, []string{"b"})
	if got["a"].Value != Internal || got["b"].Value != Unknown {
		t.Fatalf("%v", got)
	}
}

func TestUnionAndAttrs(t *testing.T) {
	u := Union([]PortRange{{"tcp", 80, 90}, {"tcp", 91, 100}, {"udp", 5, 5}})
	if len(u) != 2 || u[0].To != 100 {
		t.Fatalf("%v", u)
	}
	a := Exposure{Value: Internet, Ports: u, Evidence: []string{"x", "x"}}.Attrs()
	if a["exposure_evidence"] != `["x"]` {
		t.Fatal(a)
	}
}
