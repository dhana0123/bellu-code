package lens

import (
	"encoding/json"
	"testing"
	"time"
)

// TestSliceJSONTruncationReason checks that the reason is serialized on a
// truncated slice and omitted when truncated is false (Requirements 2.5, 2.6).
func TestSliceJSONTruncationReason(t *testing.T) {
	decode := func(s Slice) map[string]any {
		raw, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		m := map[string]any{}
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	for _, tc := range []struct {
		name  string
		setup func(g awsGraph)
		want  string
	}{
		{"entity limit", func(g awsGraph) { g.eng.catMax = 2 }, ReasonEntityLimit},
		{"time limit", func(g awsGraph) { g.eng.catTime = time.Nanosecond }, ReasonTimeLimit},
	} {
		g := newAWSGraph(t)
		tc.setup(g)
		m := decode(slice(t, g, "category-cloud-infrastructure"))
		if m["truncated"] != true || m["reason"] != tc.want {
			t.Errorf("%s: truncated=%v reason=%v, want reason %q", tc.name, m["truncated"], m["reason"], tc.want)
		}
	}
	g := newAWSGraph(t)
	m := decode(slice(t, g, "category-cloud-infrastructure"))
	if m["truncated"] != false {
		t.Fatalf("truncated = %v", m["truncated"])
	}
	if _, ok := m["reason"]; ok {
		t.Errorf("reason present on untruncated slice: %v", m["reason"])
	}
}
