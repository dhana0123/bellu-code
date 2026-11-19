package collectors

import (
	"reflect"
	"testing"
)

func TestStatusRecorderTruncations(t *testing.T) {
	var r StatusRecorder
	r.Truncate("rules@connection", 3)
	r.Truncate("ec2", 0)
	want := []Truncation{{Scope: "rules@connection", Omitted: 3}, {Scope: "ec2"}}
	st := r.Status()
	if !reflect.DeepEqual(st.Truncations, want) {
		t.Fatalf("got %v, want %v", st.Truncations, want)
	}
	st.Truncations[0].Omitted = 99
	if r.Status().Truncations[0].Omitted != 3 {
		t.Fatal("Status must return a copy")
	}
	r.Reset()
	if len(r.Status().Truncations) != 0 {
		t.Fatal("Reset must clear truncations")
	}
}
