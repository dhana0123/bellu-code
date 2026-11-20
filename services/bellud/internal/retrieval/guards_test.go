package retrieval

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestResolveBudget(t *testing.T) {
	b, err := ResolveBudget(nil)
	if err != nil || b != (QueryBudget{500, 1000, 20 * time.Second}) {
		t.Fatalf("defaults: %+v %v", b, err)
	}
	b, err = ResolveBudget(json.RawMessage(`{"max_nodes":99999,"max_edges":10,"max_duration_seconds":5}`))
	if err != nil || b != (QueryBudget{2000, 10, 5 * time.Second}) {
		t.Fatalf("clamp: %+v %v", b, err)
	}
	b, err = ResolveBudget(json.RawMessage(`{"max_nodes":99999999999999999999999}`))
	if err != nil || b.MaxNodes != 2000 {
		t.Fatalf("huge: %+v %v", b, err)
	}
	for field, body := range map[string]string{
		"max_nodes":            `{"max_nodes":0}`,
		"max_edges":            `{"max_edges":1.5}`,
		"max_duration_seconds": `{"max_duration_seconds":"3"}`,
	} {
		_, err := ResolveBudget(json.RawMessage(body))
		var ve *ValidationError
		if !errors.As(err, &ve) || ve.Field != field {
			t.Errorf("%s: got %v", body, err)
		}
	}
	for _, body := range []string{`{"max_nodes":null}`, `{"max_nodes":-3}`, `{"max_nodes":1e3}`, `[1]`} {
		if _, err := ResolveBudget(json.RawMessage(body)); err == nil {
			t.Errorf("%s accepted", body)
		}
	}
}

func TestStripIdentityFields(t *testing.T) {
	a, err := StripIdentityFields([]byte(`{"q":"x","workspace":"other","tenant":"t"}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := StripIdentityFields([]byte(`{"q":"x"}`))
	if string(a) != string(b) || strings.Contains(string(a), "workspace") {
		t.Fatalf("%s vs %s", a, b)
	}
}

func TestClampScope(t *testing.T) {
	kept, removed := ClampScope([]string{"a", "x", "a", "b"}, []string{"a", "b", "c"})
	if strings.Join(kept, ",") != "a,b" || strings.Join(removed, ",") != "x" {
		t.Fatalf("%v %v", kept, removed)
	}
}

func TestNotFoundIdentical(t *testing.T) {
	if EntityVisible("w1", "w2", true) || EntityVisible("w1", "w1", false) || !EntityVisible("w1", "w1", true) {
		t.Fatal("visibility")
	}
	a, b := httptest.NewRecorder(), httptest.NewRecorder()
	WriteNotFound(a)
	WriteNotFound(b)
	if a.Code != 404 || a.Body.String() != b.Body.String() {
		t.Fatal("not identical")
	}
}

func TestRoundsBound(t *testing.T) {
	var r Rounds
	for want := 0; want < 2; want++ {
		if got, err := r.Begin(); err != nil || got != want {
			t.Fatalf("round %d: %d %v", want, got, err)
		}
	}
	if _, err := r.Begin(); !errors.Is(err, ErrReplanLimit) || r.Run() != 2 {
		t.Fatal("third round allowed")
	}
}

func TestResultValidator(t *testing.T) {
	var v ResultValidator
	s := Schema{Name: "plan.v1", Validate: func(raw []byte) error {
		if !json.Valid(raw) {
			return errors.New("bad json")
		}
		return nil
	}}
	if out, err := v.Accept("planner", s, []byte(`{}`)); err != nil || out == nil {
		t.Fatal("valid rejected")
	}
	if out, err := v.Accept("planner", s, []byte(`{`)); err == nil || out != nil {
		t.Fatal("invalid accepted")
	}
	f := v.Failures()
	if len(f) != 1 || f[0].Agent != "planner" || f[0].Schema != "plan.v1" {
		t.Fatalf("%+v", f)
	}
}

func TestWithholdSideEffectTools(t *testing.T) {
	tools := []Tool{{"read", false}, {"write", true}}
	var s AgentSession
	if len(s.Tools(tools)) != 2 {
		t.Fatal("before taint")
	}
	s.MarkUntrustedRead()
	got := s.Tools(tools)
	if len(got) != 1 || got[0].Name != "read" {
		t.Fatalf("%+v", got)
	}
}

func TestCheckConnectorOp(t *testing.T) {
	allow := func(c, op string) bool { return op == "GET /x" }
	if CheckConnectorOp(allow, "gh", "GET /x") != nil {
		t.Fatal("allowed refused")
	}
	var re *RefusedError
	if err := CheckConnectorOp(allow, "gh", "DELETE /x"); !errors.As(err, &re) || re.Operation != "DELETE /x" {
		t.Fatal(err)
	}
	if CheckConnectorOp(nil, "gh", "GET /x") == nil {
		t.Fatal("nil allowlist must fail closed")
	}
}

func TestMeter(t *testing.T) {
	now := time.Unix(0, 0)
	m := newMeter(QueryBudget{2, 1, time.Second}, func() time.Time { return now })
	if !m.AddNode() || !m.AddNode() || m.AddNode() {
		t.Fatal("nodes")
	}
	if r := m.Result(); !r.Truncated || r.Limit != LimitNodes {
		t.Fatalf("%+v", r)
	}
	m = newMeter(QueryBudget{5, 1, time.Second}, func() time.Time { return now })
	if !m.AddEdge() || m.AddEdge() || m.Result().Limit != LimitEdges {
		t.Fatal("edges")
	}
	m = newMeter(QueryBudget{5, 5, time.Second}, func() time.Time { return now })
	now = now.Add(time.Second)
	if m.AddNode() || m.Result().Limit != LimitDuration {
		t.Fatal("duration")
	}
	if (newMeter(QueryBudget{1, 1, time.Second}, func() time.Time { return now })).Result().Truncated {
		t.Fatal("fresh meter truncated")
	}
}

func TestTopK(t *testing.T) {
	k := NewTopK()
	if k.Get() != 4 {
		t.Fatal("default")
	}
	if err := k.Set(50); err != nil || k.Get() != 50 {
		t.Fatal("50")
	}
	for _, bad := range []any{0, 51, -1, 2.5, "7", nil} {
		err := k.Set(bad)
		if err == nil || k.Get() != 50 {
			t.Errorf("%v accepted or changed value", bad)
		}
	}
	if err := k.Set(0); err == nil || !strings.Contains(err.Error(), "0") {
		t.Error("error should name value")
	}
}

func TestDistributeTopK(t *testing.T) {
	for total := 1; total <= 50; total++ {
		for units := 1; units <= 12; units++ {
			sum := 0
			for _, s := range DistributeTopK(total, units) {
				if s < 0 {
					t.Fatal("negative")
				}
				sum += s
			}
			if sum != total {
				t.Fatalf("total %d units %d sum %d", total, units, sum)
			}
		}
	}
	if DistributeTopK(4, 0) != nil {
		t.Fatal("no units")
	}
}
