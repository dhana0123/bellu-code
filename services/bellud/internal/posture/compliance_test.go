package posture

import (
	"context"
	"testing"
	"testing/fstest"

	"github.com/bellu/bellucode/services/bellud/internal/findings"
)

func TestComputeStatus(t *testing.T) {
	cases := []struct {
		c    ControlCounts
		want ControlStatus
	}{
		{ControlCounts{Failing: 1, Passed: 3, Errored: 1, EnabledRules: 1}, StatusFail},
		{ControlCounts{Passed: 1, Errored: 2, EnabledRules: 1}, StatusPass},
		{ControlCounts{EnabledRules: 1}, StatusNotApplicable},
		{ControlCounts{EnabledRules: 0, Errored: 1}, StatusNotApplicable},
		{ControlCounts{Errored: 1, EnabledRules: 2}, StatusError},
	}
	for _, tc := range cases {
		if got := ComputeStatus(tc.c); got != tc.want {
			t.Errorf("%+v: got %s want %s", tc.c, got, tc.want)
		}
	}
}

func TestComplianceControls(t *testing.T) {
	ctx := context.Background()
	f := newEvalFixture(t, "1")
	src := fstest.MapFS{"r1.rego": {Data: []byte(bad)}}
	rule := func(id string, bm ...string) Rule {
		return Rule{ID: id, Title: id, Severity: findings.SevHigh, Category: "cloud_infrastructure", AppliesTo: []string{"host"}, Benchmarks: bm, Kind: KindPosture, Rego: "r1.rego"}
	}
	pack := Pack{ID: "p", Version: "1", Source: src, Rules: []Rule{
		rule("r1", "CIS:1.1", "CIS:1.3"),
		rule("r2", "CIS:1.1", "OTHER:9"), // second rule on control 1.1
		rule("r3", "CIS:1.2"),
		rule("r4", "CIS:1.4"),
	}}
	e, errs := NewEngine(ctx, []Pack{pack}, f.g.Query())
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	e.Configure(f.db, nil)
	if got := e.Benchmarks(); len(got) != 2 || got[0] != "CIS" || got[1] != "OTHER" {
		t.Fatalf("benchmarks %v", got)
	}
	ws := f.db.WorkspaceID()
	ins := func(rule, entity, result string) {
		t.Helper()
		if _, err := f.db.DB().Exec(`INSERT INTO posture_eval (workspace_id, pack_id, rule_id, entity_id, result, pack_version, evaluated_at) VALUES (?,?,?,?,?,?,?)`,
			ws, "p", rule, entity, result, "1", "2026-01-01T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
	}
	ins("r1", "h1", "pass") // 1.1 and 1.3 pass via r1...
	ins("r2", "h1", "fail") // ...but r2 fails h1 and h2 on 1.1
	ins("r2", "h2", "fail")
	ins("r1", "h2", "pass")
	ins("r3", "h1", "error") // 1.2 errored, nothing else
	// r4: no rows -> not applicable

	check := func(want map[string]ControlResult) {
		t.Helper()
		got, err := e.Compliance(ctx, "CIS")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(want) {
			t.Fatalf("%+v", got)
		}
		for _, g := range got {
			w := want[g.Control]
			if g.Status != w.Status || g.FailingEntities != w.FailingEntities || g.Benchmark != "CIS" {
				t.Errorf("%s: got %+v want %+v", g.Control, g, w)
			}
		}
	}
	check(map[string]ControlResult{
		"1.1": {Status: StatusFail, FailingEntities: 2},
		"1.2": {Status: StatusError},
		"1.3": {Status: StatusPass},
		"1.4": {Status: StatusNotApplicable},
	})

	// disabling r3 makes 1.2 not applicable; disabling r2 makes 1.1 pass via r1
	no := false
	for _, id := range []string{"r3", "r2"} {
		if err := e.SetOverride(ctx, Override{PackID: "p", RuleID: id, Enabled: &no}); err != nil {
			t.Fatal(err)
		}
	}
	check(map[string]ControlResult{
		"1.1": {Status: StatusPass},
		"1.2": {Status: StatusNotApplicable},
		"1.3": {Status: StatusPass},
		"1.4": {Status: StatusNotApplicable},
	})
}
