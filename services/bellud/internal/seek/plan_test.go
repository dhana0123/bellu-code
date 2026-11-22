package seek

import (
	"encoding/json"
	"strings"
	"testing"
)

// Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 4.2, 4.5, 12.1

func unit(cwe string) map[string]any {
	return map[string]any{"cwe_id": cwe, "root_cause": "rc", "code_snippet": "x()"}
}

func plan(units ...map[string]any) map[string]any {
	ws := make([]any, len(units))
	for i, u := range units {
		ws[i] = u
	}
	return map[string]any{"language": "go", "reasoning": "why", "weaknesses": ws}
}

func raw(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func paths(issues []Issue) []string {
	out := make([]string, len(issues))
	for i, is := range issues {
		out[i] = is.Path
	}
	return out
}

func hasPath(issues []Issue, path string) bool {
	for _, is := range issues {
		if is.Path == path {
			return true
		}
	}
	return false
}

func TestParsePlanValid(t *testing.T) {
	p, rejected, issues := ParsePlan(raw(t, plan(unit("CWE-79"), unit("CWE-89"))))
	if len(issues) != 0 || len(rejected) != 0 {
		t.Fatalf("issues=%v rejected=%v", issues, rejected)
	}
	if p.Language != "go" || p.Reasoning != "why" || len(p.Weaknesses) != 2 ||
		p.Weaknesses[0].CWEID != "CWE-79" || p.Weaknesses[1].CWEID != "CWE-89" {
		t.Fatalf("unexpected plan %+v", p)
	}
	if p.Weaknesses[0].RootCause != "rc" || p.Weaknesses[0].Snippet != "x()" {
		t.Fatalf("unit fields not decoded: %+v", p.Weaknesses[0])
	}
}

func TestParsePlanEmptyWeaknessesIsValid(t *testing.T) {
	p, rejected, issues := ParsePlan(raw(t, plan()))
	if len(issues) != 0 || len(rejected) != 0 {
		t.Fatalf("issues=%v rejected=%v", issues, rejected)
	}
	if len(p.Weaknesses) != 0 {
		t.Fatalf("want no weaknesses, got %v", p.Weaknesses)
	}
	b, err := p.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"weaknesses":[]`) {
		t.Fatalf("empty weaknesses must marshal as [], got %s", b)
	}
}

func TestParsePlanStructuralIssues(t *testing.T) {
	cases := []struct {
		name string
		in   func() any
		path string
	}{
		{"unknown top-level field", func() any { p := plan(unit("CWE-79")); p["extra"] = 1; return p }, "extra"},
		{"unknown unit field", func() any {
			p := plan(unit("CWE-79"), unit("CWE-80"))
			p["weaknesses"].([]any)[1].(map[string]any)["extra"] = "x"
			return p
		}, "weaknesses[1].extra"},
		{"missing language", func() any { p := plan(); delete(p, "language"); return p }, "language"},
		{"missing reasoning", func() any { p := plan(); delete(p, "reasoning"); return p }, "reasoning"},
		{"missing weaknesses", func() any { p := plan(); delete(p, "weaknesses"); return p }, "weaknesses"},
		{"missing cwe_id", func() any { u := unit("CWE-1"); delete(u, "cwe_id"); return plan(unit("CWE-2"), u) }, "weaknesses[1].cwe_id"},
		{"missing root_cause", func() any { u := unit("CWE-1"); delete(u, "root_cause"); return plan(u) }, "weaknesses[0].root_cause"},
		{"missing code_snippet", func() any { u := unit("CWE-1"); delete(u, "code_snippet"); return plan(u) }, "weaknesses[0].code_snippet"},
		{"language wrong type", func() any { p := plan(); p["language"] = 5; return p }, "language"},
		{"reasoning wrong type", func() any { p := plan(); p["reasoning"] = nil; return p }, "reasoning"},
		{"weaknesses not array", func() any { p := plan(); p["weaknesses"] = "CWE-79"; return p }, "weaknesses"},
		{"weaknesses item not object", func() any {
			p := plan(unit("CWE-1"))
			p["weaknesses"] = append(p["weaknesses"].([]any), "CWE-2")
			return p
		}, "weaknesses[1]"},
		{"cwe_id wrong type", func() any { u := unit("x"); u["cwe_id"] = 79; return plan(u) }, "weaknesses[0].cwe_id"},
		{"root_cause wrong type", func() any { u := unit("CWE-1"); u["root_cause"] = []string{"a"}; return plan(u) }, "weaknesses[0].root_cause"},
		{"code_snippet wrong type", func() any { u := unit("CWE-1"); u["code_snippet"] = true; return plan(unit("CWE-2"), unit("CWE-3"), u) }, "weaknesses[2].code_snippet"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, _, issues := ParsePlan(raw(t, tc.in()))
			if !hasPath(issues, tc.path) {
				t.Fatalf("want issue at %q, got %v", tc.path, paths(issues))
			}
			if len(p.Weaknesses) != 0 {
				t.Fatalf("no plan expected on structural error, got %+v", p)
			}
			for _, is := range issues {
				if is.Reason == "" {
					t.Fatalf("issue %q has no reason", is.Path)
				}
			}
		})
	}
}

func TestParsePlanNotAnObject(t *testing.T) {
	for _, in := range []string{`[]`, `"plan"`, `42`, `null`, `true`, `{"language":`, ``} {
		p, _, issues := ParsePlan([]byte(in))
		if len(issues) == 0 {
			t.Fatalf("%q: want issues", in)
		}
		if len(p.Weaknesses) != 0 {
			t.Fatalf("%q: no plan expected", in)
		}
	}
}

func TestParsePlanLengthBoundaries(t *testing.T) {
	rep := func(s string, n int) string { return strings.Repeat(s, n) }
	cases := []struct {
		name  string
		build func(n int) any
		ok    int
		bad   int
		path  string
	}{
		{"root_cause", func(n int) any { u := unit("CWE-1"); u["root_cause"] = rep("a", n); return plan(u) }, MaxRootCause, MaxRootCause + 1, "weaknesses[0].root_cause"},
		{"code_snippet", func(n int) any { u := unit("CWE-1"); u["code_snippet"] = rep("a", n); return plan(unit("CWE-2"), u) }, MaxSnippet, MaxSnippet + 1, "weaknesses[1].code_snippet"},
		{"language", func(n int) any { p := plan(); p["language"] = rep("a", n); return p }, MaxLanguage, MaxLanguage + 1, "language"},
		{"reasoning", func(n int) any { p := plan(); p["reasoning"] = rep("a", n); return p }, MaxReasoning, MaxReasoning + 1, "reasoning"},
		{"weaknesses count", func(n int) any {
			us := make([]map[string]any, n)
			for i := range us {
				us[i] = unit("CWE-" + string(rune('1'+i)))
			}
			return plan(us...)
		}, MaxWeaknesses, MaxWeaknesses + 1, "weaknesses"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, rej, issues := ParsePlan(raw(t, tc.build(tc.ok))); len(issues) != 0 || len(rej) != 0 {
				t.Fatalf("limit must pass: issues=%v rejected=%v", issues, rej)
			}
			_, _, issues := ParsePlan(raw(t, tc.build(tc.bad)))
			if !hasPath(issues, tc.path) {
				t.Fatalf("want issue at %q, got %v", tc.path, paths(issues))
			}
		})
	}
}

func TestParsePlanEmptyStrings(t *testing.T) {
	p := plan()
	p["language"] = ""
	if _, _, issues := ParsePlan(raw(t, p)); !hasPath(issues, "language") {
		t.Fatalf("empty language: got %v", paths(issues))
	}
	// reasoning may be empty.
	p = plan()
	p["reasoning"] = ""
	if _, _, issues := ParsePlan(raw(t, p)); len(issues) != 0 {
		t.Fatalf("empty reasoning must pass: %v", issues)
	}
	u := unit("CWE-1")
	u["root_cause"] = ""
	if _, _, issues := ParsePlan(raw(t, plan(u))); !hasPath(issues, "weaknesses[0].root_cause") {
		t.Fatalf("empty root_cause: got %v", paths(issues))
	}
	u = unit("CWE-1")
	u["code_snippet"] = ""
	if _, _, issues := ParsePlan(raw(t, plan(unit("CWE-2"), u))); !hasPath(issues, "weaknesses[1].code_snippet") {
		t.Fatalf("empty code_snippet: got %v", paths(issues))
	}
}

// Lengths are code points: multibyte runes must neither be over-counted as
// bytes nor as UTF-16 units.
func TestParsePlanLengthCountsCodePoints(t *testing.T) {
	for _, r := range []string{"é", "世", "😀"} {
		lang := strings.Repeat(r, MaxLanguage)
		root := strings.Repeat(r, MaxRootCause)
		snip := strings.Repeat(r, MaxSnippet)
		reas := strings.Repeat(r, MaxReasoning)
		u := unit("CWE-1")
		u["root_cause"], u["code_snippet"] = root, snip
		p := plan(u)
		p["language"], p["reasoning"] = lang, reas
		got, rej, issues := ParsePlan(raw(t, p))
		if len(issues) != 0 || len(rej) != 0 {
			t.Fatalf("%q at limit must pass: %v %v", r, issues, rej)
		}
		if got.Language != lang || got.Weaknesses[0].RootCause != root {
			t.Fatalf("%q: values altered", r)
		}

		u["root_cause"], u["code_snippet"] = root+r, snip+r
		p["language"], p["reasoning"] = lang+r, reas+r
		_, _, issues = ParsePlan(raw(t, p))
		for _, path := range []string{"language", "reasoning", "weaknesses[0].root_cause", "weaknesses[0].code_snippet"} {
			if !hasPath(issues, path) {
				t.Fatalf("%q over limit: want issue at %q, got %v", r, path, paths(issues))
			}
		}
	}
}

func TestParsePlanMultipleIssuesReported(t *testing.T) {
	u := unit("CWE-1")
	u["root_cause"] = strings.Repeat("a", MaxRootCause+1)
	p := plan(unit("CWE-2"), unit("CWE-3"), u)
	p["language"] = ""
	_, _, issues := ParsePlan(raw(t, p))
	if !hasPath(issues, "language") || !hasPath(issues, "weaknesses[2].root_cause") {
		t.Fatalf("got %v", paths(issues))
	}
}

func TestParsePlanRejectsBadCWEIDsPerUnit(t *testing.T) {
	bad := []string{"CWE-", "CWE-123456", "cwe-79", "CWE-7x", " CWE-79", "CWE-79\n", "79", "CWE--1", ""}
	us := []map[string]any{unit("CWE-79")}
	for _, b := range bad {
		us = append(us, unit(b))
	}
	us = append(us, unit("CWE-89"))
	p, rejected, issues := ParsePlan(raw(t, plan(us...)))
	if len(issues) != 0 {
		t.Fatalf("bad cwe_id is per unit, not a plan issue: %v", issues)
	}
	if len(p.Weaknesses) != 2 || p.Weaknesses[0].CWEID != "CWE-79" || p.Weaknesses[1].CWEID != "CWE-89" {
		t.Fatalf("valid units must continue in order: %+v", p.Weaknesses)
	}
	if len(rejected) != len(bad) {
		t.Fatalf("want %d rejected, got %v", len(bad), rejected)
	}
	for i, d := range rejected {
		if d.Index != i+1 || d.Reason == "" {
			t.Fatalf("rejected[%d] = %+v", i, d)
		}
	}
}

func TestParsePlanBoundaryCWEIDs(t *testing.T) {
	p, rejected, issues := ParsePlan(raw(t, plan(unit("CWE-0"), unit("CWE-12345"))))
	if len(issues) != 0 || len(rejected) != 0 || len(p.Weaknesses) != 2 {
		t.Fatalf("p=%+v rejected=%v issues=%v", p, rejected, issues)
	}
}

func TestParsePlanDuplicatesKeepFirst(t *testing.T) {
	a := unit("CWE-79")
	a["root_cause"] = "first"
	b := unit("CWE-79")
	b["root_cause"] = "second"
	p, rejected, issues := ParsePlan(raw(t, plan(a, unit("CWE-89"), b, unit("CWE-20"), unit("CWE-79"))))
	if len(issues) != 0 {
		t.Fatalf("issues: %v", issues)
	}
	var ids []string
	for _, w := range p.Weaknesses {
		ids = append(ids, w.CWEID)
	}
	if strings.Join(ids, ",") != "CWE-79,CWE-89,CWE-20" || p.Weaknesses[0].RootCause != "first" {
		t.Fatalf("kept %v %+v", ids, p.Weaknesses)
	}
	if len(rejected) != 2 || rejected[0].Index != 2 || rejected[1].Index != 4 {
		t.Fatalf("rejected %+v", rejected)
	}
	for _, d := range rejected {
		if d.Reason == "" {
			t.Fatal("duplicate reason empty")
		}
	}
}

func TestParsePlanDuplicateComparedAsExactStrings(t *testing.T) {
	// "CWE-079" and "CWE-79" are different strings and both match the format.
	p, rejected, _ := ParsePlan(raw(t, plan(unit("CWE-79"), unit("CWE-079"))))
	if len(p.Weaknesses) != 2 || len(rejected) != 0 {
		t.Fatalf("p=%+v rejected=%v", p, rejected)
	}
}

func TestParsePlanMixedRejections(t *testing.T) {
	p, rejected, issues := ParsePlan(raw(t, plan(unit("CWE-1"), unit("bad"), unit("CWE-1"), unit("CWE-2"))))
	if len(issues) != 0 || len(p.Weaknesses) != 2 || p.Weaknesses[1].CWEID != "CWE-2" {
		t.Fatalf("p=%+v issues=%v", p, issues)
	}
	if len(rejected) != 2 || rejected[0].Index != 1 || rejected[1].Index != 2 {
		t.Fatalf("rejected=%+v", rejected)
	}
}

func TestPlanMarshalRoundTrip(t *testing.T) {
	first, _, issues := ParsePlan(raw(t, plan(unit("CWE-79"), unit("CWE-89"))))
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	b1, err := first.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	second, rej, issues := ParsePlan(b1)
	if len(issues) != 0 || len(rej) != 0 {
		t.Fatalf("reparse: %v %v", issues, rej)
	}
	b2, err := second.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if string(b1) != string(b2) {
		t.Fatalf("not stable:\n%s\n%s", b1, b2)
	}
}

func TestParseTopKAccepts(t *testing.T) {
	cases := []struct {
		in   json.RawMessage
		want int
	}{
		{nil, DefaultTopK},
		{json.RawMessage(`1`), 1},
		{json.RawMessage(`4`), 4},
		{json.RawMessage(`10`), 10},
	}
	for _, tc := range cases {
		got, issues := ParseTopK(tc.in)
		if len(issues) != 0 || got != tc.want {
			t.Fatalf("%s: got %d %v want %d", tc.in, got, issues, tc.want)
		}
	}
	if DefaultTopK != 4 {
		t.Fatalf("default top_k must be 4, got %d", DefaultTopK)
	}
}

func TestParseTopKRejects(t *testing.T) {
	for _, in := range []string{`0`, `11`, `-1`, `4.5`, `"4"`, `"abc"`, `true`, `[]`, `{}`, `1e1000`} {
		_, issues := ParseTopK(json.RawMessage(in))
		if len(issues) == 0 {
			t.Fatalf("%s: want issues", in)
		}
		if !hasPath(issues, "top_k") {
			t.Fatalf("%s: want path top_k, got %v", in, paths(issues))
		}
	}
}
