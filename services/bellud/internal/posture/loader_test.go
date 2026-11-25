package posture

import (
	"encoding/json"
	"strings"
	"testing"
	"testing/fstest"
)

func okRule() map[string]any {
	return map[string]any{"id": "r1", "title": "t", "description": "d", "severity": "informational", "category": "cloud_infrastructure",
		"applies_to": []string{"aws_resource"}, "remediation": "fix", "benchmarks": []string{"CIS-AWS-1.4:2.1.1"}, "rego": "r1.rego"}
}

func pack(rules ...map[string]any) fstest.MapFS {
	b, _ := json.Marshal(map[string]any{"id": "p", "version": "1", "rules": rules})
	return fstest.MapFS{"p/pack.json": {Data: b}, "p/r1.rego": {Data: []byte("package bellu.p.r1\n")}}
}

func TestValidPackLoads(t *testing.T) {
	ps, errs, err := LoadAll(pack(okRule()))
	if err != nil || len(errs) != 0 || len(ps) != 1 || len(ps[0].Rules) != 1 || ps[0].Rules[0].Severity != "info" {
		t.Fatalf("%+v %v %v", ps, errs, err)
	}
}

func TestBoundsRejectedNamingField(t *testing.T) {
	long := func(n int) string { return strings.Repeat("x", n) }
	cases := map[string]any{
		"id": long(129), "title": long(201), "description": long(2001), "severity": "urgent",
		"category": "nope", "applies_to": []string{}, "remediation": long(4001), "benchmarks": make([]string, 21),
	}
	for field, v := range cases {
		r := okRule()
		r[field] = v
		ps, errs, _ := LoadAll(pack(r))
		if len(ps[0].Rules) != 0 || len(errs) == 0 || !strings.Contains(errs[0].Detail, field+":") {
			t.Errorf("%s: rules=%d errs=%v", field, len(ps[0].Rules), errs)
		}
	}
	r := okRule()
	r["applies_to"] = make([]string, 51)
	if _, errs, _ := LoadAll(pack(r)); len(errs) == 0 {
		t.Error("51 kinds accepted")
	}
}

func TestBadRuleRejectedOthersKept(t *testing.T) {
	bad := okRule()
	bad["id"] = "bad"
	bad["title"] = ""
	ps, errs, _ := LoadAll(pack(okRule(), bad))
	if len(ps[0].Rules) != 1 || len(errs) != 1 || errs[0].RuleID != "bad" || !strings.HasPrefix(errs[0].Error(), "p/bad: schema:") {
		t.Fatalf("%+v %v", ps, errs)
	}
}

func TestDuplicateIDRejected(t *testing.T) {
	ps, errs, _ := LoadAll(pack(okRule(), okRule()))
	if len(ps[0].Rules) != 1 || len(errs) != 1 || !strings.Contains(errs[0].Detail, "duplicate") {
		t.Fatalf("%+v %v", ps, errs)
	}
}

func TestMissingRegoRejected(t *testing.T) {
	r := okRule()
	r["rego"] = "missing.rego"
	if _, errs, _ := LoadAll(pack(r)); len(errs) != 1 || errs[0].Check != "compile" {
		t.Fatalf("%v", errs)
	}
}

func TestBundledLoadsClean(t *testing.T) {
	if _, errs, err := LoadAll(Bundled()); err != nil || len(errs) != 0 {
		t.Fatalf("%v %v", errs, err)
	}
}
