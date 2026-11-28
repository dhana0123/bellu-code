package rules

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/posture"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
)

const rego = "package bellu.p.r1\nimport rego.v1\nviolation contains {} if input.attributes.os == \"bad\"\n"

func setup(t *testing.T) (http.Handler, *sqlite.Store) {
	t.Helper()
	ctx := context.Background()
	db, err := sqlite.Open(ctx, t.TempDir(), "ws1", sqlite.Options{Migrations: sqlitemigrations.FS})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	rule := func(id string, bm ...string) posture.Rule {
		return posture.Rule{ID: id, Title: id, Severity: findings.SevHigh, Category: "cloud_infrastructure", AppliesTo: []string{"host"}, Benchmarks: bm, Kind: posture.KindPosture, Rego: "r.rego"}
	}
	pack := posture.Pack{ID: "p", Version: "7", Source: fstest.MapFS{"r.rego": {Data: []byte(rego)}}, Rules: []posture.Rule{rule("r1", "CIS:1.1"), rule("r2", "CIS:1.2")}}
	e, errs := posture.NewEngine(ctx, []posture.Pack{pack}, nil)
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	e.Configure(db, nil)
	return New(e, e, true), db
}

func do(h http.Handler, method, target, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(method, target, strings.NewReader(body)))
	return w
}

func ruleStates(t *testing.T, h http.Handler) map[string]wireRule {
	t.Helper()
	w := do(h, "GET", Prefix+"/packs/p/rules", "")
	var b struct{ Items []wireRule }
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil || w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	m := map[string]wireRule{}
	for _, r := range b.Items {
		m[r.ID] = r
	}
	return m
}

func TestOverridePrecedenceRoundTripAndAudit(t *testing.T) {
	h, db := setup(t)
	var packs struct{ Items []wirePack }
	if w := do(h, "GET", Prefix+"/packs", ""); json.Unmarshal(w.Body.Bytes(), &packs) != nil ||
		len(packs.Items) != 1 || packs.Items[0].Version != "7" || !packs.Items[0].Enabled || packs.Items[0].RuleCount != 2 {
		t.Fatalf("%s", w.Body)
	}
	// Pack disabled: both rules off.
	if w := do(h, "PUT", Prefix+"/overrides", `{"packId":"p","enabled":false}`); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if s := ruleStates(t, h); s["r1"].Enabled || s["r2"].Enabled {
		t.Fatalf("%+v", s)
	}
	// A rule setting beats the pack setting; severity override too.
	if w := do(h, "PUT", Prefix+"/overrides", `{"packId":"p","ruleId":"r1","enabled":true,"severity":"low"}`); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	s := ruleStates(t, h)
	if !s["r1"].Enabled || s["r1"].Severity != "low" || s["r1"].DefaultSev != "high" || s["r2"].Enabled {
		t.Fatalf("%+v", s)
	}
	for body, field := range map[string]string{`{"packId":"p","severity":"bogus"}`: "severity", `{"packId":""}`: "packId"} {
		if w := do(h, "PUT", Prefix+"/overrides", body); w.Code != 400 || !strings.Contains(w.Body.String(), `"field":"`+field+`"`) {
			t.Fatalf("%s: %d %s", body, w.Code, w.Body)
		}
	}
	if w := do(h, "PUT", Prefix+"/overrides", `{"packId":"nope","enabled":true}`); w.Code != 404 {
		t.Fatalf("%d", w.Code)
	}
	var n int
	if err := db.DB().QueryRow(`SELECT count(*) FROM audit WHERE action='rule.override'`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("audit rows %d %v", n, err)
	}
}

func TestCompliance(t *testing.T) {
	h, db := setup(t)
	var l struct{ Benchmarks []string }
	if w := do(h, "GET", Prefix+"/compliance", ""); json.Unmarshal(w.Body.Bytes(), &l) != nil || len(l.Benchmarks) != 1 || l.Benchmarks[0] != "CIS" {
		t.Fatalf("%s", w.Body)
	}
	if _, err := db.DB().Exec(`INSERT INTO posture_eval (workspace_id, pack_id, rule_id, entity_id, result, pack_version, evaluated_at) VALUES (?,?,?,?,?,?,?)`,
		db.WorkspaceID(), "p", "r1", "h1", "fail", "7", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	var c struct {
		Benchmark string
		Controls  []wireControl
	}
	w := do(h, "GET", Prefix+"/compliance?benchmark=CIS", "")
	if json.Unmarshal(w.Body.Bytes(), &c) != nil || len(c.Controls) != 2 || c.Controls[0] != (wireControl{"1.1", "fail", 1}) || c.Controls[1].Status != "not_applicable" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w := do(h, "GET", Prefix+"/compliance?benchmark=NOPE", ""); w.Code != 404 {
		t.Fatalf("%d", w.Code)
	}
}

func TestFlagOffIs404(t *testing.T) {
	h := New(nil, nil, false)
	for _, c := range [][2]string{{"GET", "/packs"}, {"GET", "/packs/p/rules"}, {"PUT", "/overrides"}, {"GET", "/compliance"}} {
		if w := do(h, c[0], Prefix+c[1], `{}`); w.Code != 404 {
			t.Errorf("%v: %d", c, w.Code)
		}
	}
}
