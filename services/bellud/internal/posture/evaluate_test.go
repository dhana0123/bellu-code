package posture

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/facade"
	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
)

type evalFixture struct {
	eng *Engine
	g   graph.Engine
	db  *sqlite.Store
	fs  *findings.Store
	ids map[string]facade.EntityID
	os  map[string]string
}

const bad = "package bellu.p.r1\nimport rego.v1\nviolation contains {\"evidence\": {\"b\": \"2\", \"a\": \"1\"}} if input.attributes.os == \"bad\"\n"

func newEvalFixture(t *testing.T, version string) *evalFixture {
	t.Helper()
	ctx := context.Background()
	db, err := sqlite.Open(ctx, t.TempDir(), "ws1", sqlite.Options{Migrations: sqlitemigrations.FS})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	fst := findings.New(db)
	t.Cleanup(fst.Close)
	g, err := graph.Open(ctx, graph.Config{Enabled: true, Dir: filepath.Join(t.TempDir(), "g"), Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close(ctx) })
	f := &evalFixture{g: g, db: db, fs: fst, ids: map[string]facade.EntityID{}, os: map[string]string{}}
	f.eng = f.engine(t, version)
	return f
}

func (f *evalFixture) engine(t *testing.T, version string) *Engine {
	t.Helper()
	pack := Pack{ID: "p", Version: version, Source: fstest.MapFS{"r1.rego": {Data: []byte(bad)}},
		Rules: []Rule{{ID: "r1", Title: "bad os", Severity: findings.SevHigh, Category: "cloud_infrastructure", AppliesTo: []string{"host"}, Kind: KindPosture, Rego: "r1.rego"}}}
	e, errs := NewEngine(context.Background(), []Pack{pack}, f.g.Query())
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	e.Configure(f.db, func(ctx context.Context) FindingsSink { return f.fs.JobSink(ctx, findings.ScanRef{JobID: "j"}) })
	e.run.backoff = nil
	return e
}

// setHost records the host and re-sends all hosts, since each Apply is a full
// observation of the collector.
func (f *evalFixture) setHost(t *testing.T, name, os string) {
	t.Helper()
	f.os[name] = os
	var es []batch.Entity
	for n, o := range f.os {
		es = append(es, batch.Entity{Type: "host", Identity: map[string]string{"hostname": n}, Attributes: map[string]any{"os": o}})
	}
	if _, err := f.g.Ingest().Apply(context.Background(), batch.Batch{Collector: "host", Entities: es}); err != nil {
		t.Fatal(err)
	}
	id, _ := identity.Hash("host", map[string]string{"hostname": name})
	f.ids[name] = facade.EntityID(id)
}

func (f *evalFixture) open(t *testing.T) []findings.Finding {
	t.Helper()
	pg, err := f.fs.List(context.Background(), findings.ListQuery{Statuses: []findings.Status{findings.StatusOpen}, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	return pg.Items
}

func (f *evalFixture) evalRows(t *testing.T, result string) int {
	var n int
	if err := f.db.DB().QueryRow(`SELECT COUNT(*) FROM posture_eval WHERE result=?`, result).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestFullRunCreatesThenResolves(t *testing.T) {
	ctx := context.Background()
	f := newEvalFixture(t, "1")
	f.setHost(t, "h1", "bad")
	f.setHost(t, "h2", "good")
	sum, err := f.eng.Evaluate(ctx, Scope{Full: true})
	if err != nil || sum.Entities != 2 || sum.Findings != 1 {
		t.Fatalf("%+v %v", sum, err)
	}
	got := f.open(t)
	if len(got) != 1 || got[0].Source != "posture:p" || got[0].RulePackVersion != "1" || got[0].Type != findings.TypeMisconfiguration ||
		got[0].AssetID != string(f.ids["h1"]) || len(got[0].Evidence) != 3 || got[0].Evidence[1].Ref != "a" {
		t.Fatalf("%+v", got)
	}
	if f.evalRows(t, "fail") != 1 || f.evalRows(t, "pass") != 1 {
		t.Fatal("posture_eval rows")
	}
	f.setHost(t, "h1", "good")
	if sum, err = f.eng.Evaluate(ctx, Scope{Full: true}); err != nil || sum.Resolved != 1 || len(f.open(t)) != 0 {
		t.Fatalf("%+v %v", sum, err)
	}
	if f.evalRows(t, "fail") != 0 || f.evalRows(t, "pass") != 2 {
		t.Fatal("posture_eval rows after fix")
	}
}

func TestDisabledRuleAndOverridePrecedence(t *testing.T) {
	ctx := context.Background()
	f := newEvalFixture(t, "1")
	f.setHost(t, "h1", "bad")
	yes, no := true, false
	low, crit := findings.SevLow, findings.SevCritical
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	// pack disabled, rule enabled: the rule wins, with the pack severity override
	must(f.eng.SetOverride(ctx, Override{PackID: "p", Enabled: &no, Severity: &low}))
	must(f.eng.SetOverride(ctx, Override{PackID: "p", RuleID: "r1", Enabled: &yes}))
	if _, err := f.eng.Evaluate(ctx, Scope{Full: true}); err != nil {
		t.Fatal(err)
	}
	if got := f.open(t); len(got) != 1 || got[0].Severity != findings.SevLow {
		t.Fatalf("%+v", got)
	}
	// rule severity beats pack severity
	must(f.eng.SetOverride(ctx, Override{PackID: "p", RuleID: "r1", Enabled: &yes, Severity: &crit}))
	if _, err := f.eng.Evaluate(ctx, Scope{Full: true}); err != nil {
		t.Fatal(err)
	}
	if got := f.open(t); len(got) != 1 || got[0].Severity != findings.SevCritical {
		t.Fatalf("%+v", got)
	}
	// rule disabled: no findings, existing one resolved, no posture_eval rows
	must(f.eng.SetOverride(ctx, Override{PackID: "p", RuleID: "r1", Enabled: &no}))
	if sum, err := f.eng.Evaluate(ctx, Scope{Full: true}); err != nil || sum.Findings != 0 || len(f.open(t)) != 0 {
		t.Fatalf("%+v %v", sum, err)
	}
	if f.evalRows(t, "fail")+f.evalRows(t, "pass") != 0 {
		t.Fatal("rows for disabled rule")
	}
}

func TestIncrementalScopeAndVersionChange(t *testing.T) {
	ctx := context.Background()
	f := newEvalFixture(t, "1")
	for _, h := range []string{"h1", "h2", "h3"} {
		f.setHost(t, h, "bad")
	}
	// a finding entity affects h2 only
	fid, _ := identity.Hash("finding", map[string]string{"id": "x"})
	if _, err := f.g.Ingest().Apply(ctx, batch.Batch{Collector: "f", Entities: []batch.Entity{
		{Type: "finding", Identity: map[string]string{"id": "x"}}},
		Relations: []batch.Relation{{Type: "affects", From: string(fid), To: string(f.ids["h2"])}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.eng.Evaluate(ctx, Scope{Full: true}); err != nil {
		t.Fatal(err)
	}
	f.db.DB().Exec(`UPDATE posture_eval SET result='pass'`) // marker: only re-evaluated rows turn back to fail
	sum, err := f.eng.Evaluate(ctx, Scope{Changed: []facade.EntityID{facade.EntityID(fid)}})
	if err != nil || sum.Full || sum.Entities != 1 || f.evalRows(t, "fail") != 1 {
		t.Fatalf("%+v %v fail=%d", sum, err, f.evalRows(t, "fail"))
	}
	// a new pack version forces a full run even for an incremental scope
	e2 := f.engine(t, "2")
	sum, err = e2.Evaluate(ctx, Scope{Changed: []facade.EntityID{facade.EntityID(fid)}})
	if err != nil || !sum.Full || sum.Entities != 3 {
		t.Fatalf("%+v %v", sum, err)
	}
	for _, x := range f.open(t) {
		if x.RulePackVersion != "2" {
			t.Fatalf("version %s", x.RulePackVersion)
		}
	}
}
