package issues

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"testing"
	"testing/fstest"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/facade"
	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
	"github.com/bellu/bellucode/services/bellud/internal/posture"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
)

type failReader struct {
	posture.GraphReader
	fail bool
}

func (f *failReader) Neighbors(ctx context.Context, id facade.EntityID, o facade.NeighborOpts) (facade.Page[facade.Edge], error) {
	if f.fail {
		return facade.Page[facade.Edge]{}, errors.New("graph down")
	}
	return f.GraphReader.Neighbors(ctx, id, o)
}

type rfix struct {
	g      graph.Engine
	fs     *findings.Store
	re     *Reevaluator
	rd     *failReader
	host   facade.EntityID
	finder facade.EntityID
}

func newRFix(t *testing.T) *rfix {
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
	h, _ := identity.Hash("host", map[string]string{"hostname": "h1"})
	x, _ := identity.Hash("finding", map[string]string{"id": "x"})
	rego := fmt.Sprintf("package bellu.p.tc\nimport rego.v1\nviolation contains {\"path\": [{\"entity\": %q, \"relation\": \"affects\"}, {\"entity\": input.id}]} if input.attributes.os == \"bad\"\n", string(x))
	pack := posture.Pack{ID: "p", Version: "1", Source: fstest.MapFS{"tc.rego": {Data: []byte(rego)}},
		Rules: []posture.Rule{{ID: "tc", Title: "toxic", Severity: findings.SevHigh, Category: "cloud_infrastructure", AppliesTo: []string{"host"}, Kind: posture.KindToxicCombination, Rego: "tc.rego"}}}
	eng, errs := posture.NewEngine(ctx, []posture.Pack{pack}, g.Query())
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	rd := &failReader{GraphReader: g.Query()}
	f := &rfix{g: g, fs: fst, rd: rd, host: facade.EntityID(h), finder: facade.EntityID(x)}
	f.re = &Reevaluator{Engine: eng, Reader: rd, Store: New(db), Finds: fst, Packs: []posture.Pack{pack},
		Retries: 1, Backoff: []time.Duration{time.Millisecond}, Debounce: 20 * time.Millisecond}
	return f
}

func (f *rfix) setOS(t *testing.T, os string) {
	t.Helper()
	_, err := f.g.Ingest().Apply(context.Background(), batch.Batch{Collector: "c",
		Entities: []batch.Entity{
			{Type: "host", Identity: map[string]string{"hostname": "h1"}, Attributes: map[string]any{"os": os}},
			{Type: "finding", Identity: map[string]string{"id": "x"}}},
		Relations: []batch.Relation{{Type: "affects", From: string(f.finder), To: string(f.host),
			Attributes: map[string]any{"evidence": "ev1", "confidence": "extracted"}}}})
	if err != nil {
		t.Fatal(err)
	}
}

func (f *rfix) report(t *testing.T) {
	t.Helper()
	_, err := f.fs.Report(context.Background(), findings.ScanRef{JobID: "j"}, []findings.Finding{{
		ID: "f1", RuleID: "r", Title: "t", Category: "cloud_infrastructure", Type: findings.TypeMisconfiguration,
		Severity: findings.SevHigh, Status: findings.StatusOpen, AssetID: string(f.host), Source: "s"}})
	if err != nil {
		t.Fatal(err)
	}
}

func (f *rfix) list(t *testing.T, st Status) []Issue {
	t.Helper()
	l, err := f.re.Store.List(context.Background(), Query{Statuses: []Status{st}})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestReevaluateCreatesAndResolves(t *testing.T) {
	ctx := context.Background()
	f := newRFix(t)
	f.setOS(t, "bad")
	f.report(t)
	sum, err := f.re.Reevaluate(ctx, posture.Scope{Full: true})
	if err != nil || sum.Upserted != 1 || len(f.list(t, StatusOpen)) != 1 {
		t.Fatalf("%+v %v", sum, err)
	}
	f.setOS(t, "good")
	sum, err = f.re.Reevaluate(ctx, posture.Scope{Changed: []facade.EntityID{f.host}})
	if err != nil || sum.Resolved != 1 || len(f.list(t, StatusOpen)) != 0 || len(f.list(t, StatusResolved)) != 1 {
		t.Fatalf("%+v %v", sum, err)
	}
	f.setOS(t, "bad") // the condition returns: the Issue reopens
	if _, err = f.re.Reevaluate(ctx, posture.Scope{Full: true}); err != nil || len(f.list(t, StatusOpen)) != 1 {
		t.Fatalf("reopen: %v", err)
	}
}

func TestFailureLeavesIssuesUnchanged(t *testing.T) {
	ctx := context.Background()
	f := newRFix(t)
	f.setOS(t, "bad")
	f.report(t)
	if _, err := f.re.Reevaluate(ctx, posture.Scope{Full: true}); err != nil {
		t.Fatal(err)
	}
	f.setOS(t, "good")
	f.rd.fail = true
	f.re.Reader = f.rd
	// Source reads fail while evaluating the (changed) scope.
	_, err := f.re.Reevaluate(ctx, posture.Scope{Changed: []facade.EntityID{f.host}})
	if err == nil || !f.re.Last().Failed || f.re.Last().Attempts != 2 || len(f.list(t, StatusOpen)) != 1 {
		t.Fatalf("err=%v last=%+v", err, f.re.Last())
	}
	f.rd.fail = false
	if _, err := f.re.Reevaluate(ctx, posture.Scope{Changed: []facade.EntityID{f.host}}); err != nil || f.re.Last().Failed || len(f.list(t, StatusOpen)) != 0 {
		t.Fatalf("recover: %v", err)
	}
}

func TestMemberFindingResolveTriggersReevaluation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := newRFix(t)
	f.setOS(t, "bad")
	f.report(t)
	if _, err := f.re.Reevaluate(ctx, posture.Scope{Full: true}); err != nil {
		t.Fatal(err)
	}
	go f.re.Watch(ctx)
	time.Sleep(50 * time.Millisecond) // let Watch subscribe
	if n, err := f.fs.ResolveMissing(ctx, findings.ScanRef{JobID: "j2"}, string(f.host), "s", map[string]struct{}{}); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(f.list(t, StatusResolved)) == 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("issue not resolved after its member finding resolved")
}
