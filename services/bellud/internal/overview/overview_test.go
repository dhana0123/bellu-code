package overview

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/facade"
	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schemaall"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
)

type env struct {
	svc *Service
	eng facade.Engine
	fs  *findings.Store
	db  *sqlite.Store
	clk *time.Time
}

func newEnv(t *testing.T) env {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	eng, err := facade.Open(ctx, facade.Config{Enabled: true, Dir: filepath.Join(t.TempDir(), "g")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); eng.Close(context.Background()) })
	db, err := sqlite.Open(ctx, t.TempDir(), "ws1", sqlite.Options{Migrations: sqlitemigrations.FS})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	fs := findings.New(db)
	t.Cleanup(fs.Close)
	reg, err := schemaall.Default()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	svc := New(eng, reg, fs, db.DB(), "ws1", WithClock(func() time.Time { return now }))
	if err := svc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return env{svc, eng, fs, db, &now}
}

func (e env) addAWS(t *testing.T, collector string, types ...string) {
	t.Helper()
	b := batch.Batch{Collector: collector, ObservedAt: time.Now().UTC()}
	for i, typ := range types {
		b.Entities = append(b.Entities, batch.Entity{Type: "aws_resource",
			Identity:   map[string]string{"connection": "c1", "arn": collector + typ + string(rune('a'+i))},
			Attributes: map[string]any{"resource_type": typ}})
	}
	if _, err := e.eng.Ingest().Apply(context.Background(), b); err != nil {
		t.Fatal(err)
	}
}

func (e env) card(t *testing.T, c schema.OverviewCategory) (CategorySummary, uint64) {
	t.Helper()
	s, err := e.svc.Summaries(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range s.Categories {
		if x.Category == c {
			return x, s.Revision
		}
	}
	t.Fatalf("no card %s", c)
	return CategorySummary{}, 0
}

func TestNineCardsInOrderEmptyStates(t *testing.T) {
	e := newEnv(t)
	s, err := e.svc.Summaries(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Categories) != 9 {
		t.Fatalf("%d cards", len(s.Categories))
	}
	for i, c := range s.Categories {
		if c.Category != schema.OverviewOrder[i] || c.Title == "" || c.Subtitle == "" {
			t.Errorf("%d: %+v", i, c)
		}
		if len(c.Severity) != 5 {
			t.Errorf("%s: severity keys %v", c.Category, c.Severity)
		}
		for _, v := range findings.AllSeverities {
			if n, ok := c.Severity[v]; !ok || n != 0 {
				t.Errorf("%s %s: %d %v", c.Category, v, n, ok)
			}
		}
		if c.TopIssues == nil || len(c.TopIssues) != 0 {
			t.Errorf("%s: top issues %v", c.Category, c.TopIssues)
		}
		want := SourceConnector
		if scannerFed[c.Category] {
			want = SourceScanner
		}
		if c.EmptyState == nil || c.EmptyState.MissingSource != want || c.EmptyState.SetupLink != "/security/connectors" {
			t.Errorf("%s: empty state %+v", c.Category, c.EmptyState)
		}
	}
}

func TestCountWithTypeOverridesAndRevision(t *testing.T) {
	e := newEnv(t)
	_, rev0 := e.card(t, schema.OvCloud)
	e.addAWS(t, "aws", "ec2:instance", "ec2:instance", "s3:bucket", "iam:role")
	e.svc.Refresh()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, _ := e.card(t, schema.OvCloud)
		if c.EntityCount == 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cloud, rev1 := e.card(t, schema.OvCloud)
	data, _ := e.card(t, schema.OvData)
	ident, _ := e.card(t, schema.OvIdentity)
	if cloud.EntityCount != 2 || data.EntityCount != 1 || ident.EntityCount != 1 {
		t.Fatalf("cloud=%d data=%d identity=%d", cloud.EntityCount, data.EntityCount, ident.EntityCount)
	}
	if cloud.EmptyState != nil || data.EmptyState != nil {
		t.Error("empty state on populated card")
	}
	if rev1 <= rev0 {
		t.Errorf("revision %d -> %d", rev0, rev1)
	}
	if _, rev2 := e.card(t, schema.OvCloud); rev2 != rev1 {
		t.Errorf("revision moved without change: %d -> %d", rev1, rev2)
	}
}

func TestSeverityAndTopIssuesCachedFor5s(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.fs.Report(ctx, findings.ScanRef{JobID: "j1"}, []findings.Finding{
		{ID: "f1", RuleID: "r", Title: "t", Category: schema.OvVuln, Type: findings.TypeVulnerability, Severity: findings.SevCritical, AssetID: "a", Source: "grype"},
		{ID: "f2", RuleID: "r", Title: "t", Category: schema.OvVuln, Type: findings.TypeVulnerability, Severity: findings.SevLow, AssetID: "b", Source: "grype"},
	}); err != nil {
		t.Fatal(err)
	}
	for i, r := range []float64{10, 90, 50, 70, 20} {
		_, err := e.db.DB().Exec(`INSERT INTO issue(id,workspace_id,rule_id,title,severity,risk_score,status,category,path,created_at,updated_at)
			VALUES(?,?,?,?,?,?,?,?,'[]','t','t')`, "i"+string(rune('0'+i)), "ws1", "r", "issue", "high", r, "open", string(schema.OvVuln))
		if err != nil {
			t.Fatal(err)
		}
	}
	e.db.DB().Exec(`INSERT INTO issue(id,workspace_id,rule_id,title,severity,risk_score,status,category,path,created_at,updated_at)
		VALUES('ign','ws1','r','x','high',99,'ignored','vulnerabilities','[]','t','t')`)
	v, _ := e.card(t, schema.OvVuln)
	if v.Severity[findings.SevCritical] != 1 || v.Severity[findings.SevLow] != 1 || v.Severity[findings.SevHigh] != 0 {
		t.Fatalf("severity %v", v.Severity)
	}
	if len(v.TopIssues) != 3 || v.TopIssues[0].RiskScore != 90 || v.TopIssues[1].RiskScore != 70 || v.TopIssues[2].RiskScore != 50 {
		t.Fatalf("top issues %+v", v.TopIssues)
	}
	// Cached: a new finding is invisible until 5 s pass.
	if _, err := e.fs.Report(ctx, findings.ScanRef{JobID: "j2"}, []findings.Finding{
		{ID: "f3", RuleID: "r", Title: "t", Category: schema.OvVuln, Type: findings.TypeVulnerability, Severity: findings.SevHigh, AssetID: "c", Source: "grype"},
	}); err != nil {
		t.Fatal(err)
	}
	*e.clk = e.clk.Add(CacheTTL - time.Millisecond)
	if v, _ = e.card(t, schema.OvVuln); v.Severity[findings.SevHigh] != 0 {
		t.Fatal("cache not used")
	}
	*e.clk = e.clk.Add(time.Millisecond)
	v, rev := e.card(t, schema.OvVuln)
	if v.Severity[findings.SevHigh] != 1 {
		t.Fatalf("cache not refreshed: %v", v.Severity)
	}
	if _, r0 := e.card(t, schema.OvCloud); r0 != rev {
		t.Errorf("revision unstable: %d vs %d", rev, r0)
	}
}

func TestSummariesBeforeStart(t *testing.T) {
	if _, err := (&Service{}).Summaries(context.Background()); err != ErrNotStarted {
		t.Fatal(err)
	}
}

// Without findings or a database the service still serves nine cards with zero
// severity counts and no top issues.
func TestSummariesNilFindingsAndDB(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eng, err := facade.Open(ctx, facade.Config{Enabled: true, Dir: filepath.Join(t.TempDir(), "g")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); eng.Close(context.Background()) }()
	reg, err := schemaall.Default()
	if err != nil {
		t.Fatal(err)
	}
	svc := New(eng, reg, nil, nil, "ws1")
	if err := svc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	s, err := svc.Summaries(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Categories) != 9 {
		t.Fatalf("%d cards", len(s.Categories))
	}
	for _, c := range s.Categories {
		for _, v := range findings.AllSeverities {
			if n, ok := c.Severity[v]; !ok || n != 0 {
				t.Errorf("%s severity %s = %d (present %v)", c.Category, v, n, ok)
			}
		}
		if len(c.TopIssues) != 0 {
			t.Errorf("%s has top issues", c.Category)
		}
	}
}
