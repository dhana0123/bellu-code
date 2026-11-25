package cvesource

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/cvelocal"
	"github.com/bellu/bellucode/services/bellud/internal/intel/model"
	"github.com/bellu/bellucode/services/bellud/internal/intel/store"
	"github.com/bellu/bellucode/services/bellud/internal/testutil/noexternal"
	_ "modernc.org/sqlite"
)

func TestMain(m *testing.M) { noexternal.Main(m) }

var now = time.Date(2024, 6, 10, 12, 0, 0, 0, time.UTC)

var testVulns = []model.Vuln{
	{
		ID: "CVE-2024-1000", Aliases: []string{"GHSA-aaaa-bbbb-cccc"}, Summary: "lodash pollution",
		Severity: model.SevHigh, CVSS: model.CVSS{Vector: "CVSS:3.1/AV:N", Score: 7.5, Version: "3.1"},
		KnownExploited: true, EPSS: 0.42,
		Affected: []model.AffectedPackage{{Purl: "pkg:npm/lodash", Ranges: []model.SemverRange{{Introduced: "0", Fixed: "4.17.21"}}, FixedIn: []string{"4.17.21"}}},
	},
	{ID: "CVE-2021-44228", Summary: "db log4j", Severity: model.SevCritical},
	{ID: "CVE-2024-2000", Summary: "all versions", Affected: []model.AffectedPackage{{Purl: "pkg:npm/leftpad"}}},
}

func newStore(t *testing.T, created time.Time) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "intel"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	var sb strings.Builder
	for _, v := range testVulns {
		b, _ := json.Marshal(v)
		sb.Write(b)
		sb.WriteByte('\n')
	}
	if err := s.Replace(context.Background(), store.ImportInfo{Version: "v1", CreatedAt: created}, strings.NewReader(sb.String())); err != nil {
		t.Fatal(err)
	}
	return s
}

func newSource(t *testing.T, created time.Time) *DB {
	t.Helper()
	d, err := New(Options{Store: newStore(t, created), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func ids(r Result[[]Vuln]) []string {
	out := []string{}
	for _, v := range r.Data {
		out = append(out, v.ID)
	}
	return out
}

func TestLookupByIDAndAlias(t *testing.T) {
	d := newSource(t, now.Add(-time.Hour))
	for _, id := range []string{"CVE-2024-1000", "GHSA-aaaa-bbbb-cccc"} {
		r, err := d.Lookup(context.Background(), LookupQuery{ID: id})
		if err != nil || len(r.Data) != 1 {
			t.Fatalf("%s: %+v %v", id, r, err)
		}
		v := r.Data[0]
		if v.ID != "CVE-2024-1000" || v.Severity != "high" || v.CVSSScore != 7.5 || v.CVSSVector == "" ||
			!v.KEV || v.EPSS != 0.42 || len(v.Aliases) != 1 || len(v.Ranges) != 1 ||
			len(v.FixedVersions) != 1 || v.FixedVersions[0] != "4.17.21" || v.Origin != OriginIntelStore {
			t.Fatalf("%+v", v)
		}
		if len(r.Warnings) != 0 || r.FieldFrom["lookup"] != ModeDB {
			t.Fatalf("%+v", r)
		}
	}
}

func TestLookupByPurlVersion(t *testing.T) {
	d := newSource(t, now)
	ctx := context.Background()
	r, err := d.Lookup(ctx, LookupQuery{Purl: "pkg:npm/lodash@4.17.0"})
	if err != nil || len(r.Data) != 1 || r.Data[0].AffectedState != StateAffected {
		t.Fatalf("affected: %+v %v", r, err)
	}
	r, err = d.Lookup(ctx, LookupQuery{Purl: "pkg:npm/lodash", Version: "4.17.21"})
	if err != nil || len(r.Data) != 0 || r.Data == nil {
		t.Fatalf("not affected: %+v %v", r, err)
	}
	r, err = d.Lookup(ctx, LookupQuery{Purl: "pkg:npm/lodash"})
	if err != nil || len(r.Data) != 1 || r.Data[0].AffectedState != StateUnknown {
		t.Fatalf("unknown: %+v %v", r, err)
	}
	r, _ = d.Lookup(ctx, LookupQuery{Purl: "pkg:npm/leftpad@1.0.0?arch=x"})
	if got := ids(r); len(got) != 1 || got[0] != "CVE-2024-2000" {
		t.Fatalf("no ranges: %v", got)
	}
	if _, err := d.Lookup(ctx, LookupQuery{Purl: "lodash@1"}); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("bad purl: %v", err)
	}
}

func TestLookupByCPE(t *testing.T) {
	d := newSource(t, now)
	ctx := context.Background()
	for _, c := range []string{"cpe:2.3:a:lodash:lodash:4.17.0:*:*:*:*:*:*:*", "cpe:/a:lodash:lodash:4.17.0"} {
		r, err := d.Lookup(ctx, LookupQuery{CPE: c})
		if err != nil || len(r.Data) != 0 || len(r.Warnings) != 1 || r.Warnings[0].Code != WarnCPENotIndexd {
			t.Fatalf("%s: %+v %v", c, r, err)
		}
	}
	for _, c := range []string{"cpe:2.3:a:x", "cpe:2.3:z:v:p:1:*:*:*:*:*:*:*", "nope"} {
		if _, err := d.Lookup(ctx, LookupQuery{CPE: c}); !errors.Is(err, ErrInvalidQuery) {
			t.Fatalf("%s: %v", c, err)
		}
	}
}

func TestLookupEmptyAndInvalid(t *testing.T) {
	d := newSource(t, now)
	r, err := d.Lookup(context.Background(), LookupQuery{ID: "CVE-1999-0001"})
	if err != nil || r.Data == nil || len(r.Data) != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	for _, q := range []LookupQuery{{}, {ID: "a", Purl: "pkg:npm/x"}} {
		if _, err := d.Lookup(context.Background(), q); !errors.Is(err, ErrInvalidQuery) {
			t.Fatalf("%+v: %v", q, err)
		}
	}
}

func TestStaleAndMissingWarnings(t *testing.T) {
	d := newSource(t, now.Add(-10*24*time.Hour-3*time.Hour))
	r, err := d.Lookup(context.Background(), LookupQuery{ID: "CVE-2024-1000"})
	if err != nil || len(r.Data) != 1 || len(r.Warnings) != 1 || r.Warnings[0].Code != WarnStaleDB ||
		!strings.Contains(r.Warnings[0].Message, "10 days") {
		t.Fatalf("%+v %v", r, err)
	}
	if st := d.Status(); !st.DBInstalled || !st.DBStale || st.DBAge != 243*time.Hour {
		t.Fatalf("%+v", st)
	}

	empty, _ := New(Options{Now: func() time.Time { return now }})
	r, err = empty.Lookup(context.Background(), LookupQuery{ID: "CVE-2024-1000"})
	if err != nil || len(r.Data) != 0 || len(r.Warnings) != 1 || r.Warnings[0].Code != WarnMissingDB {
		t.Fatalf("%+v %v", r, err)
	}
	if st := empty.Status(); st.DBInstalled || st.Mode != ModeDB {
		t.Fatalf("%+v", st)
	}
}

func TestModeValidationKeepsPrevious(t *testing.T) {
	d := newSource(t, now)
	if d.Mode() != ModeDB {
		t.Fatalf("default %q", d.Mode())
	}
	if err := d.SetMode("both"); err != nil || d.Mode() != ModeBoth {
		t.Fatalf("%v %q", err, d.Mode())
	}
	err := d.SetMode("sideways")
	if err == nil || d.Mode() != ModeBoth || d.Status().Mode != ModeBoth {
		t.Fatalf("%v %q", err, d.Mode())
	}
	for _, w := range []string{"cve.mode", "db", "graph", "both"} {
		if !strings.Contains(err.Error(), w) {
			t.Fatalf("%q lacks %q", err, w)
		}
	}
	if _, err := New(Options{Mode: "x"}); err == nil || !strings.Contains(err.Error(), "cve.mode") {
		t.Fatalf("%v", err)
	}
}

func TestGraphAndDetailReportGap(t *testing.T) {
	d := newSource(t, now)
	ctx := context.Background()
	if _, err := d.Graph(ctx, GraphQuery{ID: "CVE-2024-1000"}); !errors.Is(err, ErrGraphModeDisabled) {
		t.Fatalf("%v", err)
	}
	_ = d.SetMode("graph")
	g, err := d.Graph(ctx, GraphQuery{ID: "CVE-2024-1000"})
	if err != nil || len(g.Gaps) != 1 || g.Gaps[0] != (Gap{GapGraphUnavailable, CauseNotConfigured}) {
		t.Fatalf("%+v %v", g, err)
	}
	if st := d.Status(); st.LastGap == nil || st.LastGap.Cause != CauseNotConfigured || st.BSKGReachable {
		t.Fatalf("%+v", st)
	}
	det, err := d.Detail(ctx, "CVE-2024-1000", ModeBoth)
	if err != nil || det.Data.Vuln.ID != "CVE-2024-1000" || len(det.Gaps) != 1 || det.FieldFrom["detail"] != ModeDB {
		t.Fatalf("both keeps db data: %+v %v", det, err)
	}
	det, _ = d.Detail(ctx, "CVE-2024-1000", ModeGraph)
	if det.Data.Vuln.ID != "CVE-2024-1000" || len(det.Gaps) != 1 || det.FieldFrom["detail"] != ModeDB {
		t.Fatalf("graph: %+v", det)
	}
	if _, err := d.Detail(ctx, "CVE-2024-1000", "x"); err == nil {
		t.Fatal("bad mode accepted")
	}
}

// installGraph writes a minimal Local_CVE_Graph snapshot and opens it.
func installGraph(t *testing.T) *cvelocal.Source {
	t.Helper()
	dir := t.TempDir()
	snap := filepath.Join(dir, "snapshots", "snap-1")
	if err := os.MkdirAll(snap, 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(snap, "graph.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{
		`CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		`CREATE TABLE nodes(id TEXT PRIMARY KEY, type TEXT NOT NULL, props TEXT NOT NULL, h TEXT NOT NULL)`,
		`CREATE TABLE edges(id TEXT PRIMARY KEY, type TEXT NOT NULL, src TEXT NOT NULL, dst TEXT NOT NULL, props TEXT NOT NULL, h TEXT NOT NULL)`,
		`CREATE INDEX edges_dst ON edges(dst, type)`,
		`CREATE INDEX edges_src_type ON edges(src, type)`,
		`CREATE INDEX nodes_type ON nodes(type)`,
		`CREATE TABLE history(entity_id TEXT, version INTEGER, event_time TEXT, recorded_at TEXT, state TEXT, payload TEXT)`,
		`INSERT INTO meta VALUES('schema_version','1'),('created_at','2024-06-09T00:00:00Z'),('has_history','false')`,
		`INSERT INTO nodes VALUES('vuln:CVE-2024-3000','Vulnerability','{"summary":"libfoo overflow","trust_state":"trusted"}','')`,
		`INSERT INTO nodes VALUES('pkg:pypi/foo','Package','{"ecosystem":"PyPI","name":"foo"}','')`,
		`INSERT INTO edges VALUES('1','AFFECTS','vuln:CVE-2024-3000','pkg:pypi/foo','{"status":"trusted","entries":[{"source":"osv","scheme":"generic","versions":["1.0.0"],"fixed":"1.0.1"}]}','')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join("snapshots", "snap-1"), filepath.Join(dir, "current")); err != nil {
		t.Fatal(err)
	}
	g, err := cvelocal.Open(dir, cvelocal.WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close() })
	return g
}

func TestSecondSourceCVEGraph(t *testing.T) {
	d, err := New(Options{Store: newStore(t, now), Graph: installGraph(t), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	r, err := d.Lookup(ctx, LookupQuery{Purl: "pkg:pypi/foo@1.0.0"})
	if err != nil || len(r.Data) != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	v := r.Data[0]
	if v.ID != "CVE-2024-3000" || v.Origin != OriginCVEGraph || v.AffectedState != StateAffected ||
		len(v.FixedVersions) != 1 || v.FixedVersions[0] != "1.0.1" {
		t.Fatalf("%+v", v)
	}
	r, _ = d.Lookup(ctx, LookupQuery{ID: "CVE-2024-3000"})
	if len(r.Data) != 1 || r.Data[0].Origin != OriginCVEGraph {
		t.Fatalf("by id: %+v", r)
	}
	r, _ = d.Lookup(ctx, LookupQuery{Purl: "pkg:pypi/foo@1.0.1"})
	if len(r.Data) != 0 {
		t.Fatalf("fixed version matched: %+v", r)
	}
}
