package cvelocal

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

const ddl = `
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE nodes(id TEXT PRIMARY KEY, type TEXT NOT NULL, props TEXT NOT NULL, h TEXT NOT NULL);
CREATE TABLE edges(id TEXT PRIMARY KEY, type TEXT NOT NULL, src TEXT NOT NULL, dst TEXT NOT NULL, props TEXT NOT NULL, h TEXT NOT NULL);
CREATE INDEX edges_dst ON edges(dst, type);
CREATE INDEX edges_src_type ON edges(src, type);
CREATE INDEX nodes_type ON nodes(type);
CREATE TABLE history(entity_id TEXT, version INTEGER, event_time TEXT, recorded_at TEXT, state TEXT, payload TEXT);`

type edge struct{ typ, src, dst, props string }

var fixtureNodes = [][3]string{
	{"vuln:CVE-2024-1000", "Vulnerability", `{"summary":"Prototype pollution in lodash merge","trust_state":"trusted"}`},
	{"vuln:CVE-2024-2000", "Vulnerability", `{"summary":"Buffer overflow in libfoo parser","trust_state":"trusted"}`},
	{"vuln:CVE-2024-3000", "Vulnerability", `{"summary":"No relations at all","trust_state":"trusted"}`},
	{"src:osv:GHSA-AAAA-BBBB-CCCC", "SourceRecord", `{"kind":"record","source":"osv","external_id":"GHSA-AAAA-BBBB-CCCC"}`},
	{"src:osv:CVE-2024-2000", "SourceRecord", `{"kind":"record","source":"osv","external_id":"CVE-2024-2000"}`},
	{"pkg:npm/lodash", "Package", `{"ecosystem":"npm","name":"lodash"}`},
	{"pkg:pypi/my-lib", "Package", `{"ecosystem":"PyPI","name":"my-lib"}`},
	{"cwe:79", "Weakness", `{"cwe_id":"CWE-79","name":"Cross-site Scripting","description":"Improper neutralization"}`},
	{"cwe:80", "Weakness", `{"cwe_id":"CWE-80"}`},
	{"patch:1", "Patch", `{"url":"https://example.test/fix","source":"osv","fixed_version":"4.17.21"}`},
}

var fixtureEdges = []edge{
	{"ALIAS_OF", "src:osv:GHSA-AAAA-BBBB-CCCC", "vuln:CVE-2024-1000", `{}`},
	{"HAS_SOURCE_RECORD", "vuln:CVE-2024-1000", "src:osv:GHSA-AAAA-BBBB-CCCC", `{}`},
	{"ALIAS_OF", "src:osv:CVE-2024-2000", "vuln:CVE-2024-2000", `{}`},
	{"HAS_SOURCE_RECORD", "vuln:CVE-2024-2000", "src:osv:CVE-2024-2000", `{}`},
	{"AFFECTS", "vuln:CVE-2024-1000", "pkg:npm/lodash", `{"status":"trusted","entries":[{"source":"osv","scheme":"generic","versions":["4.17.0"],"fixed":"4.17.21"}]}`},
	{"CLASSIFIED_AS", "vuln:CVE-2024-1000", "cwe:79", `{}`},
	{"CHILD_OF", "cwe:80", "cwe:79", `{}`},
	{"FIXED_BY", "vuln:CVE-2024-1000", "patch:1", `{}`},
}

// install writes a graph.db under <dir>/snapshots/snap-1 and points current at it.
func install(t *testing.T, withHistory bool) string {
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
	exec := func(q string, a ...any) {
		t.Helper()
		if _, err := db.Exec(q, a...); err != nil {
			t.Fatal(err)
		}
	}
	exec(ddl)
	for k, v := range map[string]string{"schema_version": "1", "created_at": "2024-05-01T00:00:00Z", "has_history": strconv.FormatBool(withHistory)} {
		exec(`INSERT INTO meta VALUES(?,?)`, k, v)
	}
	for _, n := range fixtureNodes {
		exec(`INSERT INTO nodes VALUES(?,?,?,'')`, n[0], n[1], n[2])
	}
	for i, e := range fixtureEdges {
		exec(`INSERT INTO edges VALUES(?,?,?,?,?,'')`, strconv.Itoa(i), e.typ, e.src, e.dst, e.props)
	}
	exec(`INSERT INTO nodes VALUES('exploit:1','Exploit','{"url":"https://example.test/poc","source":"edb"}','')`)
	exec(`INSERT INTO edges VALUES('x1','HAS_EXPLOIT','vuln:CVE-2024-2000','exploit:1','{}','')`)
	rec := func(id, summary string) string {
		return `{"source":"osv","id":"` + id + `","summary":"` + summary + `","published":"2024-01-01T00:00:00Z","modified":"2024-02-01T00:00:00Z","withdrawn":"0001-01-01T00:00:00Z"}`
	}
	exec(`INSERT INTO history VALUES('src:osv:GHSA-AAAA-BBBB-CCCC',1,'','2024-02-01T00:00:00Z','active',?)`, rec("GHSA-AAAA-BBBB-CCCC", "old lodash summary"))
	exec(`INSERT INTO history VALUES('src:osv:CVE-2024-2000',1,'','2024-04-01T00:00:00Z','active',?)`, rec("CVE-2024-2000", "libfoo"))
	if err := os.Symlink(filepath.Join("snapshots", "snap-1"), filepath.Join(dir, "current")); err != nil {
		t.Fatal(err)
	}
	return dir
}

func open(t *testing.T, dir string) *Source {
	t.Helper()
	s, err := Open(dir, WithClock(func() time.Time { return time.Date(2024, 5, 2, 12, 30, 0, 0, time.UTC) }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenNotInstalled(t *testing.T) {
	if _, err := Open(t.TempDir()); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("got %v, want ErrNotInstalled", err)
	}
}

func TestInfo(t *testing.T) {
	i := open(t, install(t, true)).Info()
	if i.SnapshotID != "snap-1" || !i.BuiltAt.Equal(time.Date(2024, 5, 1, 0, 0, 0, 0, time.UTC)) || i.Age != 36*time.Hour {
		t.Fatalf("info %+v", i)
	}
}

func TestByID(t *testing.T) {
	ctx := context.Background()
	s := open(t, install(t, true))
	v, err := s.ByID(ctx, "cve-2024-1000")
	if err != nil || v == nil {
		t.Fatalf("v=%v err=%v", v, err)
	}
	if v.StableID != "bid:vuln:CVE-2024-1000" || v.ID != "CVE-2024-1000" {
		t.Fatalf("ids %q %q", v.StableID, v.ID)
	}
	if len(v.Patches) != 1 || v.Patches[0].FixedVersion != "4.17.21" || len(v.Exploits) != 0 {
		t.Fatalf("patches %+v exploits %+v", v.Patches, v.Exploits)
	}
	if len(v.Weaknesses) != 1 || v.Weaknesses[0].Name != "Cross-site Scripting" {
		t.Fatalf("weaknesses %+v", v.Weaknesses)
	}
	again, _ := s.ByID(ctx, "bid:vuln:CVE-2024-1000")
	if !reflect.DeepEqual(v, again) {
		t.Fatal("not identical across calls and Stable_ID input")
	}
	v2, _ := s.ByID(ctx, "CVE-2024-2000")
	if len(v2.Exploits) != 1 || v2.Patches == nil || len(v2.Patches) != 0 || v2.Weaknesses == nil {
		t.Fatalf("absent lists must be empty, not nil: %+v", v2)
	}
	for _, id := range []string{"GHSA-AAAA-BBBB-CCCC", "CVE-1999-0001"} { // alias, unknown
		if v, err := s.ByID(ctx, id); v != nil || err != nil {
			t.Fatalf("%s: got %v, %v; want empty", id, v, err)
		}
	}
	for _, id := range []string{"", "  ", "CVE 1", strings.Repeat("A", 300)} {
		if _, err := s.ByID(ctx, id); !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "id") {
			t.Fatalf("%q: %v", id, err)
		}
	}
}

func TestByPackage(t *testing.T) {
	ctx := context.Background()
	s := open(t, install(t, true))
	got, err := s.ByPackage(ctx, "pkg:npm/lodash", "4.17.0")
	if err != nil || len(got) != 1 {
		t.Fatalf("got %+v err %v", got, err)
	}
	a := got[0]
	if a.VulnerabilityID != "bid:vuln:CVE-2024-1000" || a.PackageID != "bid:pkg:pkg:npm/lodash" || a.VersionID != "bid:pkg:pkg:npm/lodash@4.17.0" || a.FixedVersion != "4.17.21" {
		t.Fatalf("%+v", a)
	}
	if fromPurl, _ := s.ByPackage(ctx, "PKG:npm/lodash@4.17.0?arch=x", ""); !reflect.DeepEqual(fromPurl, got) {
		t.Fatalf("version taken from purl differs: %+v", fromPurl)
	}
	if none, err := s.ByPackage(ctx, "pkg:npm/lodash", "4.17.21"); err != nil || len(none) != 0 || none == nil {
		t.Fatalf("fixed version: %+v %v", none, err)
	}
	if none, err := s.ByPackage(ctx, "pkg:npm/unknown", "1.0.0"); err != nil || len(none) != 0 {
		t.Fatalf("unknown package: %+v %v", none, err)
	}
	for _, c := range [][2]string{{"", "1"}, {"lodash", "1"}, {"pkg:npm", "1"}, {"pkg:npm/lodash", ""}, {"pkg:npm/lodash", "1 2"}, {"pkg:maven/x", "1"}} {
		if _, err := s.ByPackage(ctx, c[0], c[1]); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("%v: %v", c, err)
		}
	}
}

func TestSearch(t *testing.T) {
	ctx := context.Background()
	s := open(t, install(t, true))
	got, err := s.Search(ctx, "lodash merge", 10)
	if err != nil || len(got) != 1 || got[0].ID != "CVE-2024-1000" || got[0].Relevance <= 0 {
		t.Fatalf("got %+v err %v", got, err)
	}
	got, _ = s.Search(ctx, "in", 10) // matches several summaries and ids
	for i := 1; i < len(got); i++ {
		if got[i-1].Relevance < got[i].Relevance {
			t.Fatalf("not descending: %+v", got)
		}
	}
	if got, _ := s.Search(ctx, "CVE-2024-2000", 10); len(got) == 0 || got[0].ID != "CVE-2024-2000" {
		t.Fatalf("exact id must rank first: %+v", got)
	}
	if got, _ := s.Search(ctx, "in", 1); len(got) != 1 {
		t.Fatalf("limit ignored: %d", len(got))
	}
	if got, err := s.Search(ctx, "%_", 10); err != nil || len(got) != 0 {
		t.Fatalf("LIKE wildcards must be literal: %+v %v", got, err)
	}
	for _, q := range []string{"", "   ", strings.Repeat("a", 501)} {
		if _, err := s.Search(ctx, q, 10); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("%d chars: %v", len(q), err)
		}
	}
	if _, err := s.Search(ctx, "x", 0); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("limit 0: %v", err)
	}
	if _, err := s.Search(ctx, strings.Repeat("a", 500), 1000); err != nil {
		t.Fatalf("500 chars and a large limit are valid: %v", err)
	}
}

func TestSearchCapsAtMax(t *testing.T) {
	dir := install(t, false)
	db, _ := sql.Open("sqlite", filepath.Join(dir, "current", "graph.db"))
	for i := range 150 {
		if _, err := db.Exec(`INSERT INTO nodes VALUES(?,?,?,'')`, "vuln:CVE-2025-"+strconv.Itoa(10000+i), "Vulnerability", `{"summary":"widget flaw"}`); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	got, err := open(t, dir).Search(context.Background(), "widget", 1000)
	if err != nil || len(got) != 100 {
		t.Fatalf("len %d err %v", len(got), err)
	}
}

func TestWeakness(t *testing.T) {
	ctx := context.Background()
	s := open(t, install(t, true))
	w, err := s.Weakness(ctx, "cwe-79")
	if err != nil || w == nil || w.ID != "CWE-79" || !reflect.DeepEqual(w.Children, []string{"CWE-80"}) || len(w.Parents) != 0 {
		t.Fatalf("%+v %v", w, err)
	}
	if c, _ := s.Weakness(ctx, "80"); c == nil || !reflect.DeepEqual(c.Parents, []string{"CWE-79"}) {
		t.Fatalf("%+v", c)
	}
	if w, err := s.Weakness(ctx, "CWE-999"); w != nil || err != nil {
		t.Fatalf("unknown: %v %v", w, err)
	}
	for _, c := range []string{"", "CWE-", "CWE-x", "79; DROP"} {
		if _, err := s.Weakness(ctx, c); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("%q: %v", c, err)
		}
	}
}

func TestAsOf(t *testing.T) {
	ctx := context.Background()
	s := open(t, install(t, true))
	at, err := s.AsOf(ctx, time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if v, err := at.ByID(ctx, "CVE-2024-1000"); err != nil || v == nil || v.Summary != "old lodash summary" {
		t.Fatalf("%+v %v", v, err)
	}
	if v, _ := at.ByID(ctx, "CVE-2024-2000"); v != nil {
		t.Fatalf("recorded after the as-of time: %+v", v)
	}
	if got, _ := at.ByPackage(ctx, "pkg:npm/lodash", "4.17.0"); len(got) != 1 {
		t.Fatalf("by package as-of: %+v", got)
	}
	if got, _ := at.Search(ctx, "libfoo", 10); len(got) != 0 {
		t.Fatalf("search as-of: %+v", got)
	}
	before, err := s.AsOf(ctx, time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if v, err := before.ByID(ctx, "CVE-2024-1000"); v != nil || err != nil {
		t.Fatalf("before earliest: %v %v", v, err)
	}
	if got, err := before.ByPackage(ctx, "pkg:npm/lodash", "4.17.0"); len(got) != 0 || err != nil {
		t.Fatalf("%v %v", got, err)
	}
	if got, err := before.Search(ctx, "lodash", 5); len(got) != 0 || err != nil {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []time.Time{{}, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)} {
		if _, err := s.AsOf(ctx, bad); !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "as-of") {
			t.Fatalf("%v: %v", bad, err)
		}
	}
	nohist := open(t, install(t, false))
	if _, err := nohist.AsOf(ctx, time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)); !errors.Is(err, ErrHistoryUnavailable) {
		t.Fatalf("got %v", err)
	}
}

func TestReadsLeaveGraphUnchanged(t *testing.T) {
	ctx := context.Background()
	dir := install(t, true)
	p := filepath.Join(dir, "current", "graph.db")
	before, _ := os.ReadFile(p)
	s := open(t, dir)
	_, _ = s.ByID(ctx, "CVE-2024-1000")
	_, _ = s.ByID(ctx, "")
	_, _ = s.ByPackage(ctx, "pkg:npm/lodash", "4.17.0")
	_, _ = s.Search(ctx, "lodash", 5)
	_, _ = s.Weakness(ctx, "79")
	if _, err := s.db.ExecContext(ctx, `DELETE FROM nodes`); err == nil {
		t.Fatal("handle is writable")
	}
	after, _ := os.ReadFile(p)
	if sha256.Sum256(before) != sha256.Sum256(after) {
		t.Fatal("graph.db changed")
	}
}

// The adapter must not be able to reach the network: no package that opens
// sockets or HTTP clients may be imported by the non-test files.
func TestNoNetworkImports(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range af.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if p == "net" || strings.HasPrefix(p, "net/") && p != "net/url" || strings.Contains(p, "cveupdate") {
				t.Errorf("%s imports %s", f, p)
			}
		}
	}
}
