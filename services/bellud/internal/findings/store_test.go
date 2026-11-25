package findings

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newStore(t *testing.T, opts ...Option) (*Store, *sqlite.Store, *clock) {
	t.Helper()
	db, err := sqlite.Open(context.Background(), t.TempDir(), "ws1", sqlite.Options{Migrations: sqlitemigrations.FS})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	c := &clock{t: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := New(db, append([]Option{WithClock(c.now)}, opts...)...)
	t.Cleanup(s.Close)
	return s, db, c
}

func sample(id string) Finding {
	return Finding{ID: id, RuleID: "r1", Title: "t", Category: "code_and_dependencies", Type: TypeVulnerability,
		Severity: SevHigh, AssetID: "asset1", Source: "grype"}
}

func count(t *testing.T, db *sqlite.Store, q string) int {
	t.Helper()
	var n int
	if err := db.DB().QueryRow(q).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestReportLifecycleAndHistory(t *testing.T) {
	ctx := context.Background()
	s, db, c := newStore(t)
	ch := s.Subscribe()

	res, err := s.Report(ctx, ScanRef{JobID: "j1"}, []Finding{sample("a"), sample("b")})
	if err != nil || res.Created != 2 {
		t.Fatalf("report: %+v %v", res, err)
	}
	first := c.t
	c.t = c.t.Add(time.Hour)
	if res, err = s.Report(ctx, ScanRef{}, []Finding{sample("a")}); err != nil || res.Updated != 1 {
		t.Fatalf("repeat: %+v %v", res, err)
	}
	f, _, _ := s.Get(ctx, "a")
	if !f.FirstSeen.Equal(first) || !f.LastSeen.Equal(c.t) {
		t.Fatalf("first/last seen: %v %v", f.FirstSeen, f.LastSeen)
	}

	// Scan completes without "b": it resolves, then a new report reopens it.
	n, err := s.ResolveMissing(ctx, ScanRef{}, "asset1", "grype", map[string]struct{}{"a": {}})
	if err != nil || n != 1 {
		t.Fatalf("resolve: %d %v", n, err)
	}
	b, _, _ := s.Get(ctx, "b")
	if b.Status != StatusResolved || b.ResolvedAt == nil {
		t.Fatalf("b: %+v", b)
	}
	if res, _ = s.Report(ctx, ScanRef{}, []Finding{sample("b")}); res.Reopened != 1 {
		t.Fatalf("reopen: %+v", res)
	}
	b, ev, _ := s.Get(ctx, "b")
	if b.Status != StatusOpen || b.ResolvedAt != nil || len(ev) != 3 || ev[2].Prev != StatusResolved || ev[2].New != StatusOpen {
		t.Fatalf("b after reopen: %+v %+v", b, ev)
	}
	// Two audited changes on b (resolve, reopen).
	if got := count(t, db, `SELECT count(*) FROM audit WHERE subject='b' AND action='finding.status_change'`); got != 2 {
		t.Fatalf("audit rows: %d", got)
	}
	if len(ch) != 4 { // a created, b created, b resolved, b reopened
		t.Fatalf("changes: %d", len(ch))
	}
}

func TestSetStatusIgnoreExpireAndValidation(t *testing.T) {
	ctx := context.Background()
	s, db, c := newStore(t)
	if _, err := s.Report(ctx, ScanRef{}, []Finding{sample("a")}); err != nil {
		t.Fatal(err)
	}
	user := Actor{ID: "u1"}
	soon := c.t.Add(time.Hour)

	for name, err := range map[string]error{
		"empty reason": s.SetStatus(ctx, "a", StatusIgnored, user, " ", nil),
		"long reason":  s.SetStatus(ctx, "a", StatusIgnored, user, strings.Repeat("x", 1025), nil),
		"past expiry":  s.SetStatus(ctx, "a", StatusIgnored, user, "ok", &c.t),
	} {
		var inv *InvalidError
		if !errors.As(err, &inv) {
			t.Fatalf("%s: want InvalidError, got %v", name, err)
		}
	}
	if f, _, _ := s.Get(ctx, "a"); f.Status != StatusOpen {
		t.Fatalf("finding changed by rejected call: %s", f.Status)
	}
	if err := s.SetStatus(ctx, "a", StatusIgnored, user, "false positive", &soon); err != nil {
		t.Fatal(err)
	}
	// A repeat report changes last_seen only.
	c.t = c.t.Add(time.Minute)
	changed := sample("a")
	changed.Title = "new title"
	if _, err := s.Report(ctx, ScanRef{}, []Finding{changed}); err != nil {
		t.Fatal(err)
	}
	f, _, _ := s.Get(ctx, "a")
	if f.Status != StatusIgnored || f.Title != "t" || !f.LastSeen.Equal(c.t) {
		t.Fatalf("ignored repeat: %+v", f)
	}
	if n, _ := s.ExpireSnoozes(ctx, c.t); n != 0 {
		t.Fatalf("expired early: %d", n)
	}
	if n, err := s.ExpireSnoozes(ctx, soon); err != nil || n != 1 {
		t.Fatalf("expire: %d %v", n, err)
	}
	f, ev, _ := s.Get(ctx, "a")
	last := ev[len(ev)-1]
	if f.Status != StatusOpen || last.Actor != "system" || last.Prev != StatusIgnored {
		t.Fatalf("after expiry: %+v %+v", f, last)
	}
	if got := count(t, db, `SELECT count(*) FROM audit WHERE actor_kind='system'`); got != 1 {
		t.Fatalf("system audit rows: %d", got)
	}
}

func TestAuditFailureRollsBackStatusChange(t *testing.T) {
	ctx := context.Background()
	s, db, _ := newStore(t)
	if _, err := s.Report(ctx, ScanRef{}, []Finding{sample("a")}); err != nil {
		t.Fatal(err)
	}
	// Make audit inserts fail.
	if _, err := db.DB().Exec(`CREATE TRIGGER audit_block BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'blocked'); END`); err != nil {
		t.Fatal(err)
	}
	err := s.SetStatus(ctx, "a", StatusInProgress, Actor{ID: "u1"}, "", nil)
	if !errors.Is(err, ErrAuditWriteFailed) || !strings.HasPrefix(err.Error(), "audit_write_failed") {
		t.Fatalf("want audit_write_failed, got %v", err)
	}
	f, ev, _ := s.Get(ctx, "a")
	if f.Status != StatusOpen || len(ev) != 1 {
		t.Fatalf("not rolled back: %s %d", f.Status, len(ev))
	}
}

func TestFailedBatchRollsBackAndKeepsEarlierBatches(t *testing.T) {
	ctx := context.Background()
	s, db, _ := newStore(t)
	fs := make([]Finding, MaxBatch+3)
	for i := range fs {
		fs[i] = sample(fmt.Sprintf("f%04d", i))
	}
	fs[MaxBatch+2].Title = "" // invalid row in the second batch
	res, err := s.Report(ctx, ScanRef{}, fs)
	var inv *InvalidError
	if !errors.As(err, &inv) || inv.Field != "title" {
		t.Fatalf("want title error, got %v", err)
	}
	if res.Created != MaxBatch {
		t.Fatalf("created %d", res.Created)
	}
	if got := count(t, db, `SELECT count(*) FROM finding`); got != MaxBatch {
		t.Fatalf("rows %d, want %d", got, MaxBatch)
	}
	if got := count(t, db, `SELECT count(*) FROM finding_event`); got != MaxBatch {
		t.Fatalf("events %d", got)
	}
}

func TestRedactionFailureDropsExcerptAndWritesScannerError(t *testing.T) {
	ctx := context.Background()
	s, db, _ := newStore(t, WithRedactor(func(in string) (string, error) {
		if strings.Contains(in, "bad") {
			return "", errors.New("boom")
		}
		return strings.ReplaceAll(in, "secret", "[x]"), nil
	}))
	f := sample("a")
	f.Evidence = []EvidenceRef{{Kind: "file", Ref: "p", Excerpt: "a secret"}, {Kind: "file", Ref: "q", Excerpt: "bad one"}}
	res, err := s.Report(ctx, ScanRef{JobID: "j1"}, []Finding{f})
	if err != nil || res.RedactionFailures != 1 {
		t.Fatalf("report: %+v %v", res, err)
	}
	got, _, _ := s.Get(ctx, "a")
	if got.Evidence[0].Excerpt != "a [x]" || got.Evidence[1].Excerpt != "" {
		t.Fatalf("evidence: %+v", got.Evidence)
	}
	if n := count(t, db, `SELECT count(*) FROM scanner_error WHERE job_id='j1' AND cause LIKE 'redaction_failed%'`); n != 1 {
		t.Fatalf("scanner_error rows: %d", n)
	}
}

func TestListFiltersAndPaging(t *testing.T) {
	ctx := context.Background()
	s, _, c := newStore(t)
	for i := 0; i < 5; i++ {
		f := sample(fmt.Sprintf("f%d", i))
		if i == 4 {
			f.Severity = SevLow
		}
		c.t = c.t.Add(time.Second)
		if _, err := s.Report(ctx, ScanRef{}, []Finding{f}); err != nil {
			t.Fatal(err)
		}
	}
	p1, err := s.List(ctx, ListQuery{Limit: 2})
	if err != nil || len(p1.Items) != 2 || p1.NextCursor == "" || p1.Items[0].ID != "f4" {
		t.Fatalf("page1: %+v %v", p1, err)
	}
	p2, _ := s.List(ctx, ListQuery{Limit: 2, Cursor: p1.NextCursor})
	p3, _ := s.List(ctx, ListQuery{Limit: 2, Cursor: p2.NextCursor})
	if len(p2.Items) != 2 || len(p3.Items) != 1 || p3.NextCursor != "" || p2.Items[0].ID != "f2" {
		t.Fatalf("pages: %+v %+v", p2, p3)
	}
	low, _ := s.List(ctx, ListQuery{Severities: []Severity{SevLow}})
	if len(low.Items) != 1 || low.Items[0].ID != "f4" {
		t.Fatalf("filter: %+v", low)
	}
}

func TestJobSinkResolvesUnseen(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newStore(t)
	if _, err := s.Report(ctx, ScanRef{}, []Finding{sample("a"), sample("b")}); err != nil {
		t.Fatal(err)
	}
	j := s.JobSink(ctx, ScanRef{JobID: "j2"})
	if err := j.Findings([]Finding{sample("a")}); err != nil {
		t.Fatal(err)
	}
	if n, err := j.ResolveMissing(ctx, "asset1", "grype"); err != nil || n != 1 {
		t.Fatalf("resolve: %d %v", n, err)
	}
	if c, u := j.Counts(); c != 0 || u != 1 {
		t.Fatalf("counts %d %d", c, u)
	}
}
