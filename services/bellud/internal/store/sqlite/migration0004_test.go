package sqlite

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
)

// migrationsUpTo returns the embedded migrations numbered 0001..n.
func migrationsUpTo(t *testing.T, n int) fs.FS {
	t.Helper()
	out := fstest.MapFS{}
	entries, err := fs.ReadDir(sqlitemigrations.FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sql") || e.Name()[:4] > []string{"0000", "0001", "0002", "0003", "0004"}[n] {
			continue
		}
		b, err := fs.ReadFile(sqlitemigrations.FS, e.Name())
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = &fstest.MapFile{Data: b}
	}
	return out
}

// Validates: Requirements 3.12, 3.15, 21.8.
func TestMigration0004SecurityPlatform(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()

	// Phase 1: a finding written under 0001..0003 only.
	old, err := Open(ctx, root, "ws1", Options{Migrations: migrationsUpTo(t, 3)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.DB().Exec(`INSERT INTO finding(id,workspace_id,kind,body,revisions,cve_snapshot_id,verdict,created_at)
		VALUES('f-old','ws1','legacy','{"a":1}','r1','snap','v','2024-01-01')`); err != nil {
		t.Fatal(err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}

	// Phase 2: reopen with 0004 applied.
	s, err := Open(ctx, root, "ws1", Options{Migrations: sqlitemigrations.FS})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	db := s.DB()
	if v, err := s.Version(ctx); err != nil || v < 4 {
		t.Fatalf("version = %d, %v; want at least 4", v, err)
	}

	var id, ws, kind, body, revs, snap, verdict, created string
	if err := db.QueryRow(`SELECT id,workspace_id,kind,body,revisions,cve_snapshot_id,verdict,created_at FROM finding WHERE id='f-old'`).
		Scan(&id, &ws, &kind, &body, &revs, &snap, &verdict, &created); err != nil {
		t.Fatalf("old finding lost: %v", err)
	}
	if ws != "ws1" || kind != "legacy" || body != `{"a":1}` || revs != "r1" || snap != "snap" || verdict != "v" || created != "2024-01-01" {
		t.Errorf("old finding columns changed: %v", []string{ws, kind, body, revs, snap, verdict, created})
	}
	var category, severity, status string
	var occ int
	if err := db.QueryRow(`SELECT category,severity,status,occurrences FROM finding WHERE id='f-old'`).Scan(&category, &severity, &status, &occ); err != nil {
		t.Fatal(err)
	}
	if category != "code_and_dependencies" || severity != "info" || status != "open" || occ != 1 {
		t.Errorf("new column defaults wrong: %s %s %s %d", category, severity, status, occ)
	}

	// File mode 0600 (21.8).
	fi, err := os.Stat(filepath.Join(s.Dir(), DBFileName))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("db mode = %v, want 0600", fi.Mode().Perm())
	}

	exec := func(q string, args ...any) error { _, err := db.Exec(q, args...); return err }
	wantErr := func(name string, err error, sub string) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), sub) {
			t.Errorf("%s: got %v, want error containing %q", name, err, sub)
		}
	}

	// CHECK constraints on finding.
	wantErr("finding severity", exec(`UPDATE finding SET severity='bogus' WHERE id='f-old'`), "CHECK")
	wantErr("finding status", exec(`UPDATE finding SET status='bogus' WHERE id='f-old'`), "CHECK")
	wantErr("finding risk_score", exec(`UPDATE finding SET risk_score=101 WHERE id='f-old'`), "CHECK")
	wantErr("finding evidence_refs", exec(`UPDATE finding SET evidence_refs='not json' WHERE id='f-old'`), "CHECK")
	wantErr("finding title", exec(`UPDATE finding SET title=? WHERE id='f-old'`, strings.Repeat("x", 257)), "CHECK")
	wantErr("finding description", exec(`UPDATE finding SET description=? WHERE id='f-old'`, strings.Repeat("x", 8193)), "CHECK")
	wantErr("finding snooze_reason", exec(`UPDATE finding SET snooze_reason=? WHERE id='f-old'`, strings.Repeat("x", 1025)), "CHECK")
	if err := exec(`UPDATE finding SET severity='high', status='resolved', risk_score=100, title=?, description=? WHERE id='f-old'`,
		strings.Repeat("x", 256), strings.Repeat("x", 8192)); err != nil {
		t.Errorf("boundary values rejected: %v", err)
	}

	// CHECK constraints on other tables.
	issue := func(title, sev, status string, risk float64, path string) error {
		return exec(`INSERT INTO issue(id,workspace_id,rule_id,title,severity,risk_score,status,category,path,created_at,updated_at)
			VALUES(lower(hex(randomblob(4))),'ws1','r',?,?,?,?,'c',?,'t','t')`, title, sev, risk, status, path)
	}
	wantErr("issue empty title", issue("", "high", "open", 1, "[]"), "CHECK")
	wantErr("issue long title", issue(strings.Repeat("x", 257), "high", "open", 1, "[]"), "CHECK")
	wantErr("issue severity", issue("t", "bogus", "open", 1, "[]"), "CHECK")
	wantErr("issue status", issue("t", "high", "in_progress", 1, "[]"), "CHECK")
	wantErr("issue risk", issue("t", "high", "open", -1, "[]"), "CHECK")
	wantErr("issue path", issue("t", "high", "open", 1, "{bad"), "CHECK")
	if err := issue("t", "high", "open", 50, "[]"); err != nil {
		t.Errorf("valid issue rejected: %v", err)
	}
	job := func(kind, status string) error {
		return exec(`INSERT INTO scan_job(id,workspace_id,kind,target_type,target_id,status,queued_at)
			VALUES(lower(hex(randomblob(4))),'ws1',?,'a','b',?,'t')`, kind, status)
	}
	wantErr("scan_job kind", job("bogus", "queued"), "CHECK")
	wantErr("scan_job status", job("sbom", "bogus"), "CHECK")
	if err := job("sbom", "skipped_unchanged"); err != nil {
		t.Errorf("valid scan_job rejected: %v", err)
	}
	for _, n := range []int{899, 2592001} {
		wantErr("scan_schedule interval", exec(`INSERT INTO scan_schedule(id,workspace_id,kind,target_type,target_id,interval_s,next_at)
			VALUES(lower(hex(randomblob(4))),'ws1','k','a','b',?,'t')`, n), "CHECK")
	}
	wantErr("posture_eval result", exec(`INSERT INTO posture_eval VALUES('ws1','p','r','e','maybe',NULL,'v','t')`), "CHECK")
	wantErr("collector_gap reason", exec(`INSERT INTO collector_gap VALUES('ws1','c','r','s','bogus',NULL,'t')`), "CHECK")
	wantErr("secret_verify_audit result", exec(`INSERT INTO secret_verify_audit(workspace_id,provider,fingerprint,at,result) VALUES('ws1','p','f','t','bogus')`), "CHECK")

	// Indexes (including the partial snooze index).
	wantIdx := map[string]string{
		"finding_list_idx": "finding", "finding_cat_idx": "finding", "finding_asset_idx": "finding", "finding_snooze_idx": "finding",
		"issue_list_idx": "issue", "issue_cat_idx": "issue", "scan_job_queue_idx": "scan_job", "scan_job_target_idx": "scan_job",
		"runtime_event_ts_idx": "runtime_event",
	}
	for name, table := range wantIdx {
		var tbl string
		if err := db.QueryRow(`SELECT tbl_name FROM sqlite_master WHERE type='index' AND name=?`, name).Scan(&tbl); err != nil || tbl != table {
			t.Errorf("index %s on %s missing: tbl=%q err=%v", name, table, tbl, err)
		}
	}
	var snoozeSQL string
	if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE name='finding_snooze_idx'`).Scan(&snoozeSQL); err != nil || !strings.Contains(snoozeSQL, "WHERE snooze_until IS NOT NULL") {
		t.Errorf("finding_snooze_idx is not partial: %q %v", snoozeSQL, err)
	}

	// finding_event is append-only (3.12).
	if err := exec(`INSERT INTO finding_event(workspace_id,finding_id,at,actor,prev_status,new_status,reason) VALUES('ws1','f-old','t','system',NULL,'open','x')`); err != nil {
		t.Fatal(err)
	}
	wantErr("finding_event update", exec(`UPDATE finding_event SET reason='y'`), "append-only")
	wantErr("finding_event delete", exec(`DELETE FROM finding_event`), "append-only")
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM finding_event WHERE reason='x'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("finding_event row changed: n=%d err=%v", n, err)
	}
}
