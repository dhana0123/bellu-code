package sqlite

import (
	"context"
	"strings"
	"testing"

	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
)

func TestMigration0001Constraints(t *testing.T) {
	s, err := Open(context.Background(), t.TempDir(), "ws1", Options{Migrations: sqlitemigrations.FS})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	db := s.DB()

	rel := func(id, state, method, from, until string) error {
		var u any
		if until != "" {
			u = until
		}
		_, err := db.Exec(`INSERT INTO relation(workspace_id,id,type,from_id,to_id,state,confidence,method,recorded_at,valid_from,valid_until,observed_at,source_revision)
			VALUES('ws1',?,'t','a','b',?,0.5,?,'x',?,?,'x','r')`, id, state, method, from, u)
		return err
	}
	exec := func(q string, args ...any) error { _, err := db.Exec(q, args...); return err }
	wantErr := func(name string, err error, sub string) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), sub) {
			t.Errorf("%s: got %v, want error containing %q", name, err, sub)
		}
	}

	wantErr("llm confirmed", rel("r1", "confirmed", "llm", "2024-01-01", ""), "llm_never_confirmed")
	wantErr("interval", rel("r2", "hypothesis", "llm", "2024-02-01", "2024-01-01"), "valid_interval")
	if err := rel("r3", "hypothesis", "llm", "2024-01-01", ""); err != nil {
		t.Fatal(err)
	}
	wantErr("hypothesis->confirmed", exec(`UPDATE relation SET state='confirmed' WHERE id='r3'`), "illegal relation state transition")
	wantErr("candidate without evidence", exec(`UPDATE relation SET state='candidate' WHERE id='r3'`), "relation requires evidence")
	if err := exec(`INSERT INTO relation_evidence VALUES('ws1','r3','ev:1')`); err != nil {
		t.Fatal(err)
	}
	if err := exec(`UPDATE relation SET state='candidate' WHERE id='r3'`); err != nil {
		t.Fatal(err)
	}

	if err := exec(`INSERT INTO evidence VALUES('ws1','ev:1','k',x'01',zeroblob(32),'l','trusted_source',NULL,'x','x','r')`); err != nil {
		t.Fatal(err)
	}
	wantErr("evidence update", exec(`UPDATE evidence SET kind='z'`), "append-only")
	wantErr("evidence delete", exec(`DELETE FROM evidence`), "append-only")

	if err := exec(`INSERT INTO audit(workspace_id,at,actor_kind,action,subject) VALUES('ws1','x','a','b','c')`); err != nil {
		t.Fatal(err)
	}
	wantErr("audit update", exec(`UPDATE audit SET action='z'`), "append-only")
	wantErr("audit delete", exec(`DELETE FROM audit`), "append-only")

	for _, n := range []int{0, 3} {
		wantErr("planning_rounds", exec(`INSERT INTO agent_run(id,workspace_id,agent,planning_rounds) VALUES('a','ws1','x',?)`, n), "CHECK")
	}
	if err := exec(`INSERT INTO fts_text(stable_id,workspace_id,body) VALUES('bid:1','ws1','hello world')`); err != nil {
		t.Fatal(err)
	}
}
