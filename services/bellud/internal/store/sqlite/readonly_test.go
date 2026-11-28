package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
)

func openReal(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), t.TempDir(), "ws1", Options{Migrations: sqlitemigrations.FS})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenReadOnlyRejectsWrites(t *testing.T) {
	ctx := context.Background()
	s := openReal(t)
	ro, err := OpenReadOnly(ctx, filepath.Join(s.Dir(), DBFileName))
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	var n int
	if err := ro.QueryRow("SELECT count(*) FROM meta").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if _, err := ro.Exec("INSERT INTO meta(key,value) VALUES('x','y')"); err == nil {
		t.Fatal("write succeeded on read-only handle")
	}
	var after int
	_ = s.DB().QueryRow("SELECT count(*) FROM meta WHERE key='x'").Scan(&after)
	if after != 0 {
		t.Fatal("row was written")
	}
}

func TestOpenReadOnlyDoesNotCreateMissingFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "graph.db")
	if _, err := OpenReadOnly(context.Background(), p); err == nil {
		t.Fatal("opened missing file")
	}
}

func TestAppendAuditCommitsWithOriginatingChange(t *testing.T) {
	ctx := context.Background()
	s := openReal(t)
	at := time.Date(2024, 1, 2, 3, 4, 5, 0, time.FixedZone("x", 3600))
	err := s.Write(ctx, "ws1", func(tx *sql.Tx) error {
		if _, err := tx.Exec("INSERT INTO meta(key,value) VALUES('k','v')"); err != nil {
			return err
		}
		return AppendAudit(ctx, tx, "ws1", AuditEntry{Actor: "human", Action: "a", Target: "t", Outcome: "ok", At: at})
	})
	if err != nil {
		t.Fatal(err)
	}
	var actor, when, outcome string
	if err := s.DB().QueryRow("SELECT actor_kind, at, detail FROM audit").Scan(&actor, &when, &outcome); err != nil {
		t.Fatal(err)
	}
	if actor != "human" || outcome != "ok" || when != "2024-01-02T02:04:05Z" {
		t.Fatalf("got %q %q %q", actor, when, outcome)
	}
}

func TestAuditFailureRollsBackOriginatingChange(t *testing.T) {
	ctx := context.Background()
	s := openReal(t)
	err := s.Write(ctx, "ws1", func(tx *sql.Tx) error {
		if _, err := tx.Exec("INSERT INTO meta(key,value) VALUES('k','v')"); err != nil {
			return err
		}
		return AppendAudit(ctx, tx, "ws1", AuditEntry{Actor: "", Action: "a", Target: "t", Outcome: "ok"})
	})
	if !errors.Is(err, ErrInvalidAudit) {
		t.Fatalf("err=%v", err)
	}
	var n int
	_ = s.DB().QueryRow("SELECT count(*) FROM meta WHERE key='k'").Scan(&n)
	if n != 0 {
		t.Fatal("originating change was committed")
	}
}
