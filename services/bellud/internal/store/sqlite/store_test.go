package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
	"time"
)

var goodMigrations = fstest.MapFS{
	"0001_init.sql": {Data: []byte(`
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE t (workspace_id TEXT NOT NULL, v INTEGER);`)},
	"README.md": {Data: []byte("ignored")},
}

func open(t *testing.T, root, ws string, m fstest.MapFS) *Store {
	t.Helper()
	s, err := Open(context.Background(), root, ws, Options{Migrations: m})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func pragma(t *testing.T, s *Store, name string) string {
	t.Helper()
	var v string
	if err := s.DB().QueryRow("PRAGMA " + name).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestOpenSetsPragmasAndPermissions(t *testing.T) {
	root := t.TempDir()
	s := open(t, root, "ws1", goodMigrations)
	if got := pragma(t, s, "journal_mode"); got != "wal" {
		t.Fatalf("journal_mode=%s", got)
	}
	if got := pragma(t, s, "foreign_keys"); got != "1" {
		t.Fatalf("foreign_keys=%s", got)
	}
	if got := pragma(t, s, "busy_timeout"); got != "5000" {
		t.Fatalf("busy_timeout=%s", got)
	}
	if st := s.DB().Stats(); st.MaxOpenConnections != 1 {
		t.Fatalf("max open=%d", st.MaxOpenConnections)
	}
	if v, _ := s.Version(context.Background()); v != 1 {
		t.Fatalf("version=%d", v)
	}
	fi, _ := os.Stat(s.Dir())
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", fi.Mode().Perm())
	}
	entries, _ := os.ReadDir(s.Dir())
	for _, e := range entries {
		info, _ := e.Info()
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v", e.Name(), info.Mode().Perm())
		}
	}
}

func TestRejectsBadWorkspaceID(t *testing.T) {
	for _, id := range []string{"", "..", "a/b", "../x"} {
		if _, err := Open(context.Background(), t.TempDir(), id, Options{Migrations: goodMigrations}); err == nil {
			t.Fatalf("accepted %q", id)
		}
	}
}

func TestFailedMigrationRollsBackAndReportsNumber(t *testing.T) {
	root := t.TempDir()
	open(t, root, "ws1", goodMigrations).Close()
	bad := fstest.MapFS{
		"0001_init.sql": goodMigrations["0001_init.sql"],
		"0002_bad.sql":  {Data: []byte("CREATE TABLE ok2 (a); INSERT INTO nope VALUES (1);")},
	}
	_, err := Open(context.Background(), root, "ws1", Options{Migrations: bad})
	var me *MigrationError
	if !errors.As(err, &me) || me.Number != 2 || !errors.Is(err, ErrMigration) {
		t.Fatalf("err=%v", err)
	}
	// Reopen with the good set: version still 1 and ok2 does not exist.
	s := open(t, root, "ws1", goodMigrations)
	if v, _ := s.Version(context.Background()); v != 1 {
		t.Fatalf("version=%d", v)
	}
	if ok, _ := tableExists(context.Background(), s.DB(), "ok2"); ok {
		t.Fatal("partial migration persisted")
	}
}

func TestWorkspaceMismatchLeavesDataUnchanged(t *testing.T) {
	ctx := context.Background()
	s := open(t, t.TempDir(), "ws1", goodMigrations)
	err := s.Write(ctx, "other", func(tx *sql.Tx) error {
		_, err := tx.Exec("INSERT INTO t VALUES ('other', 1)")
		return err
	})
	if !errors.Is(err, ErrWorkspaceMismatch) {
		t.Fatalf("err=%v", err)
	}
	if err := s.Write(ctx, "ws1", func(tx *sql.Tx) error {
		_, err := tx.Exec("INSERT INTO t VALUES ('ws1', 1)")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var n int
	s.DB().QueryRow("SELECT count(*) FROM t").Scan(&n)
	if n != 1 {
		t.Fatalf("rows=%d", n)
	}
}

func TestOpeningDatabaseOfAnotherWorkspaceFails(t *testing.T) {
	root := t.TempDir()
	open(t, root, "ws1", goodMigrations).Close()
	dir, _ := WorkspaceDir(root, "ws1")
	other, _ := WorkspaceDir(root, "ws2")
	os.MkdirAll(other, 0o700)
	if err := os.Rename(filepath.Join(dir, DBFileName), filepath.Join(other, DBFileName)); err != nil {
		t.Fatal(err)
	}
	_, err := Open(context.Background(), root, "ws2", Options{Migrations: goodMigrations})
	if !errors.Is(err, ErrWorkspaceMismatch) {
		t.Fatalf("err=%v", err)
	}
}

func TestBusyWriteFailsAfterTimeoutAndLeavesDataUnchanged(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the 5s busy timeout")
	}
	ctx := context.Background()
	s := open(t, t.TempDir(), "ws1", goodMigrations)

	// A second connection (standing in for another process) holds the write lock.
	other, err := sql.Open("sqlite", "file:"+filepath.Join(s.Dir(), DBFileName))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	otx, err := other.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := otx.Exec("INSERT INTO t VALUES ('ws1', 99)"); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	err = s.Write(ctx, "ws1", func(tx *sql.Tx) error {
		_, err := tx.Exec("INSERT INTO t VALUES ('ws1', 1)")
		return err
	})
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("err=%v", err)
	}
	if d := time.Since(start); d < 4*time.Second || d > 8*time.Second {
		t.Fatalf("waited %v", d)
	}
	otx.Rollback()
	var n int
	s.DB().QueryRow("SELECT count(*) FROM t").Scan(&n)
	if n != 0 {
		t.Fatalf("rows=%d", n)
	}
}
