// Package sqlite is the embedded per-workspace system of record. It owns the
// workspace directory, the single writer connection, and the migration runner.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	msqlite "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

const (
	// DBFileName is the database file inside the workspace directory.
	DBFileName = "bellu.db"
	// BusyTimeoutMillis is the SQLite busy timeout.
	BusyTimeoutMillis = 5000

	dirMode  os.FileMode = 0o700
	fileMode os.FileMode = 0o600
)

var (
	// ErrBusy means the write lock was not acquired within the busy timeout.
	ErrBusy = errors.New("sqlite: database is busy")
	// ErrWorkspaceMismatch means a write named a workspace other than the open one.
	ErrWorkspaceMismatch = errors.New("sqlite: workspace mismatch")
	// ErrMigration wraps a failed migration; see MigrationError.
	ErrMigration = errors.New("sqlite: migration failed")
)

// MigrationError reports the migration that failed to apply.
type MigrationError struct {
	Number int
	Err    error
}

func (e *MigrationError) Error() string {
	return fmt.Sprintf("sqlite: migration %04d failed: %v", e.Number, e.Err)
}
func (e *MigrationError) Unwrap() []error { return []error{ErrMigration, e.Err} }

var workspaceIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// Store is an open workspace database with exactly one writer connection.
type Store struct {
	db          *sql.DB
	dir         string
	workspaceID string
}

// Options configure Open.
type Options struct {
	// Migrations holds NNNN_name.sql files at its root. Required.
	Migrations fs.FS
}

// WorkspaceDir returns <dataRoot>/workspaces/<workspaceID>.
func WorkspaceDir(dataRoot, workspaceID string) (string, error) {
	if !workspaceIDRe.MatchString(workspaceID) || workspaceID == "." || workspaceID == ".." {
		return "", fmt.Errorf("sqlite: invalid workspace id %q", workspaceID)
	}
	return filepath.Join(dataRoot, "workspaces", workspaceID), nil
}

// Open creates the workspace directory (0700) and bellu.db (0600) if needed,
// opens only that workspace, and applies pending migrations. If a migration
// fails the store is not returned and the error carries the migration number.
func Open(ctx context.Context, dataRoot, workspaceID string, opts Options) (*Store, error) {
	if opts.Migrations == nil {
		return nil, errors.New("sqlite: migrations filesystem is required")
	}
	dir, err := WorkspaceDir(dataRoot, workspaceID)
	if err != nil {
		return nil, err
	}
	for _, d := range []string{filepath.Join(dataRoot, "workspaces"), dir} {
		if err := os.MkdirAll(d, dirMode); err != nil {
			return nil, err
		}
		if err := os.Chmod(d, dirMode); err != nil {
			return nil, err
		}
	}
	path := filepath.Join(dir, DBFileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, fileMode)
	if err != nil {
		return nil, err
	}
	f.Close()
	if err := os.Chmod(path, fileMode); err != nil {
		return nil, err
	}

	dsn := "file:" + filepath.ToSlash(path) +
		"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)" +
		"&_pragma=busy_timeout(" + strconv.Itoa(BusyTimeoutMillis) + ")&_pragma=synchronous(NORMAL)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // exactly one writer connection
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	s := &Store{db: db, dir: dir, workspaceID: workspaceID}
	if err := s.init(ctx, opts.Migrations); err != nil {
		db.Close()
		return nil, err
	}
	s.chmodFiles()
	return s, nil
}

func (s *Store) init(ctx context.Context, migrations fs.FS) error {
	if err := checkWAL(ctx, s.db); err != nil {
		return mapErr(err)
	}
	if err := migrate(ctx, s.db, migrations); err != nil {
		return err
	}
	return s.bindWorkspace(ctx)
}

func checkWAL(ctx context.Context, db *sql.DB) error {
	var mode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil {
		return err
	}
	if !strings.EqualFold(mode, "wal") {
		return fmt.Errorf("sqlite: journal_mode is %q, want wal", mode)
	}
	return nil
}

// bindWorkspace records workspace_id in meta on first open and rejects a
// database that belongs to another workspace. It is a no-op until a migration
// has created the meta table.
func (s *Store) bindWorkspace(ctx context.Context) error {
	recorded, ok, err := s.metaWorkspaceID(ctx, s.db)
	if err != nil {
		return err
	}
	if !ok {
		if exists, err := tableExists(ctx, s.db, "meta"); err != nil || !exists {
			return err
		}
		_, err := s.db.ExecContext(ctx, "INSERT INTO meta(key, value) VALUES('workspace_id', ?)", s.workspaceID)
		return mapErr(err)
	}
	if recorded != s.workspaceID {
		return fmt.Errorf("%w: database belongs to %q, opened as %q", ErrWorkspaceMismatch, recorded, s.workspaceID)
	}
	return nil
}

type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func tableExists(ctx context.Context, q queryer, name string) (bool, error) {
	var n int
	err := q.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?", name).Scan(&n)
	return n > 0, err
}

func (s *Store) metaWorkspaceID(ctx context.Context, q queryer) (string, bool, error) {
	if exists, err := tableExists(ctx, q, "meta"); err != nil || !exists {
		return "", false, err
	}
	var v string
	err := q.QueryRowContext(ctx, "SELECT value FROM meta WHERE key='workspace_id'").Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return v, err == nil, err
}

var migrationRe = regexp.MustCompile(`^(\d{4})_[A-Za-z0-9_.-]+\.sql$`)

type migration struct {
	number int
	name   string
}

func listMigrations(fsys fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}
	var out []migration
	for _, e := range entries {
		if m := migrationRe.FindStringSubmatch(e.Name()); m != nil && !e.IsDir() {
			n, _ := strconv.Atoi(m[1])
			out = append(out, migration{n, e.Name()})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].number < out[j].number })
	for i, m := range out {
		if m.number != i+1 {
			return nil, fmt.Errorf("sqlite: migration numbers must be contiguous from 0001; found %04d at position %d", m.number, i+1)
		}
	}
	return out, nil
}

// migrate applies each pending migration in its own transaction and records
// the number in PRAGMA user_version inside that transaction.
func migrate(ctx context.Context, db *sql.DB, fsys fs.FS) error {
	all, err := listMigrations(fsys)
	if err != nil {
		return err
	}
	var current int
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&current); err != nil {
		return mapErr(err)
	}
	if current > len(all) {
		return fmt.Errorf("sqlite: database schema version %d is newer than the %d known migrations", current, len(all))
	}
	for _, m := range all[current:] {
		body, err := fs.ReadFile(fsys, m.name)
		if err != nil {
			return &MigrationError{m.number, err}
		}
		if err := applyOne(ctx, db, m.number, string(body)); err != nil {
			return &MigrationError{m.number, mapErr(err)}
		}
	}
	return nil
}

func applyOne(ctx context.Context, db *sql.DB, number int, body string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, body); err != nil {
		_ = tx.Rollback()
		return err
	}
	// PRAGMA does not accept bound parameters; number is an int.
	if _, err := tx.ExecContext(ctx, "PRAGMA user_version = "+strconv.Itoa(number)); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// Version returns PRAGMA user_version.
func (s *Store) Version(ctx context.Context) (int, error) {
	var v int
	err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v)
	return v, mapErr(err)
}

// WorkspaceID returns the active workspace id.
func (s *Store) WorkspaceID() string { return s.workspaceID }

// Dir returns the workspace directory.
func (s *Store) Dir() string { return s.dir }

// DB exposes the single-connection handle for repositories in this module.
// Writes must go through Write so the workspace check applies.
func (s *Store) DB() *sql.DB { return s.db }

// Close closes the database.
func (s *Store) Close() error {
	err := s.db.Close()
	s.chmodFiles()
	return err
}

func (s *Store) chmodFiles() {
	for _, suffix := range []string{"", "-wal", "-shm"} {
		p := filepath.Join(s.dir, DBFileName+suffix)
		if _, err := os.Stat(p); err == nil {
			_ = os.Chmod(p, fileMode)
		}
	}
}

// Write runs fn in one transaction after checking that workspaceID equals the
// workspace_id recorded in meta. On mismatch fn is not called and nothing
// changes. If fn returns an error the transaction is rolled back. A lock that
// cannot be acquired within the busy timeout yields ErrBusy.
func (s *Store) Write(ctx context.Context, workspaceID string, fn func(tx *sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return mapErr(err)
	}
	recorded, ok, err := s.metaWorkspaceID(ctx, tx)
	if err == nil {
		if !ok {
			recorded = s.workspaceID
		}
		if workspaceID != recorded {
			err = fmt.Errorf("%w: write for %q, workspace is %q", ErrWorkspaceMismatch, workspaceID, recorded)
		}
	}
	if err == nil {
		err = fn(tx)
	}
	if err != nil {
		_ = tx.Rollback()
		return mapErr(err)
	}
	return mapErr(tx.Commit())
}

// mapErr converts SQLITE_BUSY and SQLITE_LOCKED into ErrBusy.
func mapErr(err error) error {
	if err == nil || errors.Is(err, ErrBusy) {
		return err
	}
	var se *msqlite.Error
	if errors.As(err, &se) {
		switch se.Code() & 0xff {
		case sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED:
			return fmt.Errorf("%w: %v", ErrBusy, err)
		}
	}
	return err
}
