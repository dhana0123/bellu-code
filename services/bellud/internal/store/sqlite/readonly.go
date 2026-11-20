package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// OpenReadOnly opens an existing SQLite file (bellu.db or the installed
// graph.db) for reading only. The URI uses mode=ro and every connection sets
// PRAGMA query_only = ON, so a write statement fails and changes nothing.
// The file is never created.
func OpenReadOnly(ctx context.Context, path string) (*sql.DB, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(abs)}
	u.RawQuery = "mode=ro&_pragma=query_only(ON)&_pragma=busy_timeout(" + strconv.Itoa(BusyTimeoutMillis) + ")"
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	// Fail now if the file is missing or unreadable.
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite: open read-only %q: %w", path, mapErr(err))
	}
	return db, nil
}

// AuditEntry is one append-only audit row.
type AuditEntry struct {
	Actor   string
	Action  string
	Target  string
	Outcome string
	// At is the event time. The zero value means now. It is stored in UTC.
	At time.Time
}

// ErrInvalidAudit means an audit entry had an empty required field.
var ErrInvalidAudit = errors.New("sqlite: invalid audit entry")

// AppendAudit inserts one audit row inside the caller's transaction. It never
// commits. If it returns an error the caller must return that error from its
// Store.Write function so the whole transaction, including the originating
// change, rolls back.
//
// The audit table has columns actor_kind, subject and detail; they hold the
// actor, target and outcome respectively.
func AppendAudit(ctx context.Context, tx *sql.Tx, workspaceID string, e AuditEntry) error {
	if strings.TrimSpace(workspaceID) == "" || strings.TrimSpace(e.Actor) == "" ||
		strings.TrimSpace(e.Action) == "" || strings.TrimSpace(e.Target) == "" ||
		strings.TrimSpace(e.Outcome) == "" {
		return fmt.Errorf("%w: workspace, actor, action, target and outcome are required", ErrInvalidAudit)
	}
	at := e.At
	if at.IsZero() {
		at = time.Now()
	}
	_, err := tx.ExecContext(ctx,
		`INSERT INTO audit(workspace_id, at, actor_kind, action, subject, detail) VALUES(?,?,?,?,?,?)`,
		workspaceID, at.UTC().Format(time.RFC3339Nano), e.Actor, e.Action, e.Target, e.Outcome)
	if err != nil {
		return fmt.Errorf("sqlite: audit append failed: %w", mapErr(err))
	}
	return nil
}
