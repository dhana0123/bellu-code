package cce

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
)

// ErrInvalidRelation is returned for a relation missing required fields.
var ErrInvalidRelation = errors.New("invalid relation")

// NewRelationID returns sha256(type|from|to|workspace) as 64 lowercase hex
// characters. Each field is length-prefixed so that a separator inside a field
// cannot make two different inputs hash alike.
func NewRelationID(relType string, from, to StableID, ws WorkspaceID) RelationID {
	h := sha256.New()
	for _, f := range []string{relType, string(from), string(to), string(ws)} {
		fmt.Fprintf(h, "%d:%s|", len(f), f)
	}
	return RelationID(hex.EncodeToString(h.Sum(nil)))
}

// InsertResult reports whether InsertRelation stored a new row.
type InsertResult struct {
	ID            RelationID
	AlreadyExists bool
}

// InsertRelation stores rel under its deterministic id. If a relation with the
// same id exists, nothing changes and AlreadyExists is true. The ID field of
// rel is ignored and recomputed.
func InsertRelation(ctx context.Context, s *sqlite.Store, rel Relation) (InsertResult, error) {
	id := NewRelationID(rel.Type, rel.From, rel.To, rel.Workspace)
	res := InsertResult{ID: id}
	if rel.Type == "" || rel.From == "" || rel.To == "" || rel.Workspace == "" {
		return res, fmt.Errorf("%w: type, from, to, and workspace are required", ErrInvalidRelation)
	}
	if err := ValidateTemporal(rel.Temporal); err != nil {
		return res, err
	}
	err := s.Write(ctx, string(rel.Workspace), func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM relation WHERE workspace_id = ? AND id = ?`,
			string(rel.Workspace), string(id)).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			res.AlreadyExists = true
			return nil
		}
		t := rel.Temporal
		_, err := tx.ExecContext(ctx,
			`INSERT INTO relation (workspace_id, id, type, from_id, to_id, state, confidence, method,
			   event_time, recorded_at, valid_from, valid_until, observed_at, source_revision)
			 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			string(rel.Workspace), string(id), rel.Type, string(rel.From), string(rel.To),
			string(rel.State), rel.Confidence, string(rel.Method),
			optTime(t.EventTime), utc(t.RecordedAt), utc(t.ValidFrom), optTime(t.ValidUntil),
			utc(t.ObservedAt), t.SourceRevision)
		return err
	})
	return res, err
}

// timeLayout is fixed width (always nine fractional digits) so stored
// timestamps compare correctly as strings. RFC3339Nano trims trailing zeros,
// which breaks ordering ("…:00Z" sorts after "…:00.5Z"). It still parses with
// time.RFC3339Nano.
const timeLayout = "2006-01-02T15:04:05.000000000Z"

func utc(t time.Time) string { return t.UTC().Format(timeLayout) }

func optTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return utc(*t)
}
