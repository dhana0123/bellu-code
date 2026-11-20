package sqlite

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"math"
	"strings"

	msqlite "modernc.org/sqlite"
)

// modernc.org/sqlite registers functions process-wide, so every connection
// opened afterwards, including read-only ones, has ln().
func init() {
	err := msqlite.RegisterDeterministicScalarFunction("ln", 1,
		func(_ *msqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
			switch v := args[0].(type) {
			case float64:
				return math.Log(v), nil
			case int64:
				return math.Log(float64(v)), nil
			}
			return nil, nil
		})
	if err != nil {
		panic(err)
	}
}

// TextHit is one FTS5 match.
type TextHit struct {
	StableID string
	Score    float64 // bm25; lower is a better match
}

// IndexText replaces the fts_text row for stableID with body, in the caller's
// workspace. fts_text has no unique key, so the old row is deleted first.
func (s *Store) IndexText(ctx context.Context, workspaceID, stableID, body string) error {
	if stableID == "" {
		return errors.New("sqlite: empty stable id")
	}
	return s.Write(ctx, workspaceID, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx,
			"DELETE FROM fts_text WHERE workspace_id = ? AND stable_id = ?", workspaceID, stableID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx,
			"INSERT INTO fts_text(stable_id, workspace_id, body) VALUES(?, ?, ?)", stableID, workspaceID, body)
		return err
	})
}

// RemoveText deletes the fts_text row for stableID.
func (s *Store) RemoveText(ctx context.Context, workspaceID, stableID string) error {
	return s.Write(ctx, workspaceID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			"DELETE FROM fts_text WHERE workspace_id = ? AND stable_id = ?", workspaceID, stableID)
		return err
	})
}

// SearchText returns up to limit matches for the terms in the active
// workspace, best first, ties by stable id. Each whitespace-separated term is
// quoted so user input cannot inject FTS5 operators; terms are ANDed.
func (s *Store) SearchText(ctx context.Context, query string, limit int) ([]TextHit, error) {
	if limit < 1 {
		return nil, errors.New("sqlite: limit must be a positive integer")
	}
	terms := strings.Fields(query)
	if len(terms) == 0 {
		return nil, nil
	}
	for i, t := range terms {
		terms[i] = `"` + strings.ReplaceAll(t, `"`, `""`) + `"`
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT stable_id, bm25(fts_text) AS score FROM fts_text
		 WHERE fts_text MATCH ? AND workspace_id = ?
		 ORDER BY score, stable_id LIMIT ?`,
		strings.Join(terms, " "), s.workspaceID, limit)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []TextHit
	for rows.Next() {
		var h TextHit
		if err := rows.Scan(&h.StableID, &h.Score); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
