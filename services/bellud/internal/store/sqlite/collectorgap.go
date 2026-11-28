package sqlite

import (
	"context"
	"database/sql"
	"time"
)

// CollectorGap is one row of collector_gap.
type CollectorGap struct {
	Connector, ResourceType, Scope, Reason, Detail string
}

// ReplaceCollectorGaps replaces every stored gap of connector with gaps in one
// transaction, so a run that read everything clears the old gaps.
func (s *Store) ReplaceCollectorGaps(ctx context.Context, connector string, gaps []CollectorGap, runAt time.Time) error {
	return s.Write(ctx, s.workspaceID, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM collector_gap WHERE workspace_id=? AND connector=?`, s.workspaceID, connector); err != nil {
			return err
		}
		for _, g := range gaps {
			if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO collector_gap
				(workspace_id,connector,resource_type,scope,reason,detail,run_at) VALUES(?,?,?,?,?,?,?)`,
				s.workspaceID, connector, g.ResourceType, g.Scope, g.Reason, nullIfEmpty(g.Detail), runAt.UTC().Format(time.RFC3339)); err != nil {
				return err
			}
		}
		return nil
	})
}

// ListCollectorGaps returns the stored gaps of connector ordered by resource type and scope.
func (s *Store) ListCollectorGaps(ctx context.Context, connector string) ([]CollectorGap, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT resource_type,scope,reason,COALESCE(detail,'') FROM collector_gap
		WHERE workspace_id=? AND connector=? ORDER BY resource_type,scope`, s.workspaceID, connector)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []CollectorGap
	for rows.Next() {
		g := CollectorGap{Connector: connector}
		if err := rows.Scan(&g.ResourceType, &g.Scope, &g.Reason, &g.Detail); err != nil {
			return nil, mapErr(err)
		}
		out = append(out, g)
	}
	return out, mapErr(rows.Err())
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
