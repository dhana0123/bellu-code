package sqlite

import (
	"context"
	"fmt"
)

const (
	// DefaultMaxDepth is the default traversal depth bound.
	DefaultMaxDepth = 10
	// DefaultRowCap is the default traversal row cap.
	DefaultRowCap = 10000
)

// Limit names the bound that truncated a traversal.
type Limit string

const (
	LimitNone   Limit = ""
	LimitDepth  Limit = "depth"
	LimitRowCap Limit = "row_cap"
)

// TraverseOptions configure Traverse. A zero field takes its default; a
// negative field is an error.
type TraverseOptions struct {
	MaxDepth int
	RowCap   int
}

// WalkRow is one enumerated path ending at Node. Weight is the sum of
// -ln(max(confidence, 1e-6)) over the path's edges.
type WalkRow struct {
	Node   string
	Depth  int
	Weight float64
	Path   []string
}

// TraverseResult holds the rows collected, in order of depth then path.
type TraverseResult struct {
	Rows      []WalkRow
	Truncated bool
	Limit     Limit // set when Truncated
}

// Traverse enumerates simple paths from source over confirmed, currently valid
// relations of the active workspace, using a recursive CTE bounded by maximum
// depth, a per-path no-revisit guard, and a row cap. When a bound is reached it
// returns the rows so far, marks the result truncated, and names the limit.
// The source row (depth 0) counts toward the row cap.
func (s *Store) Traverse(ctx context.Context, source string, opts TraverseOptions) (TraverseResult, error) {
	maxDepth, rowCap := opts.MaxDepth, opts.RowCap
	if maxDepth < 0 || rowCap < 0 {
		return TraverseResult{}, fmt.Errorf("sqlite: traversal limits must be positive integers (max depth %d, row cap %d)", maxDepth, rowCap)
	}
	if maxDepth == 0 {
		maxDepth = DefaultMaxDepth
	}
	if rowCap == 0 {
		rowCap = DefaultRowCap
	}
	if source == "" {
		return TraverseResult{}, fmt.Errorf("sqlite: empty traversal source")
	}

	// The walk runs one level past maxDepth. A row at that level proves the
	// depth limit cut the traversal, and is discarded. Rows are ordered by depth
	// so such rows come last, and the cursor stops after rowCap+1 rows.
	rows, err := s.db.QueryContext(ctx, `
WITH RECURSIVE walk(node, depth, path, score_w) AS (
  SELECT ?1, 0, ',' || ?1 || ',', 0.0
  UNION ALL
  SELECT r.to_id, w.depth + 1, w.path || r.to_id || ',',
         w.score_w + (-ln(max(r.confidence, 1e-6)))
  FROM walk w
  JOIN relation r ON r.from_id = w.node AND r.workspace_id = ?2
  WHERE r.state = 'confirmed'
    AND r.valid_until IS NULL
    AND w.depth < ?3 + 1
    AND instr(w.path, ',' || r.to_id || ',') = 0
)
SELECT node, depth, score_w, path FROM walk ORDER BY depth, path LIMIT ?4`,
		source, s.workspaceID, maxDepth, rowCap+1)
	if err != nil {
		return TraverseResult{}, mapErr(err)
	}
	defer rows.Close()

	var res TraverseResult
	for rows.Next() {
		var r WalkRow
		var path string
		if err := rows.Scan(&r.Node, &r.Depth, &r.Weight, &path); err != nil {
			return TraverseResult{}, err
		}
		if r.Depth > maxDepth {
			res.Truncated, res.Limit = true, LimitDepth
			break
		}
		if len(res.Rows) == rowCap {
			res.Truncated, res.Limit = true, LimitRowCap
			break
		}
		r.Path = splitPath(path)
		res.Rows = append(res.Rows, r)
	}
	return res, rows.Err()
}

func splitPath(p string) []string {
	var out []string
	start := 1 // skip leading comma
	for i := 1; i < len(p); i++ {
		if p[i] == ',' {
			out = append(out, p[start:i])
			start = i + 1
		}
	}
	return out
}
