package findings

import (
	"context"

	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
)

// AllSeverities lists the five severities, most severe first.
var AllSeverities = []Severity{SevCritical, SevHigh, SevMedium, SevLow, SevInfo}

// SeverityCounts counts the open and in_progress Findings of each Overview
// category by severity (finding_cat_idx). Every category present in
// the table has all five severity keys, zero included. Categories without
// Findings are absent.
func (s *Store) SeverityCounts(ctx context.Context) (map[schema.OverviewCategory]map[Severity]int, error) {
	rows, err := s.db.DB().QueryContext(ctx,
		`SELECT category, severity, COUNT(*) FROM finding
		 WHERE workspace_id=? AND status IN ('open','in_progress') GROUP BY category, severity`, s.ws)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[schema.OverviewCategory]map[Severity]int{}
	for rows.Next() {
		var c, sev string
		var n int
		if err := rows.Scan(&c, &sev, &n); err != nil {
			return nil, err
		}
		cat := schema.OverviewCategory(c)
		m := out[cat]
		if m == nil {
			m = make(map[Severity]int, len(AllSeverities))
			for _, v := range AllSeverities {
				m[v] = 0
			}
			out[cat] = m
		}
		m[Severity(sev)] = n
	}
	return out, rows.Err()
}
