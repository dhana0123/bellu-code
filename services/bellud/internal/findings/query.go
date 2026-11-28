package findings

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
)

const findingCols = `id, workspace_id, rule_id, title, description, category, kind, severity, status, asset_id,
	evidence_refs, first_seen, last_seen, resolved_at, source, revisions, rule_pack_version, occurrences, risk_score, unmapped_severity, body`

type scanner interface{ Scan(dest ...any) error }

func scanFinding(r scanner) (Finding, error) {
	var f Finding
	var category, typ, sev, status, evidence, first, last, body string
	var resolved sql.NullString
	var risk sql.NullFloat64
	err := r.Scan(&f.ID, &f.WorkspaceID, &f.RuleID, &f.Title, &f.Description, &category, &typ, &sev, &status, &f.AssetID,
		&evidence, &first, &last, &resolved, &f.Source, &f.SourceRevision, &f.RulePackVersion, &f.Occurrences, &risk, &f.UnmappedSeverity, &body)
	if err != nil {
		return f, err
	}
	f.Category, f.Type, f.Severity, f.Status = schema.OverviewCategory(category), Type(typ), Severity(sev), Status(status)
	if err := json.Unmarshal([]byte(evidence), &f.Evidence); err != nil {
		return f, fmt.Errorf("findings: bad evidence_refs on %s: %w", f.ID, err)
	}
	if f.FirstSeen, err = parseTS(first); err != nil {
		return f, err
	}
	if f.LastSeen, err = parseTS(last); err != nil {
		return f, err
	}
	if resolved.Valid {
		t, err := parseTS(resolved.String)
		if err != nil {
			return f, err
		}
		f.ResolvedAt = &t
	}
	if risk.Valid {
		f.RiskScore = &risk.Float64
	}
	if body != "{}" {
		f.Details = json.RawMessage(body)
	}
	return f, nil
}

func parseTS(s string) (time.Time, error) {
	t, err := time.Parse(tsFmt, s)
	if err != nil {
		return t, fmt.Errorf("findings: bad timestamp %q: %w", s, err)
	}
	return t, nil
}

// Get returns one Finding and its status events, oldest first.
func (s *Store) Get(ctx context.Context, id string) (Finding, []StatusEvent, error) {
	f, err := scanFinding(s.db.DB().QueryRowContext(ctx,
		`SELECT `+findingCols+` FROM finding WHERE workspace_id=? AND id=?`, s.ws, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Finding{}, nil, ErrNotFound
	}
	if err != nil {
		return Finding{}, nil, err
	}
	rows, err := s.db.DB().QueryContext(ctx,
		`SELECT seq, at, actor, prev_status, new_status, reason FROM finding_event
		 WHERE workspace_id=? AND finding_id=? ORDER BY seq`, s.ws, id)
	if err != nil {
		return Finding{}, nil, err
	}
	defer rows.Close()
	var events []StatusEvent
	for rows.Next() {
		e := StatusEvent{FindingID: id}
		var at string
		var prev, reason sql.NullString
		if err := rows.Scan(&e.Seq, &at, &e.Actor, &prev, &e.New, &reason); err != nil {
			return Finding{}, nil, err
		}
		if e.At, err = parseTS(at); err != nil {
			return Finding{}, nil, err
		}
		e.Prev, e.Reason = Status(prev.String), reason.String
		events = append(events, e)
	}
	return f, events, rows.Err()
}

// Sort fields accepted by ListQuery.Sort. The empty value means SortLastSeen
// descending, the default order.
const (
	SortLastSeen  = "last_seen"
	SortFirstSeen = "first_seen"
	SortSeverity  = "severity"
	SortRiskScore = "risk_score"
)

// sortKey is the SQL expression a sort field orders by and how its keyset
// value is parsed from a cursor. Ties always break on id ascending.
type sortKey struct {
	expr  string
	parse func(string) (any, error)
	text  func(Finding) string
}

var severityRank = `CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END`

var sortKeys = map[string]sortKey{
	SortLastSeen:  {"last_seen", func(v string) (any, error) { return v, nil }, func(f Finding) string { return f.LastSeen.UTC().Format(tsFmt) }},
	SortFirstSeen: {"first_seen", func(v string) (any, error) { return v, nil }, func(f Finding) string { return f.FirstSeen.UTC().Format(tsFmt) }},
	SortSeverity: {severityRank, func(v string) (any, error) { return strconv.ParseInt(v, 10, 64) }, func(f Finding) string {
		return strconv.Itoa(map[Severity]int{SevCritical: 4, SevHigh: 3, SevMedium: 2, SevLow: 1}[f.Severity])
	}},
	// A Finding without a risk score sorts as -1, after every scored one when descending.
	SortRiskScore: {"COALESCE(risk_score, -1)", func(v string) (any, error) { return strconv.ParseFloat(v, 64) }, func(f Finding) string {
		if f.RiskScore == nil {
			return "-1"
		}
		return strconv.FormatFloat(*f.RiskScore, 'g', -1, 64)
	}},
}

// List returns findings with keyset paging. The default order is last_seen
// descending then id; ListQuery.Sort and Desc choose another one.
func (s *Store) List(ctx context.Context, q ListQuery) (Page[Finding], error) {
	limit := q.Limit
	if limit <= 0 {
		limit = 100
	}
	limit = min(limit, MaxBatch)
	field, desc := q.Sort, q.Desc
	if field == "" {
		field, desc = SortLastSeen, true
	}
	key, ok := sortKeys[field]
	if !ok {
		return Page[Finding]{}, &InvalidError{Field: "sort", Msg: "unknown field " + q.Sort}
	}
	where := []string{"workspace_id=?"}
	args := []any{s.ws}
	in := func(col string, vals []string) {
		if len(vals) == 0 {
			return
		}
		where = append(where, col+" IN ("+strings.TrimSuffix(strings.Repeat("?,", len(vals)), ",")+")")
		for _, v := range vals {
			args = append(args, v)
		}
	}
	in("status", mapStrings(q.Statuses))
	in("severity", mapStrings(q.Severities))
	in("kind", mapStrings(q.Types))
	in("category", mapStrings(q.Categories))
	in("asset_id", appendNonEmpty(q.AssetIDs, q.AssetID))
	in("source", appendNonEmpty(q.Sources, q.Source))
	if q.From != nil {
		where, args = append(where, "last_seen >= ?"), append(args, q.From.UTC().Format(tsFmt))
	}
	if q.To != nil {
		where, args = append(where, "last_seen <= ?"), append(args, q.To.UTC().Format(tsFmt))
	}
	if q.Cursor != "" {
		raw, id, ok := strings.Cut(q.Cursor, "|")
		if !ok {
			return Page[Finding]{}, &InvalidError{Field: "cursor", Msg: "malformed"}
		}
		v, err := key.parse(raw)
		if err != nil {
			return Page[Finding]{}, &InvalidError{Field: "cursor", Msg: "malformed"}
		}
		op := ">"
		if desc {
			op = "<"
		}
		where = append(where, "("+key.expr+" "+op+" ? OR ("+key.expr+" = ? AND id > ?))")
		args = append(args, v, v, id)
	}
	dir := "ASC"
	if desc {
		dir = "DESC"
	}
	args = append(args, limit+1)
	rows, err := s.db.DB().QueryContext(ctx,
		`SELECT `+findingCols+` FROM finding WHERE `+strings.Join(where, " AND ")+
			` ORDER BY `+key.expr+` `+dir+`, id ASC LIMIT ?`, args...)
	if err != nil {
		return Page[Finding]{}, err
	}
	defer rows.Close()
	var page Page[Finding]
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return Page[Finding]{}, err
		}
		page.Items = append(page.Items, f)
	}
	if err := rows.Err(); err != nil {
		return Page[Finding]{}, err
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		lastItem := page.Items[limit-1]
		page.NextCursor = key.text(lastItem) + "|" + lastItem.ID
	}
	return page, nil
}

func appendNonEmpty(vals []string, one string) []string {
	if one == "" {
		return vals
	}
	return append(slices.Clone(vals), one)
}

func mapStrings[T ~string](in []T) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	return out
}
