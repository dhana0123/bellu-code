// Package issues builds Issues from toxic-combination matches and stores them
// in the issue and issue_finding tables (Requirements 4.1-4.9).
package issues

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
	"github.com/bellu/bellucode/services/bellud/internal/posture"
	"github.com/bellu/bellucode/services/bellud/internal/risk"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
)

const (
	MaxFindings = 500
	tsFmt       = "2006-01-02T15:04:05.000000000Z"
	// ConfidenceExtracted is the confirmed graph confidence; ConfidenceInferred is the candidate one.
	ConfidenceExtracted = "extracted"
	ConfidenceInferred  = "inferred"
)

// Errors.
var (
	ErrHopWithoutEvidence = errors.New("issues: hop without evidence")
	ErrEmptyPath          = errors.New("issues: match has no path")
	ErrNoFindings         = errors.New("issues: no member findings")
	ErrNotFound           = errors.New("issues: not found")
	ErrInvalid            = errors.New("issues: invalid input")
)

// Status is the Issue lifecycle state.
type Status string

const (
	StatusOpen     Status = "open"
	StatusResolved Status = "resolved"
	StatusIgnored  Status = "ignored"
)

func (s Status) valid() bool { return s == StatusOpen || s == StatusResolved || s == StatusIgnored }

// Hop is one entity of the path and the relation leading to the next entity
// (empty on the last hop).
type Hop struct {
	EntityID string
	Relation string
	Evidence []string
	Inferred bool
}

// Issue is a group of findings on one evidenced path.
type Issue struct {
	ID, Title, RuleID string
	Severity          findings.Severity
	RiskScore         float64 // 0..100
	Status            Status
	Category          schema.OverviewCategory
	FindingIDs        []string // 1..500
	Path              []Hop
	IncludesInferred  bool
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// ---- Builder ----

// RelationInfo describes one graph relation.
type RelationInfo struct {
	Confidence string   // extracted or inferred
	Evidence   []string // evidence references
}

// Source gives the Builder graph and finding data.
type Source interface {
	// Relation returns the relation from -> to, if it exists.
	Relation(from, relation, to string) (RelationInfo, bool)
	// Attrs returns entity attributes; "exposure" and "criticality" (0..1) are used.
	Attrs(entityID string) map[string]string
	// Findings returns the open member findings of the entities for the rule.
	Findings(ruleID string, entityIDs []string) []findings.Finding
}

// Builder turns toxic-combination matches into Issues.
type Builder struct {
	Src             Source
	IncludeInferred bool
	Now             func() time.Time
}

// PathKey is the ordered entity ids joined, used in the Issue id.
func PathKey(hops []posture.Hop) string {
	ids := make([]string, len(hops))
	for i, h := range hops {
		ids[i] = h.EntityID
	}
	return strings.Join(ids, "\x00")
}

// FromMatch builds an Issue or returns ErrHopWithoutEvidence when any hop has
// no evidence, including when its relation is missing or is a candidate and
// IncludeInferred is unset (4.6-4.8).
func (b *Builder) FromMatch(m posture.Match) (Issue, error) {
	if len(m.Path) == 0 {
		return Issue{}, ErrEmptyPath
	}
	path := make([]Hop, len(m.Path))
	ids := make([]string, len(m.Path))
	inferred := false
	for i, h := range m.Path {
		ids[i] = h.EntityID
		path[i] = Hop{EntityID: h.EntityID, Relation: h.Relation}
		if i == len(m.Path)-1 {
			continue
		}
		info, ok := b.Src.Relation(h.EntityID, h.Relation, m.Path[i+1].EntityID)
		if !ok || len(info.Evidence) == 0 {
			return Issue{}, fmt.Errorf("%w: %s -[%s]-> %s", ErrHopWithoutEvidence, h.EntityID, h.Relation, m.Path[i+1].EntityID)
		}
		switch info.Confidence {
		case ConfidenceExtracted:
		case ConfidenceInferred:
			if !b.IncludeInferred {
				return Issue{}, fmt.Errorf("%w: inferred hop %s -[%s]-> %s excluded", ErrHopWithoutEvidence, h.EntityID, h.Relation, m.Path[i+1].EntityID)
			}
			path[i].Inferred = true
			inferred = true
		default:
			return Issue{}, fmt.Errorf("%w: unknown confidence %q", ErrHopWithoutEvidence, info.Confidence)
		}
		path[i].Evidence = info.Evidence
	}
	fs := b.Src.Findings(m.RuleID, ids)
	if len(fs) == 0 {
		return Issue{}, ErrNoFindings
	}
	if len(fs) > MaxFindings {
		fs = fs[:MaxFindings]
	}
	exposure, crit := risk.ExposureUnknown, 0.0
	for _, id := range ids {
		a := b.Src.Attrs(id)
		if risk.Exposure(a["exposure"]) == risk.ExposureInternet {
			exposure = risk.ExposureInternet
		} else if exposure == risk.ExposureUnknown && risk.Exposure(a["exposure"]) == risk.ExposureInternal {
			exposure = risk.ExposureInternal
		}
		if c, err := strconv.ParseFloat(a["criticality"], 64); err == nil && c > crit {
			crit = c
		}
	}
	var cvss, epss float64
	kev := false
	fids := make([]string, 0, len(fs))
	for _, f := range fs {
		fids = append(fids, f.ID)
		var d struct {
			CVSS float64 `json:"cvss"`
			EPSS float64 `json:"epss"`
			KEV  bool    `json:"kev"`
		}
		_ = json.Unmarshal(f.Details, &d)
		cvss, epss, kev = max(cvss, d.CVSS), max(epss, d.EPSS), kev || d.KEV
	}
	score := risk.Compute(risk.Inputs{CVSS: cvss, EPSS: epss, KEV: kev, Reachable: true, Exposure: exposure, AssetCriticality: crit})
	score = min(max(score, 0), 100)
	now := time.Now
	if b.Now != nil {
		now = b.Now
	}
	t := now().UTC()
	return Issue{
		ID:       findings.ID(m.RuleID, ids[0], PathKey(m.Path)),
		Title:    "Toxic combination: " + m.RuleID,
		RuleID:   m.RuleID,
		Severity: findings.Severity(risk.Bucket(score, kev)), RiskScore: score, Status: StatusOpen,
		Category: fs[0].Category, FindingIDs: fids, Path: path, IncludesInferred: inferred,
		CreatedAt: t, UpdatedAt: t,
	}, nil
}

// ---- Store ----

// Query filters List. Empty fields do not filter. Limit 0 means 100.
type Query struct {
	Categories []schema.OverviewCategory
	Severities []findings.Severity
	Statuses   []Status
	AssetID    string // an entity on the path or the asset of a member finding
	Limit      int
}

// Store keeps Issues on the SQLite single writer.
type Store struct {
	db  *sqlite.Store
	ws  string
	now func() time.Time
}

// New returns a Store over an open workspace database.
func New(db *sqlite.Store) *Store { return &Store{db: db, ws: db.WorkspaceID(), now: time.Now} }

// Upsert inserts or updates an Issue. An existing Issue keeps its status and
// created_at, and its member set is replaced, so repeating a call is a no-op.
func (s *Store) Upsert(ctx context.Context, is Issue) error {
	if is.ID == "" || is.Title == "" || len(is.Title) > 256 || is.RiskScore < 0 || is.RiskScore > 100 ||
		len(is.FindingIDs) < 1 || len(is.FindingIDs) > MaxFindings || len(is.Path) == 0 {
		return ErrInvalid
	}
	if is.Status == "" {
		is.Status = StatusOpen
	}
	if !is.Status.valid() {
		return ErrInvalid
	}
	path, err := json.Marshal(is.Path)
	if err != nil {
		return err
	}
	at := s.now().UTC().Format(tsFmt)
	inf := 0
	if is.IncludesInferred {
		inf = 1
	}
	return s.db.Write(ctx, s.ws, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO issue(id, workspace_id, rule_id, title, severity, risk_score, status, category, path, includes_inferred, created_at, updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET title=excluded.title, severity=excluded.severity, risk_score=excluded.risk_score,
 category=excluded.category, path=excluded.path, includes_inferred=excluded.includes_inferred, updated_at=excluded.updated_at`,
			is.ID, s.ws, is.RuleID, is.Title, string(is.Severity), is.RiskScore, string(is.Status), string(is.Category), string(path), inf, at, at)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM issue_finding WHERE workspace_id=? AND issue_id=?`, s.ws, is.ID); err != nil {
			return err
		}
		for _, f := range is.FindingIDs {
			if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO issue_finding(workspace_id, issue_id, finding_id) VALUES(?,?,?)`, s.ws, is.ID, f); err != nil {
				return err
			}
		}
		return nil
	})
}

const cols = `id, rule_id, title, severity, risk_score, status, category, path, includes_inferred, created_at, updated_at`

type scanner interface{ Scan(...any) error }

func scan(r scanner) (Issue, error) {
	var is Issue
	var sev, st, cat, path, c, u string
	var inf int
	if err := r.Scan(&is.ID, &is.RuleID, &is.Title, &sev, &is.RiskScore, &st, &cat, &path, &inf, &c, &u); err != nil {
		return Issue{}, err
	}
	is.Severity, is.Status, is.Category, is.IncludesInferred = findings.Severity(sev), Status(st), schema.OverviewCategory(cat), inf == 1
	if err := json.Unmarshal([]byte(path), &is.Path); err != nil {
		return Issue{}, err
	}
	is.CreatedAt, _ = time.Parse(tsFmt, c)
	is.UpdatedAt, _ = time.Parse(tsFmt, u)
	return is, nil
}

func (s *Store) members(ctx context.Context, id string) ([]string, error) {
	rows, err := s.db.DB().QueryContext(ctx, `SELECT finding_id FROM issue_finding WHERE workspace_id=? AND issue_id=? ORDER BY finding_id`, s.ws, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var f string
		if err := rows.Scan(&f); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// Get returns one Issue or ErrNotFound.
func (s *Store) Get(ctx context.Context, id string) (Issue, error) {
	is, err := scan(s.db.DB().QueryRowContext(ctx, `SELECT `+cols+` FROM issue WHERE workspace_id=? AND id=?`, s.ws, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Issue{}, ErrNotFound
	}
	if err != nil {
		return Issue{}, err
	}
	is.FindingIDs, err = s.members(ctx, id)
	return is, err
}

// List returns Issues sorted by risk score descending, then updated_at descending, then id.
func (s *Store) List(ctx context.Context, q Query) ([]Issue, error) {
	where, args := []string{"workspace_id=?"}, []any{s.ws}
	in := func(col string, vals []string) {
		if len(vals) == 0 {
			return
		}
		where = append(where, col+" IN ("+strings.TrimSuffix(strings.Repeat("?,", len(vals)), ",")+")")
		for _, v := range vals {
			args = append(args, v)
		}
	}
	var cats, sevs, sts []string
	for _, c := range q.Categories {
		cats = append(cats, string(c))
	}
	for _, v := range q.Severities {
		sevs = append(sevs, string(v))
	}
	for _, v := range q.Statuses {
		sts = append(sts, string(v))
	}
	in("category", cats)
	in("severity", sevs)
	in("status", sts)
	if q.AssetID != "" {
		where = append(where, `(EXISTS (SELECT 1 FROM json_each(issue.path) WHERE json_extract(value,'$.EntityID')=?)
 OR EXISTS (SELECT 1 FROM issue_finding i JOIN finding f ON f.workspace_id=i.workspace_id AND f.id=i.finding_id
  WHERE i.workspace_id=issue.workspace_id AND i.issue_id=issue.id AND f.asset_id=?))`)
		args = append(args, q.AssetID, q.AssetID)
	}
	limit := q.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	args = append(args, limit)
	rows, err := s.db.DB().QueryContext(ctx, `SELECT `+cols+` FROM issue WHERE `+strings.Join(where, " AND ")+
		` ORDER BY risk_score DESC, updated_at DESC, id LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	var out []Issue
	for rows.Next() {
		is, err := scan(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, is)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	for i := range out {
		if out[i].FindingIDs, err = s.members(ctx, out[i].ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// SetStatus changes the status and writes an audit row in the same transaction.
func (s *Store) SetStatus(ctx context.Context, id string, to Status, actor string) error {
	if !to.valid() {
		return ErrInvalid
	}
	at := s.now().UTC()
	return s.db.Write(ctx, s.ws, func(tx *sql.Tx) error {
		var prev string
		err := tx.QueryRowContext(ctx, `SELECT status FROM issue WHERE workspace_id=? AND id=?`, s.ws, id).Scan(&prev)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if prev == string(to) {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE issue SET status=?, updated_at=? WHERE workspace_id=? AND id=?`, string(to), at.Format(tsFmt), s.ws, id); err != nil {
			return err
		}
		return sqlite.AppendAudit(ctx, tx, s.ws, sqlite.AuditEntry{Actor: actor, Action: "issue.status_change", Target: id, Outcome: prev + "->" + string(to), At: at})
	})
}

// ByFinding returns the Issues that contain the finding as a member.
func (s *Store) ByFinding(ctx context.Context, findingID string) ([]Issue, error) {
	rows, err := s.db.DB().QueryContext(ctx, `SELECT issue_id FROM issue_finding WHERE workspace_id=? AND finding_id=?`, s.ws, findingID)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	var out []Issue
	for _, id := range ids {
		is, err := s.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, is)
	}
	return out, nil
}
