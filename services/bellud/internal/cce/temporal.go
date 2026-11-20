package cce

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
)

// ErrInvalidTemporal is wrapped by every TemporalError.
var ErrInvalidTemporal = errors.New("invalid temporal fields")

// TemporalError names the temporal field that failed validation.
type TemporalError struct{ Field, Reason string }

func (e *TemporalError) Error() string {
	return fmt.Sprintf("invalid temporal fields: field %q %s", e.Field, e.Reason)
}
func (e *TemporalError) Unwrap() error { return ErrInvalidTemporal }

// SourceRevisionKind says which kind of source a source_revision names.
type SourceRevisionKind string

const (
	RevCommit   SourceRevisionKind = "commit"
	RevSnapshot SourceRevisionKind = "snapshot"
	RevRun      SourceRevisionKind = "run"
)

// A source revision is exactly one of:
//
//	commit SHA          40 (SHA-1) or 64 (SHA-256) lowercase hex characters
//	CVE snapshot id     "snapshot:<id>"
//	connector run id    "run:<id>"
var (
	commitRe = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
	idRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

// ParseSourceRevision classifies rev. It fails if rev is empty, names more
// than one revision (separated by whitespace, comma, semicolon, or pipe), or
// matches none of the three forms.
func ParseSourceRevision(rev string) (SourceRevisionKind, error) {
	switch {
	case rev == "":
		return "", &TemporalError{"source_revision", "is required"}
	case strings.ContainsAny(rev, " \t\r\n,;|"):
		return "", &TemporalError{"source_revision", "must name exactly one of commit SHA, CVE snapshot id, or connector run id"}
	case commitRe.MatchString(rev):
		return RevCommit, nil
	}
	if id, ok := strings.CutPrefix(rev, "snapshot:"); ok && idRe.MatchString(id) {
		return RevSnapshot, nil
	}
	if id, ok := strings.CutPrefix(rev, "run:"); ok && idRe.MatchString(id) {
		return RevRun, nil
	}
	return "", &TemporalError{"source_revision", "must be a commit SHA, snapshot:<id>, or run:<id>"}
}

// ValidateTemporal checks the fields every relation and evidence record
// carries: valid_from, recorded_at, and source_revision are required, every
// timestamp that is set must be UTC, and valid_until must be after valid_from.
func ValidateTemporal(t Temporal) error {
	if err := checkUTC("valid_from", t.ValidFrom, true); err != nil {
		return err
	}
	if err := checkUTC("recorded_at", t.RecordedAt, true); err != nil {
		return err
	}
	if err := checkUTC("observed_at", t.ObservedAt, false); err != nil {
		return err
	}
	if t.EventTime != nil {
		if err := checkUTC("event_time", *t.EventTime, false); err != nil {
			return err
		}
	}
	if t.ValidUntil != nil {
		if err := checkUTC("valid_until", *t.ValidUntil, true); err != nil {
			return err
		}
		if !t.ValidUntil.After(t.ValidFrom) {
			return &TemporalError{"valid_until", "must be later than valid_from"}
		}
	}
	_, err := ParseSourceRevision(t.SourceRevision)
	return err
}

// checkUTC rejects a zero time when required, any non-UTC zone, and years
// outside 0001..9999 that RFC 3339 cannot represent.
func checkUTC(field string, t time.Time, required bool) error {
	if t.IsZero() {
		if required {
			return &TemporalError{field, "is required"}
		}
		return nil
	}
	if _, off := t.Zone(); off != 0 {
		return &TemporalError{field, "must be a UTC timestamp"}
	}
	if y := t.Year(); y < 1 || y > 9999 {
		return &TemporalError{field, "is not a valid timestamp"}
	}
	return nil
}

// AsOfQuery selects relations by valid time and, optionally, knowledge time.
type AsOfQuery struct {
	Workspace WorkspaceID
	// At is the valid-time instant t.
	At time.Time
	// KnownAt, when set, makes the read bitemporal: only rows with
	// recorded_at <= KnownAt are returned.
	KnownAt *time.Time
}

// ReadRelationsAsOf returns the relations with valid_from <= At and either no
// valid_until or At < valid_until. With KnownAt set it also requires
// recorded_at <= KnownAt. No match yields an empty slice and no error.
// Results are ordered by relation id, then valid_from.
func ReadRelationsAsOf(ctx context.Context, s *sqlite.Store, q AsOfQuery) ([]Relation, error) {
	if q.Workspace == "" {
		return nil, &TemporalError{"workspace", "is required"}
	}
	if err := checkUTC("as_of", q.At, true); err != nil {
		return nil, err
	}
	query := `SELECT id, type, from_id, to_id, state, confidence, method, event_time, recorded_at,
	                 valid_from, valid_until, observed_at, source_revision
	          FROM relation
	          WHERE workspace_id = ? AND valid_from <= ? AND (valid_until IS NULL OR ? < valid_until)`
	at := utc(q.At)
	args := []any{string(q.Workspace), at, at}
	if q.KnownAt != nil {
		if err := checkUTC("known_at", *q.KnownAt, true); err != nil {
			return nil, err
		}
		query += ` AND recorded_at <= ?`
		args = append(args, utc(*q.KnownAt))
	}
	query += ` ORDER BY id, valid_from`

	rows, err := s.DB().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Relation{}
	for rows.Next() {
		r := Relation{Workspace: q.Workspace}
		var (
			id, typ, from, to, state, method string
			event, until                     sql.NullString
			recorded, validFrom, observed    string
		)
		if err := rows.Scan(&id, &typ, &from, &to, &state, &r.Confidence, &method, &event, &recorded,
			&validFrom, &until, &observed, &r.Temporal.SourceRevision); err != nil {
			return nil, err
		}
		r.ID, r.Type, r.From, r.To = RelationID(id), typ, StableID(from), StableID(to)
		r.State, r.Method = EdgeState(state), Method(method)
		if r.Temporal.RecordedAt, err = parseTime(recorded); err != nil {
			return nil, err
		}
		if r.Temporal.ValidFrom, err = parseTime(validFrom); err != nil {
			return nil, err
		}
		if r.Temporal.ObservedAt, err = parseTime(observed); err != nil {
			return nil, err
		}
		if r.Temporal.EventTime, err = parseOptTime(event); err != nil {
			return nil, err
		}
		if r.Temporal.ValidUntil, err = parseOptTime(until); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	for i := range out {
		ids, err := relationEvidenceIDs(ctx, s, q.Workspace, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].Evidence = ids
	}
	return out, nil
}

func relationEvidenceIDs(ctx context.Context, s *sqlite.Store, ws WorkspaceID, id RelationID) ([]EvidenceID, error) {
	rows, err := s.DB().QueryContext(ctx,
		`SELECT evidence_id FROM relation_evidence WHERE workspace_id = ? AND relation_id = ? ORDER BY evidence_id`,
		string(ws), string(id))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []EvidenceID
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			return nil, err
		}
		ids = append(ids, EvidenceID(e))
	}
	return ids, rows.Err()
}

func parseTime(s string) (time.Time, error) { return time.Parse(time.RFC3339Nano, s) }

func parseOptTime(s sql.NullString) (*time.Time, error) {
	if !s.Valid {
		return nil, nil
	}
	t, err := parseTime(s.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}
