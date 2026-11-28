package findings

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
	"github.com/bellu/bellucode/services/bellud/internal/redact"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
)

// Limits (Requirements 3.1, 3.9, 22.5).
const (
	MaxBatch        = 1000
	MaxTitle        = 256
	MaxDescription  = 8192
	MaxReason       = 1024
	ExpiryInterval  = 30 * time.Second
	subscriberDepth = 4096
	// tsFmt is fixed width UTC so string comparison in SQL orders by time.
	tsFmt = "2006-01-02T15:04:05.000000000Z"
	// actorScanner is the event actor when a Finding carries no source name.
	actorScanner = "scanner"
)

// Errors.
var (
	// ErrNotFound means no Finding has the id.
	ErrNotFound = errors.New("findings: not found")
	// ErrAuditWriteFailed wraps a failed audit insert. The enclosing change is rolled back.
	ErrAuditWriteFailed = errors.New("audit_write_failed")
	// ErrInvalid is matched by every *InvalidError.
	ErrInvalid = errors.New("findings: invalid input")
	// ErrTransition means the lifecycle does not allow the requested change.
	ErrTransition = errors.New("findings: transition not allowed")
)

// InvalidError names the field that failed validation (Requirement 3.10).
type InvalidError struct{ Field, Msg string }

func (e *InvalidError) Error() string   { return "findings: invalid " + e.Field + ": " + e.Msg }
func (e *InvalidError) Is(t error) bool { return t == ErrInvalid }

// Actor is who changed a status: a user id, "system" or a scanner name.
type Actor struct{ ID string }

// System is the actor of automatic changes such as snooze expiry (3.11).
var System = Actor{ID: "system"}

// ScanRef ties a report to the scan job that produced it.
type ScanRef struct {
	JobID string
	// CompletedAt is used as resolved_at by ResolveMissing. Zero means now.
	CompletedAt time.Time
}

// ReportResult counts what one Report call did. Counts cover committed batches only.
type ReportResult struct {
	Created, Updated, Reopened int
	// RedactionFailures counts excerpts dropped because the Redactor failed.
	RedactionFailures int
}

// StatusEvent is a row of finding_event.
type StatusEvent struct {
	Seq       int64
	FindingID string
	At        time.Time
	Actor     string
	Prev      Status // empty for the first report
	New       Status
	Reason    string
}

// Change tells subscribers that a Finding was created or changed in a way a projection shows.
type Change struct {
	ID, AssetID string
	Status      Status
	Created     bool
}

// ListQuery filters List. Empty fields do not filter. Limit 0 means 100; the maximum is 1000.
type ListQuery struct {
	Statuses   []Status
	Severities []Severity
	Types      []Type
	Categories []schema.OverviewCategory
	// AssetID and Source are single-value filters; AssetIDs and Sources
	// match any of several values. Both forms combine as OR.
	AssetID  string
	Source   string
	AssetIDs []string
	Sources  []string
	// From and To bound last_seen, both inclusive.
	From, To *time.Time
	// Sort is one of the Sort* constants; empty means last_seen descending.
	// Desc applies only when Sort is set. Ties order by id ascending.
	Sort  string
	Desc  bool
	Limit int
	// Cursor is the NextCursor of the previous page.
	Cursor string
}

// Page is one page of results. NextCursor is empty on the last page.
type Page[T any] struct {
	Items      []T
	NextCursor string
}

// Option configures New.
type Option func(*Store)

// WithClock sets the time source.
func WithClock(now func() time.Time) Option { return func(s *Store) { s.now = now } }

// WithRedactor replaces redact.Text. Tests use it to force a redaction failure.
func WithRedactor(f func(string) (string, error)) Option { return func(s *Store) { s.redact = f } }

// Store keeps Findings, their status history and audit rows on the SQLite
// single writer.
type Store struct {
	db     *sqlite.Store
	ws     string
	now    func() time.Time
	redact func(string) (string, error)

	mu     sync.Mutex
	subs   []chan Change
	closed bool
}

// New returns a Store over an open workspace database.
func New(db *sqlite.Store, opts ...Option) *Store {
	s := &Store{db: db, ws: db.WorkspaceID(), now: time.Now, redact: redact.Text}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Subscribe returns a channel of Changes published after each commit. The
// channel is buffered; a subscriber that falls more than 4096 changes behind
// loses the excess, so consumers must also resync periodically. It is closed
// by Close.
func (s *Store) Subscribe() <-chan Change {
	ch := make(chan Change, subscriberDepth)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		close(ch)
		return ch
	}
	s.subs = append(s.subs, ch)
	return ch
}

// Close closes all subscriber channels. It does not close the database.
func (s *Store) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	for _, ch := range s.subs {
		close(ch)
	}
	s.subs = nil
}

func (s *Store) publish(cs []Change) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ch := range s.subs {
		for _, c := range cs {
			select {
			case ch <- c:
			default:
			}
		}
	}
}

// Report upserts findings in transactions of at most MaxBatch rows (22.5).
// A batch that fails rolls back; earlier batches stay committed and the
// result counts only committed batches.
func (s *Store) Report(ctx context.Context, scan ScanRef, fs []Finding) (ReportResult, error) {
	var total ReportResult
	for start := 0; start < len(fs); start += MaxBatch {
		batch := fs[start:min(start+MaxBatch, len(fs))]
		var res ReportResult
		var changes []Change
		now := s.now().UTC()
		err := s.db.Write(ctx, s.ws, func(tx *sql.Tx) error {
			res, changes = ReportResult{}, nil // fn must be restartable
			for _, f := range batch {
				if err := s.upsert(ctx, tx, scan, f, now, &res, &changes); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return total, err
		}
		total.Created += res.Created
		total.Updated += res.Updated
		total.Reopened += res.Reopened
		total.RedactionFailures += res.RedactionFailures
		s.publish(changes)
	}
	return total, nil
}

func (s *Store) upsert(ctx context.Context, tx *sql.Tx, scan ScanRef, f Finding, now time.Time, res *ReportResult, changes *[]Change) error {
	if err := validate(f); err != nil {
		return err
	}
	evidence, failures := s.redactEvidence(f.Evidence)
	for _, i := range failures {
		input := fmt.Sprintf("finding %s evidence[%d]", f.ID, i)
		if err := insertScannerError(ctx, tx, s.ws, scan.JobID, now, input, "redaction_failed: excerpt dropped"); err != nil {
			return err
		}
		res.RedactionFailures++
	}
	evJSON, err := json.Marshal(evidence)
	if err != nil {
		return err
	}
	body := "{}"
	if len(f.Details) > 0 {
		body = string(f.Details)
	}
	ts := now.Format(tsFmt)
	actor := f.Source
	if actor == "" {
		actor = actorScanner
	}

	var prev Status
	var title, category, asset string
	var sev Severity
	var occ int
	err = tx.QueryRowContext(ctx,
		`SELECT status, title, category, asset_id, severity, occurrences FROM finding WHERE workspace_id=? AND id=?`,
		s.ws, f.ID).Scan(&prev, &title, &category, &asset, &sev, &occ)
	if errors.Is(err, sql.ErrNoRows) {
		occ = max(1, f.Occurrences)
		initial := StatusOpen
		if f.Status == StatusIgnored && f.IgnoreReason != "" {
			initial = StatusIgnored
		}
		_, err = tx.ExecContext(ctx,
			`INSERT INTO finding(id, workspace_id, kind, body, revisions, created_at, category, rule_id, title, description,
				severity, status, asset_id, evidence_refs, first_seen, last_seen, source, rule_pack_version, occurrences, risk_score, unmapped_severity)
			 VALUES(?,?,?,?,?,?,?,?,?,?,?,'open',?,?,?,?,?,?,?,?,?)`,
			f.ID, s.ws, string(f.Type), body, f.SourceRevision, ts, string(f.Category), f.RuleID, f.Title, f.Description,
			string(f.Severity), f.AssetID, string(evJSON), ts, ts, f.Source, f.RulePackVersion, occ, f.RiskScore, f.UnmappedSeverity)
		if err != nil {
			return err
		}
		reason := ""
		if initial == StatusIgnored {
			reason = f.IgnoreReason
		}
		if err := insertEvent(ctx, tx, s.ws, f.ID, now, actor, "", initial, reason); err != nil {
			return err
		}
		res.Created++
		*changes = append(*changes, Change{ID: f.ID, AssetID: f.AssetID, Status: initial, Created: true})
		return nil
	}
	if err != nil {
		return err
	}

	if prev == StatusIgnored || prev == StatusAcceptedRisk {
		// A repeat report must not undo a user decision (3.4, design lifecycle).
		_, err = tx.ExecContext(ctx, `UPDATE finding SET last_seen=? WHERE workspace_id=? AND id=?`, ts, s.ws, f.ID)
		if err != nil {
			return err
		}
		res.Updated++
		return nil
	}

	next := prev
	if prev == StatusResolved {
		next = StatusOpen
	}
	if f.Type == TypeRuntimeThreat {
		occ += max(1, f.Occurrences)
	}
	_, err = tx.ExecContext(ctx,
		`UPDATE finding SET last_seen=?, status=?, resolved_at=NULL, kind=?, body=?, revisions=?, category=?, rule_id=?,
			title=?, description=?, severity=?, asset_id=?, evidence_refs=?, source=?, rule_pack_version=?, occurrences=?, risk_score=?, unmapped_severity=?
		 WHERE workspace_id=? AND id=?`,
		ts, string(next), string(f.Type), body, f.SourceRevision, string(f.Category), f.RuleID,
		f.Title, f.Description, string(f.Severity), f.AssetID, string(evJSON), f.Source, f.RulePackVersion, occ, f.RiskScore, f.UnmappedSeverity,
		s.ws, f.ID)
	if err != nil {
		return err
	}
	if next != prev {
		if err := insertEvent(ctx, tx, s.ws, f.ID, now, actor, prev, next, ""); err != nil {
			return err
		}
		if err := auditStatus(ctx, tx, s.ws, f.ID, now, actor, prev, next); err != nil {
			return err
		}
		res.Reopened++
	} else {
		res.Updated++
	}
	if next != prev || title != f.Title || category != string(f.Category) || asset != f.AssetID || sev != f.Severity {
		*changes = append(*changes, Change{ID: f.ID, AssetID: f.AssetID, Status: next})
	}
	return nil
}

// redactEvidence scrubs every excerpt. An excerpt the Redactor cannot scrub is
// dropped, never stored; its index is returned (3.18).
func (s *Store) redactEvidence(in []EvidenceRef) (out []EvidenceRef, failed []int) {
	out = make([]EvidenceRef, len(in))
	for i, e := range in {
		if e.Excerpt != "" {
			clean, rerr := s.redact(e.Excerpt)
			if rerr != nil {
				e.Excerpt = ""
				failed = append(failed, i)
			} else {
				e.Excerpt = clean
			}
		}
		out[i] = e
	}
	return out, failed
}

func validate(f Finding) error {
	bad := func(field, msg string) error { return &InvalidError{Field: field, Msg: msg} }
	switch {
	case f.ID == "":
		return bad("id", "empty")
	case f.AssetID == "":
		return bad("asset_id", "empty")
	case f.Category == "":
		return bad("category", "empty")
	case !validType(f.Type):
		return bad("type", "unknown "+string(f.Type))
	case !validSeverity(f.Severity):
		return bad("severity", "unknown "+string(f.Severity))
	case utf8.RuneCountInString(f.Title) < 1 || utf8.RuneCountInString(f.Title) > MaxTitle:
		return bad("title", "length must be 1 to 256")
	case utf8.RuneCountInString(f.Description) > MaxDescription:
		return bad("description", "longer than 8192")
	case len(f.Evidence) > MaxEvidence:
		return bad("evidence_refs", "more than 50 references")
	case len(f.Details) > 0 && !json.Valid(f.Details):
		return bad("details", "not valid JSON")
	case f.RiskScore != nil && (*f.RiskScore < 0 || *f.RiskScore > 100):
		return bad("risk_score", "outside 0..100")
	}
	return nil
}

func validType(t Type) bool {
	switch t {
	case TypeVulnerability, TypeMisconfiguration, TypeSecret, TypeLicense, TypeMalware,
		TypeRuntimeThreat, TypeAIRisk, TypeDataExposure, TypeIdentityRisk:
		return true
	}
	return false
}

func validSeverity(v Severity) bool {
	switch v {
	case SevCritical, SevHigh, SevMedium, SevLow, SevInfo:
		return true
	}
	return false
}

// ResolveMissing resolves open and in_progress findings of (asset, source)
// whose id is not in seen. The caller invokes it only after a successful,
// uncancelled scan (3.6, 3.7). Each chunk of up to MaxBatch rows is one transaction.
func (s *Store) ResolveMissing(ctx context.Context, scan ScanRef, asset, source string, seen map[string]struct{}) (int, error) {
	rows, err := s.db.DB().QueryContext(ctx,
		`SELECT id FROM finding WHERE workspace_id=? AND asset_id=? AND source=? AND status IN ('open','in_progress')`,
		s.ws, asset, source)
	if err != nil {
		return 0, err
	}
	var missing []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		if _, ok := seen[id]; !ok {
			missing = append(missing, id)
		}
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}

	at := scan.CompletedAt
	if at.IsZero() {
		at = s.now()
	}
	at = at.UTC()
	actor := source
	if actor == "" {
		actor = actorScanner
	}
	total := 0
	for start := 0; start < len(missing); start += MaxBatch {
		chunk := missing[start:min(start+MaxBatch, len(missing))]
		var changes []Change
		n := 0
		err := s.db.Write(ctx, s.ws, func(tx *sql.Tx) error {
			changes, n = nil, 0
			for _, id := range chunk {
				// Re-check the status: a user may have changed it since the read.
				prev, ok, err := currentStatus(ctx, tx, s.ws, id)
				if err != nil {
					return err
				}
				if !ok || (prev != StatusOpen && prev != StatusInProgress) {
					continue
				}
				if _, err := tx.ExecContext(ctx,
					`UPDATE finding SET status='resolved', resolved_at=? WHERE workspace_id=? AND id=?`,
					at.Format(tsFmt), s.ws, id); err != nil {
					return err
				}
				if err := insertEvent(ctx, tx, s.ws, id, at, actor, prev, StatusResolved, ""); err != nil {
					return err
				}
				if err := auditStatus(ctx, tx, s.ws, id, at, actor, prev, StatusResolved); err != nil {
					return err
				}
				changes = append(changes, Change{ID: id, AssetID: asset, Status: StatusResolved})
				n++
			}
			return nil
		})
		if err != nil {
			return total, err
		}
		total += n
		s.publish(changes)
	}
	return total, nil
}

func currentStatus(ctx context.Context, tx *sql.Tx, ws, id string) (Status, bool, error) {
	var st Status
	err := tx.QueryRowContext(ctx, `SELECT status FROM finding WHERE workspace_id=? AND id=?`, ws, id).Scan(&st)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return st, err == nil, err
}

func insertEvent(ctx context.Context, tx *sql.Tx, ws, id string, at time.Time, actor string, prev, next Status, reason string) error {
	var p, r any
	if prev != "" {
		p = string(prev)
	}
	if reason != "" {
		r = reason
	}
	_, err := tx.ExecContext(ctx,
		`INSERT INTO finding_event(workspace_id, finding_id, at, actor, prev_status, new_status, reason) VALUES(?,?,?,?,?,?,?)`,
		ws, id, at.UTC().Format(tsFmt), actor, p, string(next), r)
	return err
}

// auditStatus writes the audit row of a status change in the caller's
// transaction. A failure aborts the transaction (3.12, 21.9).
func auditStatus(ctx context.Context, tx *sql.Tx, ws, id string, at time.Time, actor string, prev, next Status) error {
	err := sqlite.AppendAudit(ctx, tx, ws, sqlite.AuditEntry{
		Actor: actor, Action: "finding.status_change", Target: id,
		Outcome: string(prev) + "->" + string(next), At: at,
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAuditWriteFailed, err)
	}
	return nil
}

func insertScannerError(ctx context.Context, tx *sql.Tx, ws, jobID string, at time.Time, input, cause string) error {
	var j any
	if jobID != "" {
		j = jobID
	}
	_, err := tx.ExecContext(ctx,
		`INSERT INTO scanner_error(workspace_id, job_id, at, input, cause) VALUES(?,?,?,?,?)`,
		ws, j, at.UTC().Format(tsFmt), input, cause)
	return err
}

// ScannerError records a Scanner_Error_Row. Input and cause pass through the
// Redactor; if it fails the placeholder is stored instead.
func (s *Store) ScannerError(ctx context.Context, scan ScanRef, input, cause string) error {
	input, cause = s.scrub(input), s.scrub(cause)
	now := s.now()
	return s.db.Write(ctx, s.ws, func(tx *sql.Tx) error {
		return insertScannerError(ctx, tx, s.ws, scan.JobID, now, input, cause)
	})
}

func (s *Store) scrub(v string) string {
	out, err := s.redact(v)
	if err != nil {
		return redact.FailedPlaceholder
	}
	return out
}

// SetStatus applies a user (or system) status change. ignored and
// accepted_risk need a reason of 1 to 1,024 characters; an expiry, when given,
// must be after now and applies only to those two statuses (3.9, 3.10). The
// finding is unchanged when an error is returned.
func (s *Store) SetStatus(ctx context.Context, id string, to Status, a Actor, reason string, expires *time.Time) error {
	now := s.now().UTC()
	if err := checkSetStatus(to, a, reason, expires, now); err != nil {
		return err
	}
	var change Change
	err := s.db.Write(ctx, s.ws, func(tx *sql.Tx) error {
		var prev Status
		var asset string
		err := tx.QueryRowContext(ctx, `SELECT status, asset_id FROM finding WHERE workspace_id=? AND id=?`, s.ws, id).Scan(&prev, &asset)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if !allowed(prev, to) {
			return fmt.Errorf("%w: %s to %s", ErrTransition, prev, to)
		}
		var snoozeReason, snoozeUntil any
		if to == StatusIgnored || to == StatusAcceptedRisk {
			snoozeReason = reason
			if expires != nil {
				snoozeUntil = expires.UTC().Format(tsFmt)
			}
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE finding SET status=?, snooze_reason=?, snooze_until=? WHERE workspace_id=? AND id=?`,
			string(to), snoozeReason, snoozeUntil, s.ws, id); err != nil {
			return err
		}
		if err := insertEvent(ctx, tx, s.ws, id, now, a.ID, prev, to, reason); err != nil {
			return err
		}
		change = Change{ID: id, AssetID: asset, Status: to}
		return auditStatus(ctx, tx, s.ws, id, now, a.ID, prev, to)
	})
	if err != nil {
		return err
	}
	s.publish([]Change{change})
	return nil
}

func checkSetStatus(to Status, a Actor, reason string, expires *time.Time, now time.Time) error {
	bad := func(field, msg string) error { return &InvalidError{Field: field, Msg: msg} }
	snooze := to == StatusIgnored || to == StatusAcceptedRisk
	switch {
	case strings.TrimSpace(a.ID) == "":
		return bad("actor", "empty")
	case to != StatusOpen && to != StatusInProgress && to != StatusResolved && !snooze:
		return bad("status", "unknown "+string(to))
	case utf8.RuneCountInString(reason) > MaxReason:
		return bad("reason", "longer than 1024")
	case snooze && strings.TrimSpace(reason) == "":
		return bad("reason", "required for "+string(to))
	case expires != nil && !snooze:
		return bad("expires", "applies only to ignored and accepted_risk")
	case expires != nil && !expires.After(now):
		return bad("expires", "must be in the future")
	}
	return nil
}

// allowed is the user lifecycle from the design. resolved is reached only by
// ResolveMissing and left only by a new report.
func allowed(from, to Status) bool {
	switch from {
	case StatusOpen, StatusInProgress:
		return to != from && to != StatusResolved
	case StatusIgnored, StatusAcceptedRisk:
		return to == StatusOpen
	}
	return false
}

// ExpireSnoozes reopens ignored and accepted_risk findings whose expiry is at
// or before now, with actor system (3.11). It returns the number reopened.
func (s *Store) ExpireSnoozes(ctx context.Context, now time.Time) (int, error) {
	rows, err := s.db.DB().QueryContext(ctx,
		`SELECT id FROM finding WHERE workspace_id=? AND status IN ('ignored','accepted_risk')
		 AND snooze_until IS NOT NULL AND snooze_until<=?`, s.ws, now.UTC().Format(tsFmt))
	if err != nil {
		return 0, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}

	at := now.UTC()
	total := 0
	for start := 0; start < len(ids); start += MaxBatch {
		chunk := ids[start:min(start+MaxBatch, len(ids))]
		var changes []Change
		err := s.db.Write(ctx, s.ws, func(tx *sql.Tx) error {
			changes = nil
			for _, id := range chunk {
				var prev Status
				var asset string
				var until sql.NullString
				err := tx.QueryRowContext(ctx,
					`SELECT status, asset_id, snooze_until FROM finding WHERE workspace_id=? AND id=?`, s.ws, id).Scan(&prev, &asset, &until)
				if errors.Is(err, sql.ErrNoRows) {
					continue
				}
				if err != nil {
					return err
				}
				if (prev != StatusIgnored && prev != StatusAcceptedRisk) || !until.Valid || until.String > at.Format(tsFmt) {
					continue // changed by a user since the read
				}
				if _, err := tx.ExecContext(ctx,
					`UPDATE finding SET status='open', snooze_reason=NULL, snooze_until=NULL WHERE workspace_id=? AND id=?`, s.ws, id); err != nil {
					return err
				}
				if err := insertEvent(ctx, tx, s.ws, id, at, System.ID, prev, StatusOpen, "snooze expired"); err != nil {
					return err
				}
				if err := auditStatus(ctx, tx, s.ws, id, at, System.ID, prev, StatusOpen); err != nil {
					return err
				}
				changes = append(changes, Change{ID: id, AssetID: asset, Status: StatusOpen})
			}
			return nil
		})
		if err != nil {
			return total, err
		}
		total += len(changes)
		s.publish(changes)
	}
	return total, nil
}

// RunExpiry calls ExpireSnoozes every interval (ExpiryInterval when zero)
// until ctx is done. A failed pass is retried on the next tick; onErr, if not
// nil, sees it.
func (s *Store) RunExpiry(ctx context.Context, interval time.Duration, onErr func(error)) {
	if interval <= 0 {
		interval = ExpiryInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := s.ExpireSnoozes(ctx, s.now()); err != nil && onErr != nil && ctx.Err() == nil {
				onErr(err)
			}
		}
	}
}
