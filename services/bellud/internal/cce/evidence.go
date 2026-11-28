package cce

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/redact"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
)

// MaxEvidenceBytes is the largest stored evidence content.
const MaxEvidenceBytes = 8192

var (
	// ErrInvalidEvidence wraps a FieldError for a rejected evidence write.
	ErrInvalidEvidence = errors.New("invalid evidence")
	// ErrGuardUnavailable means no redaction guard could scrub the content.
	ErrGuardUnavailable = errors.New("redaction guard unavailable")
	// ErrEvidenceIntegrity means stored content does not match its digest.
	ErrEvidenceIntegrity = errors.New("evidence integrity failure")
	// ErrEvidenceNotFound means no evidence row has the id in the workspace.
	ErrEvidenceNotFound = errors.New("evidence not found")
)

// FieldError names the evidence field that failed validation.
type FieldError struct{ Field, Reason string }

func (e *FieldError) Error() string {
	return fmt.Sprintf("invalid evidence: field %q %s", e.Field, e.Reason)
}
func (e *FieldError) Unwrap() error { return ErrInvalidEvidence }

// Scrubber redacts content before it is hashed and stored. A failed Scrub
// means the write is rejected.
type Scrubber interface {
	Scrub(content []byte) ([]byte, error)
}

// GuardScrubber adapts a redact.Guard. A nil guard always fails.
type GuardScrubber struct{ Guard redact.Guard }

// Scrub runs the guard over content and fails if the guard panics or the
// scrubbed result still matches a rule.
func (g GuardScrubber) Scrub(content []byte) (out []byte, err error) {
	if g.Guard == nil {
		return nil, ErrGuardUnavailable
	}
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("%w: %v", ErrGuardUnavailable, r)
		}
	}()
	in := batch.Batch{Entities: []batch.Entity{{Type: "evidence", Attributes: map[string]any{"text": string(content)}}}}
	scrubbed := g.Guard.Scrub(in)
	if g.Guard.Leaks(scrubbed) {
		return nil, fmt.Errorf("%w: content still matches a redaction rule", ErrGuardUnavailable)
	}
	text, ok := scrubbed.Entities[0].Attributes["text"].(string)
	if !ok {
		return nil, fmt.Errorf("%w: guard dropped content", ErrGuardUnavailable)
	}
	return []byte(text), nil
}

// EvidenceStore writes and reads evidence rows.
type EvidenceStore struct {
	Store    *sqlite.Store
	Scrubber Scrubber
	Now      func() time.Time // defaults to time.Now
}

// EvidenceInfo is an evidence row with its annotations.
type EvidenceInfo struct {
	Evidence
	Truncated          bool
	SuspectedInjection bool
}

// Write validates, scrubs, truncates, hashes and stores ev. Any ContentSHA256
// or ID supplied by the caller is ignored. The evidence id is the content
// digest, so writing identical scrubbed content twice keeps the first row and
// returns it. On any error nothing is stored.
func (s EvidenceStore) Write(ctx context.Context, ev Evidence) (EvidenceInfo, error) {
	if err := validateEvidence(ev); err != nil {
		return EvidenceInfo{}, err
	}
	if s.Scrubber == nil {
		return EvidenceInfo{}, ErrGuardUnavailable
	}
	scrubbed, err := s.Scrubber.Scrub(ev.Content)
	if err != nil {
		return EvidenceInfo{}, err
	}
	content, truncated := truncateUTF8(scrubbed, MaxEvidenceBytes)
	digest := sha256.Sum256(content)
	info := EvidenceInfo{Evidence: ev, Truncated: truncated}
	info.Content, info.ContentSHA256 = content, digest
	info.ID = EvidenceID("ev:" + hex.EncodeToString(digest[:]))
	info.SuspectedInjection = ev.Trust == UntrustedText && looksLikeInstruction(content)

	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	t := &info.Temporal
	if t.RecordedAt.IsZero() {
		t.RecordedAt = now()
	}
	if t.ObservedAt.IsZero() {
		t.ObservedAt = t.RecordedAt
	}
	ws := string(ev.Workspace)
	err = s.Store.Write(ctx, ws, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`INSERT INTO evidence (workspace_id, id, kind, content, content_sha256, locator, trust,
			   event_time, recorded_at, observed_at, source_revision)
			 VALUES (?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING`,
			ws, string(info.ID), string(ev.Kind), content, digest[:], ev.Locator, string(ev.Trust),
			optTime(t.EventTime), utc(t.RecordedAt), utc(t.ObservedAt), t.SourceRevision)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return nil // identical content already stored; keep the first row
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO evidence_flag (workspace_id, evidence_id, truncated) VALUES (?,?,?)`,
			ws, string(info.ID), truncated); err != nil {
			return err
		}
		if info.SuspectedInjection {
			return addStatus(ctx, tx, ws, info.ID, "suspected_injection", t.RecordedAt)
		}
		return nil
	})
	if err != nil {
		return EvidenceInfo{}, err
	}
	// The row may predate this call, so return what is stored.
	return s.Read(ctx, ev.Workspace, info.ID)
}

// Read returns the evidence row. If its content does not match its digest, or
// it was already flagged corrupt, Read returns ErrEvidenceIntegrity and no
// content. The first detection records `corrupt` in evidence_status and
// retracts every candidate or confirmed relation whose only non-corrupt
// evidence is this row. Rows are kept for audit.
func (s EvidenceStore) Read(ctx context.Context, ws WorkspaceID, id EvidenceID) (EvidenceInfo, error) {
	var (
		info                       EvidenceInfo
		content, digest            []byte
		event                      sql.NullString
		recorded, observed         string
		kind, trust                string
		truncated, corrupt, inject bool
	)
	err := s.Store.DB().QueryRowContext(ctx,
		`SELECT e.kind, e.content, e.content_sha256, e.locator, e.trust, e.event_time, e.recorded_at,
		        e.observed_at, e.source_revision,
		        COALESCE((SELECT f.truncated FROM evidence_flag f WHERE f.workspace_id = e.workspace_id AND f.evidence_id = e.id), 0),
		        EXISTS (SELECT 1 FROM evidence_status x WHERE x.workspace_id = e.workspace_id AND x.evidence_id = e.id AND x.status = 'corrupt'),
		        EXISTS (SELECT 1 FROM evidence_status x WHERE x.workspace_id = e.workspace_id AND x.evidence_id = e.id AND x.status = 'suspected_injection')
		 FROM evidence e WHERE e.workspace_id = ? AND e.id = ?`,
		string(ws), string(id)).Scan(&kind, &content, &digest, &info.Locator, &trust, &event, &recorded,
		&observed, &info.Temporal.SourceRevision, &truncated, &corrupt, &inject)
	if errors.Is(err, sql.ErrNoRows) {
		return EvidenceInfo{}, ErrEvidenceNotFound
	}
	if err != nil {
		return EvidenceInfo{}, err
	}
	sum := sha256.Sum256(content)
	if corrupt || len(digest) != sha256.Size || string(digest) != string(sum[:]) ||
		string(id) != "ev:"+hex.EncodeToString(sum[:]) {
		if !corrupt {
			if err := s.markCorrupt(ctx, ws, id); err != nil {
				return EvidenceInfo{}, err
			}
		}
		return EvidenceInfo{}, fmt.Errorf("%w: %s", ErrEvidenceIntegrity, id)
	}
	info.ID, info.Workspace, info.Kind, info.Trust = id, ws, EvidenceKind(kind), Trust(trust)
	info.Content, info.ContentSHA256 = content, sum
	info.Truncated, info.SuspectedInjection = truncated, inject
	if info.Temporal.RecordedAt, err = time.Parse(time.RFC3339Nano, recorded); err != nil {
		return EvidenceInfo{}, err
	}
	if info.Temporal.ObservedAt, err = time.Parse(time.RFC3339Nano, observed); err != nil {
		return EvidenceInfo{}, err
	}
	if event.Valid {
		et, err := time.Parse(time.RFC3339Nano, event.String)
		if err != nil {
			return EvidenceInfo{}, err
		}
		info.Temporal.EventTime = &et
	}
	return info, nil
}

func (s EvidenceStore) markCorrupt(ctx context.Context, ws WorkspaceID, id EvidenceID) error {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	return s.Store.Write(ctx, string(ws), func(tx *sql.Tx) error {
		if err := addStatus(ctx, tx, string(ws), id, "corrupt", now()); err != nil {
			return err
		}
		// Every relation that cites this row and has no other non-corrupt
		// evidence loses its evidence support. The state machine only allows
		// confirmed -> retracted and candidate -> retracted.
		_, err := tx.ExecContext(ctx,
			`UPDATE relation SET state = 'retracted'
			 WHERE workspace_id = ? AND state IN ('candidate','confirmed')
			   AND id IN (SELECT relation_id FROM relation_evidence WHERE workspace_id = ? AND evidence_id = ?)
			   AND NOT EXISTS (
			     SELECT 1 FROM relation_evidence re
			     WHERE re.workspace_id = relation.workspace_id AND re.relation_id = relation.id
			       AND re.evidence_id <> ?
			       AND NOT EXISTS (SELECT 1 FROM evidence_status x
			         WHERE x.workspace_id = re.workspace_id AND x.evidence_id = re.evidence_id AND x.status = 'corrupt'))`,
			string(ws), string(ws), string(id), string(id))
		return err
	})
}

func addStatus(ctx context.Context, tx *sql.Tx, ws string, id EvidenceID, status string, at time.Time) error {
	_, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO evidence_status (workspace_id, evidence_id, status, noted_at) VALUES (?,?,?,?)`,
		ws, string(id), status, utc(at))
	return err
}

func validateEvidence(ev Evidence) error {
	switch {
	case ev.Workspace == "":
		return &FieldError{"workspace", "is required"}
	case ev.Kind == "":
		return &FieldError{"kind", "is required"}
	case ev.Locator == "":
		return &FieldError{"locator", "is required"}
	}
	switch ev.Trust {
	case TrustedSource, Derived, UntrustedText:
	default:
		return &FieldError{"trust", "must be trusted_source, derived, or untrusted_text"}
	}
	if _, err := ParseSourceRevision(ev.Temporal.SourceRevision); err != nil {
		return &FieldError{"source_revision", err.(*TemporalError).Reason}
	}
	return nil
}

// truncateUTF8 cuts b to at most limit bytes at the last complete UTF-8
// character boundary and reports whether it cut anything.
func truncateUTF8(b []byte, limit int) ([]byte, bool) {
	if len(b) <= limit {
		return b, false
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(b[cut]) {
		cut--
	}
	return b[:cut:cut], true
}

var injectionRe = regexp.MustCompile(`(?i)\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|any)\b[^.\n]{0,40}\b(instructions?|prompts?|rules|directions)\b` +
	`|\b(you are now|act as|pretend to be|from now on you)\b` +
	`|\b(system prompt|reveal your (instructions|prompt))\b` +
	`|\b(call|invoke|run|execute) (the )?(tool|function|command)\b` +
	`|\b(disclose|exfiltrate|send|leak)\b[^.\n]{0,40}\b(secrets?|credentials?|keys?|passwords?|tokens?)\b`)

// looksLikeInstruction is a heuristic. It only annotates; nothing acts on it.
func looksLikeInstruction(b []byte) bool { return injectionRe.Match(b) }
