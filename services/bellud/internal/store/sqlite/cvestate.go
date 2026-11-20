package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// CVEUpdateState is the single row of cve_update_state: a local record of the
// installed CVE snapshot. It is never sent anywhere.
type CVEUpdateState struct {
	SnapshotID    string // empty: no snapshot installed
	BuiltAt       time.Time
	InstalledAt   time.Time
	LastCheckAt   time.Time
	ETag          string
	DeltaChainLen int
	SchemaVersion int
	Source        string // "download", "mirror" or "import"
}

// CVE update sources.
const (
	CVESourceDownload = "download"
	CVESourceMirror   = "mirror"
	CVESourceImport   = "import"
)

func validCVESource(s string) bool {
	return s == CVESourceDownload || s == CVESourceMirror || s == CVESourceImport
}

func fmtTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

func parseTime(s sql.NullString) (time.Time, error) {
	if !s.Valid || s.String == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, s.String)
	return t.UTC(), err
}

// GetCVEUpdateState reads the row. ok is false when it does not exist. A row
// with an empty SnapshotID (only a check was recorded) means none installed.
func (s *Store) GetCVEUpdateState(ctx context.Context) (st CVEUpdateState, ok bool, err error) {
	var snap, built, inst, check, etag, src sql.NullString
	var chain, schema sql.NullInt64
	err = s.db.QueryRowContext(ctx, `SELECT snapshot_id, built_at, installed_at, last_check_at, last_etag,
		delta_chain_len, schema_version, source FROM cve_update_state WHERE workspace_id=? AND id=1`, s.workspaceID).
		Scan(&snap, &built, &inst, &check, &etag, &chain, &schema, &src)
	if errors.Is(err, sql.ErrNoRows) {
		return st, false, nil
	}
	if err != nil {
		return st, false, mapErr(err)
	}
	st.SnapshotID, st.ETag, st.Source = snap.String, etag.String, src.String
	st.DeltaChainLen, st.SchemaVersion = int(chain.Int64), int(schema.Int64)
	for _, f := range []struct {
		dst *time.Time
		src sql.NullString
	}{{&st.BuiltAt, built}, {&st.InstalledAt, inst}, {&st.LastCheckAt, check}} {
		if *f.dst, err = parseTime(f.src); err != nil {
			return CVEUpdateState{}, false, fmt.Errorf("sqlite: cve_update_state: %w", err)
		}
	}
	return st, true, nil
}

// PutCVEUpdateState records an installed snapshot. LastCheckAt and ETag
// replace the stored values only when set; otherwise the stored ones are kept.
func (s *Store) PutCVEUpdateState(ctx context.Context, st CVEUpdateState) error {
	switch {
	case st.SnapshotID == "":
		return errors.New("sqlite: cve_update_state: empty snapshot id")
	case st.DeltaChainLen < 0:
		return errors.New("sqlite: cve_update_state: negative delta chain length")
	case !validCVESource(st.Source):
		return fmt.Errorf("sqlite: cve_update_state: invalid source %q", st.Source)
	}
	var etag any
	if st.ETag != "" {
		etag = st.ETag
	}
	return s.Write(ctx, s.workspaceID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO cve_update_state
			(workspace_id,id,snapshot_id,built_at,installed_at,last_check_at,last_etag,delta_chain_len,schema_version,source)
			VALUES(?,1,?,?,?,?,?,?,?,?)
			ON CONFLICT(id) DO UPDATE SET snapshot_id=excluded.snapshot_id, built_at=excluded.built_at,
			  installed_at=excluded.installed_at, delta_chain_len=excluded.delta_chain_len,
			  schema_version=excluded.schema_version, source=excluded.source,
			  last_check_at=COALESCE(excluded.last_check_at, last_check_at),
			  last_etag=COALESCE(excluded.last_etag, last_etag)`,
			s.workspaceID, st.SnapshotID, fmtTime(st.BuiltAt), fmtTime(st.InstalledAt), fmtTime(st.LastCheckAt),
			etag, st.DeltaChainLen, st.SchemaVersion, st.Source)
		return err
	})
}

// RecordCVECheck stores the time of an index check and, when etag is not
// empty, the index ETag. It never changes the installed-snapshot fields.
func (s *Store) RecordCVECheck(ctx context.Context, at time.Time, etag string) error {
	var e any
	if etag != "" {
		e = etag
	}
	return s.Write(ctx, s.workspaceID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO cve_update_state(workspace_id,id,last_check_at,last_etag)
			VALUES(?,1,?,?)
			ON CONFLICT(id) DO UPDATE SET last_check_at=excluded.last_check_at,
			  last_etag=COALESCE(excluded.last_etag, last_etag)`, s.workspaceID, fmtTime(at), e)
		return err
	})
}
