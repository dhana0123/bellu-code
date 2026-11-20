package cveupdate

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
)

// Install sources recorded in SyncStatus.
const (
	SourceDownload = sqlite.CVESourceDownload
	SourceMirror   = sqlite.CVESourceMirror
	SourceImport   = sqlite.CVESourceImport
)

// SyncStatus describes the installed CVE snapshot (Requirement 19.2). The
// retrieval cache key includes SnapshotID.
type SyncStatus struct {
	SnapshotID    string
	BuiltAt       time.Time
	InstalledAt   time.Time
	Age           time.Duration // since BuiltAt, a whole number of hours
	SchemaVersion int
	DeltaChainLen int
	Source        string // "download" | "mirror" | "import"
	LastCheckAt   time.Time
}

// AgeHours is the age in whole hours.
func (s SyncStatus) AgeHours() int { return int(s.Age / time.Hour) }

// StateStore records and reads the installed-snapshot state. *sqlite.Store
// implements it.
type StateStore interface {
	GetCVEUpdateState(ctx context.Context) (sqlite.CVEUpdateState, bool, error)
	PutCVEUpdateState(ctx context.Context, st sqlite.CVEUpdateState) error
	RecordCVECheck(ctx context.Context, at time.Time, etag string) error
}

// LoadSyncStatus reads SyncStatus from the local store without network
// access. installed is false when no snapshot is installed; the returned
// status is then the zero value. A build time in the future gives age 0.
func LoadSyncStatus(ctx context.Context, store StateStore, now time.Time) (st SyncStatus, installed bool, err error) {
	row, ok, err := store.GetCVEUpdateState(ctx)
	if err != nil || !ok || row.SnapshotID == "" {
		return SyncStatus{}, false, err
	}
	age := now.Sub(row.BuiltAt).Truncate(time.Hour)
	if age < 0 {
		age = 0
	}
	return SyncStatus{
		SnapshotID: row.SnapshotID, BuiltAt: row.BuiltAt, InstalledAt: row.InstalledAt, Age: age,
		SchemaVersion: row.SchemaVersion, DeltaChainLen: row.DeltaChainLen, Source: row.Source,
		LastCheckAt: row.LastCheckAt,
	}, true, nil
}

// FormatStatus renders what `bellu cve status` prints. With no snapshot
// installed it is exactly "none installed".
func FormatStatus(st SyncStatus, installed bool) string {
	if !installed {
		return "none installed\n"
	}
	ts := func(t time.Time) string {
		if t.IsZero() {
			return "never"
		}
		return t.UTC().Format(time.RFC3339)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "snapshot id:      %s\n", st.SnapshotID)
	fmt.Fprintf(&b, "built:            %s\n", ts(st.BuiltAt))
	fmt.Fprintf(&b, "installed:        %s\n", ts(st.InstalledAt))
	fmt.Fprintf(&b, "age:              %d hours\n", st.AgeHours())
	fmt.Fprintf(&b, "schema version:   %d\n", st.SchemaVersion)
	fmt.Fprintf(&b, "delta chain:      %d\n", st.DeltaChainLen)
	fmt.Fprintf(&b, "source:           %s\n", st.Source)
	fmt.Fprintf(&b, "last check:       %s\n", ts(st.LastCheckAt))
	return b.String()
}

// recordInstall writes cve_update_state after a successful swap.
func recordInstall(ctx context.Context, store StateStore, dir, source string, res Result, now time.Time) error {
	schema, err := snapshotSchemaVersion(ctx, dir+"/current")
	if err != nil {
		return err
	}
	return store.PutCVEUpdateState(ctx, sqlite.CVEUpdateState{
		SnapshotID: res.State.InstalledID, BuiltAt: res.State.CreatedAt, InstalledAt: now,
		LastCheckAt: now, DeltaChainLen: len(res.State.AppliedDeltas), SchemaVersion: schema, Source: source,
	})
}

func snapshotSchemaVersion(ctx context.Context, dir string) (int, error) {
	db, err := sql.Open("sqlite", "file:"+dir+"/graph.db?mode=ro")
	if err != nil {
		return 0, err
	}
	defer db.Close()
	var v int
	err = db.QueryRowContext(ctx, `SELECT CAST(value AS INTEGER) FROM meta WHERE key='schema_version'`).Scan(&v)
	return v, err
}
