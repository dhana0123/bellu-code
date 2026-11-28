package cveupdate

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
)

func openState(t *testing.T) *sqlite.Store {
	t.Helper()
	s, err := sqlite.Open(context.Background(), t.TempDir(), "ws1", sqlite.Options{Migrations: sqlitemigrations.FS})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestSyncStatusNoneInstalled(t *testing.T) {
	s, ctx, now := openState(t), context.Background(), time.Now()
	st, ok, err := LoadSyncStatus(ctx, s, now)
	if err != nil || ok || st != (SyncStatus{}) {
		t.Fatalf("got %+v %v %v", st, ok, err)
	}
	// A recorded check alone does not count as installed.
	if err := s.RecordCVECheck(ctx, now, `"e1"`); err != nil {
		t.Fatal(err)
	}
	if st, ok, _ = LoadSyncStatus(ctx, s, now); ok || st != (SyncStatus{}) {
		t.Fatalf("check-only row reported installed: %+v", st)
	}
	if got := FormatStatus(st, ok); got != "none installed\n" {
		t.Fatalf("got %q", got)
	}
}

func TestSyncStatusRoundTrip(t *testing.T) {
	s, ctx := openState(t), context.Background()
	built := time.Date(2024, 5, 1, 0, 0, 0, 0, time.UTC)
	inst := built.Add(2 * time.Hour)
	if err := s.RecordCVECheck(ctx, inst, `"e1"`); err != nil {
		t.Fatal(err)
	}
	err := s.PutCVEUpdateState(ctx, sqlite.CVEUpdateState{SnapshotID: "snap-2", BuiltAt: built, InstalledAt: inst,
		DeltaChainLen: 3, SchemaVersion: 1, Source: SourceImport})
	if err != nil {
		t.Fatal(err)
	}
	now := built.Add(50*time.Hour + 59*time.Minute)
	st, ok, err := LoadSyncStatus(ctx, s, now)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	want := SyncStatus{SnapshotID: "snap-2", BuiltAt: built, InstalledAt: inst, Age: 50 * time.Hour, SchemaVersion: 1,
		DeltaChainLen: 3, Source: "import", LastCheckAt: inst}
	if st != want || st.AgeHours() != 50 {
		t.Fatalf("got %+v", st)
	}
	row, _, _ := s.GetCVEUpdateState(ctx)
	if row.ETag != `"e1"` {
		t.Fatalf("etag lost: %q", row.ETag)
	}
	out := FormatStatus(st, true)
	for _, sub := range []string{"snap-2", "2024-05-01T00:00:00Z", "50 hours", "import", "delta chain:      3"} {
		if !strings.Contains(out, sub) {
			t.Errorf("output missing %q:\n%s", sub, out)
		}
	}
	// Check after install updates only the check time.
	later := now.Add(time.Hour)
	if err := s.RecordCVECheck(ctx, later, ""); err != nil {
		t.Fatal(err)
	}
	st2, _, _ := LoadSyncStatus(ctx, s, now)
	if !st2.LastCheckAt.Equal(later) || st2.SnapshotID != "snap-2" {
		t.Fatalf("got %+v", st2)
	}
}

func TestPutCVEUpdateStateValidation(t *testing.T) {
	s, ctx := openState(t), context.Background()
	for _, st := range []sqlite.CVEUpdateState{
		{Source: "download"},
		{SnapshotID: "a", Source: "ftp"},
		{SnapshotID: "a", Source: "mirror", DeltaChainLen: -1},
	} {
		if err := s.PutCVEUpdateState(ctx, st); err == nil {
			t.Errorf("accepted %+v", st)
		}
	}
	if _, ok, _ := s.GetCVEUpdateState(ctx); ok {
		t.Fatal("row written by rejected put")
	}
}
