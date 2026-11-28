package sqlite

import (
	"context"
	"errors"
	"testing"

	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
)

const testModel = "m1"

func newFlat(t *testing.T, dim int) (*SQLiteFlat, *Store) {
	t.Helper()
	s, err := Open(context.Background(), t.TempDir(), "ws1", Options{Migrations: sqlitemigrations.FS})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	f, err := NewSQLiteFlat(s, testModel, dim)
	if err != nil {
		t.Fatal(err)
	}
	return f, s
}

func upsert(t *testing.T, f *SQLiteFlat, id string, v ...float32) {
	t.Helper()
	if err := f.Upsert(context.Background(), "ws1", id, testModel, "r1", v); err != nil {
		t.Fatal(err)
	}
}

func ids(hits []VecHit) []string {
	out := make([]string, len(hits))
	for i, h := range hits {
		out[i] = h.ID
	}
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestFlatSearchOrdersByCosineDescending(t *testing.T) {
	f, _ := newFlat(t, 2)
	upsert(t, f, "far", 0, 1)
	upsert(t, f, "near", 1, 0.1)
	upsert(t, f, "mid", 1, 1)
	hits, err := f.Search(context.Background(), "ws1", []float32{1, 0}, 10, VecFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(hits); !equal(got, []string{"near", "mid", "far"}) {
		t.Fatalf("order = %v", got)
	}
	for i := 1; i < len(hits); i++ {
		if hits[i-1].Score < hits[i].Score {
			t.Fatalf("scores not descending: %v", hits)
		}
	}
}

func TestFlatSearchTiesOrderedByAscendingID(t *testing.T) {
	f, _ := newFlat(t, 2)
	// Same direction, different magnitude: identical cosine.
	upsert(t, f, "c", 2, 0)
	upsert(t, f, "a", 1, 0)
	upsert(t, f, "b", 3, 0)
	hits, err := f.Search(context.Background(), "ws1", []float32{1, 0}, 10, VecFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(hits); !equal(got, []string{"a", "b", "c"}) {
		t.Fatalf("ties = %v", got)
	}
}

func TestFlatSearchKBounds(t *testing.T) {
	f, _ := newFlat(t, 1)
	upsert(t, f, "a", 1)
	upsert(t, f, "b", 2)
	upsert(t, f, "c", 3)
	ctx := context.Background()

	for _, k := range []int{0, -1, MaxSearchK + 1} {
		if _, err := f.Search(ctx, "ws1", []float32{1}, k, VecFilter{}); !errors.Is(err, ErrInvalidK) {
			t.Errorf("k=%d: got %v, want ErrInvalidK", k, err)
		}
	}
	hits, err := f.Search(ctx, "ws1", []float32{1}, 1, VecFilter{})
	if err != nil || len(hits) != 1 {
		t.Fatalf("k=1: %v, %v", hits, err)
	}
	hits, err = f.Search(ctx, "ws1", []float32{1}, MaxSearchK, VecFilter{})
	if err != nil || len(hits) != 3 {
		t.Fatalf("k=1000: %v, %v", hits, err)
	}
}

func TestFlatDimensionMismatchLeavesTableUnchanged(t *testing.T) {
	f, _ := newFlat(t, 3)
	ctx := context.Background()
	upsert(t, f, "a", 1, 2, 3)

	if err := f.Upsert(ctx, "ws1", "a", testModel, "r2", []float32{9, 9}); !errors.Is(err, ErrDimensionMismatch) {
		t.Fatalf("upsert update: got %v", err)
	}
	if err := f.Upsert(ctx, "ws1", "new", testModel, "r2", []float32{1, 2, 3, 4}); !errors.Is(err, ErrDimensionMismatch) {
		t.Fatalf("upsert insert: got %v", err)
	}
	if _, err := f.Search(ctx, "ws1", []float32{1}, 5, VecFilter{}); !errors.Is(err, ErrDimensionMismatch) {
		t.Fatalf("search: got %v", err)
	}
	if n := f.Info().Count; n != 1 {
		t.Fatalf("count = %d, want 1", n)
	}
	hits, err := f.Search(ctx, "ws1", []float32{1, 2, 3}, 5, VecFilter{SourceRevision: "r1"})
	if err != nil || len(hits) != 1 || hits[0].ID != "a" {
		t.Fatalf("stored row changed: %v, %v", hits, err)
	}
}

func TestFlatUpsertReplacesDeleteRemovesAndInfo(t *testing.T) {
	f, _ := newFlat(t, 2)
	ctx := context.Background()
	upsert(t, f, "a", 1, 0)
	upsert(t, f, "a", 0, 1)
	info := f.Info()
	if info.Implementation != "sqliteFlat" || info.Model != testModel || info.Dimension != 2 || info.Count != 1 {
		t.Fatalf("info = %+v", info)
	}
	hits, _ := f.Search(ctx, "ws1", []float32{0, 1}, 1, VecFilter{})
	if len(hits) != 1 || hits[0].Score < 0.999 {
		t.Fatalf("upsert did not replace: %v", hits)
	}
	if err := f.Delete(ctx, "ws1", "a"); err != nil {
		t.Fatal(err)
	}
	if err := f.Delete(ctx, "ws1", "missing"); err != nil {
		t.Fatalf("deleting missing id: %v", err)
	}
	if n := f.Info().Count; n != 0 {
		t.Fatalf("count = %d", n)
	}
}

func TestFlatRejectsNonFiniteAndWrongModel(t *testing.T) {
	f, _ := newFlat(t, 1)
	ctx := context.Background()
	nan := float32(0)
	nan = nan / nan
	if err := f.Upsert(ctx, "ws1", "a", testModel, "r", []float32{nan}); !errors.Is(err, ErrInvalidVector) {
		t.Fatalf("nan: %v", err)
	}
	if err := f.Upsert(ctx, "ws1", "a", "other", "r", []float32{1}); err == nil {
		t.Fatal("wrong model accepted")
	}
	if n := f.Info().Count; n != 0 {
		t.Fatalf("count = %d", n)
	}
}
