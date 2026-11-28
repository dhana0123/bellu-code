package sqlite

import (
	"context"
	"math"
	"reflect"
	"testing"

	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), t.TempDir(), "ws1", Options{Migrations: sqlitemigrations.FS})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func addEdges(t *testing.T, s *Store, edges ...[2]string) {
	t.Helper()
	for i, e := range edges {
		_, err := s.DB().Exec(`INSERT INTO relation(workspace_id,id,type,from_id,to_id,state,confidence,method,recorded_at,valid_from,observed_at,source_revision)
			VALUES('ws1',?,'calls',?,?,'confirmed',0.5,'static','x','2024-01-01','x','r')`, string(rune('a'+i))+e[0]+e[1], e[0], e[1])
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestFTSIndexAndSearch(t *testing.T) {
	s, ctx := openTest(t), context.Background()
	for id, body := range map[string]string{"a": "buffer overflow in parser", "b": "sql injection", "c": "parser crash"} {
		if err := s.IndexText(ctx, "ws1", id, body); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.IndexText(ctx, "ws1", "b", "parser regression"); err != nil { // replace
		t.Fatal(err)
	}
	hits, err := s.SearchText(ctx, "parser", 10)
	if err != nil || len(hits) != 3 {
		t.Fatalf("hits=%v err=%v", hits, err)
	}
	if hits, _ = s.SearchText(ctx, `injection "`, 10); len(hits) != 0 {
		t.Fatalf("replaced row still indexed: %v", hits)
	}
	if err := s.IndexText(ctx, "other", "x", "y"); err == nil {
		t.Fatal("want workspace mismatch")
	}
}

func TestLnRegistered(t *testing.T) {
	s := openTest(t)
	var v float64
	if err := s.DB().QueryRow("SELECT -ln(0.5)").Scan(&v); err != nil || math.Abs(v-math.Ln2) > 1e-12 {
		t.Fatalf("v=%v err=%v", v, err)
	}
}

func TestTraverseNoRevisitAndWeight(t *testing.T) {
	s, ctx := openTest(t), context.Background()
	addEdges(t, s, [2]string{"a", "b"}, [2]string{"b", "c"}, [2]string{"c", "a"})
	res, err := s.Traverse(ctx, "a", TraverseOptions{})
	if err != nil || res.Truncated {
		t.Fatalf("%+v %v", res, err)
	}
	var paths [][]string
	for _, r := range res.Rows {
		paths = append(paths, r.Path)
	}
	want := [][]string{{"a"}, {"a", "b"}, {"a", "b", "c"}}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("paths=%v", paths)
	}
	if math.Abs(res.Rows[2].Weight-2*math.Ln2) > 1e-9 {
		t.Fatalf("weight=%v", res.Rows[2].Weight)
	}
}

func TestTraverseLimits(t *testing.T) {
	s, ctx := openTest(t), context.Background()
	addEdges(t, s, [2]string{"a", "b"}, [2]string{"b", "c"}, [2]string{"c", "d"})
	res, _ := s.Traverse(ctx, "a", TraverseOptions{MaxDepth: 2})
	if !res.Truncated || res.Limit != LimitDepth || len(res.Rows) != 3 {
		t.Fatalf("depth: %+v", res)
	}
	res, _ = s.Traverse(ctx, "a", TraverseOptions{MaxDepth: 3})
	if res.Truncated || len(res.Rows) != 4 {
		t.Fatalf("exact depth: %+v", res)
	}
	res, _ = s.Traverse(ctx, "a", TraverseOptions{RowCap: 2})
	if !res.Truncated || res.Limit != LimitRowCap || len(res.Rows) != 2 {
		t.Fatalf("row cap: %+v", res)
	}
	res, _ = s.Traverse(ctx, "a", TraverseOptions{RowCap: 4})
	if res.Truncated || len(res.Rows) != 4 {
		t.Fatalf("exact cap: %+v", res)
	}
	if _, err := s.Traverse(ctx, "a", TraverseOptions{MaxDepth: -1}); err == nil {
		t.Fatal("want error for negative limit")
	}
}
