package findings

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
)

func projectorFixture(t *testing.T) (*Store, graph.Engine, string) {
	t.Helper()
	ctx := context.Background()
	db, err := sqlite.Open(ctx, t.TempDir(), "ws1", sqlite.Options{Migrations: sqlitemigrations.FS})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s := New(db)
	t.Cleanup(s.Close)
	e, err := graph.Open(ctx, graph.Config{Enabled: true, Dir: filepath.Join(t.TempDir(), "g"), Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close(ctx) })
	if _, err := e.Ingest().Apply(ctx, batch.Batch{Collector: "host", Entities: []batch.Entity{
		{Type: "host", Identity: map[string]string{"hostname": "h1"}}}}); err != nil {
		t.Fatal(err)
	}
	asset, err := identity.Hash("host", map[string]string{"hostname": "h1"})
	if err != nil {
		t.Fatal(err)
	}
	return s, e, string(asset)
}

func findingCount(t *testing.T, e graph.Engine) int {
	t.Helper()
	p, err := e.Query().Find(context.Background(), graph.FindQuery{Type: "finding"})
	if err != nil {
		t.Fatal(err)
	}
	return p.Total
}

func TestProjectOpenAppearsResolvedDisappears(t *testing.T) {
	ctx := context.Background()
	s, e, asset := projectorFixture(t)
	p := NewProjector(s, e)

	f := sample("f1")
	f.AssetID = asset
	orphan := sample("f2") // asset is not in the graph: skipped, batch still applies
	if _, err := s.Report(ctx, ScanRef{JobID: "j"}, []Finding{f, orphan}); err != nil {
		t.Fatal(err)
	}
	if err := p.Project(ctx); err != nil {
		t.Fatal(err)
	}
	if n := findingCount(t, e); n != 1 {
		t.Fatalf("findings in graph = %d, want 1", n)
	}
	fid, _ := identity.Hash("finding", map[string]string{"id": "f1"})
	edges, err := e.Query().Neighbors(ctx, graph.EntityID(fid), graph.NeighborOpts{})
	if err != nil || len(edges.Items) != 1 || edges.Items[0].Type != "affects" {
		t.Fatalf("edges = %+v, %v", edges.Items, err)
	}

	if _, err := s.ResolveMissing(ctx, ScanRef{JobID: "j2"}, asset, "grype", map[string]struct{}{}); err != nil {
		t.Fatal(err)
	}
	if err := p.Project(ctx); err != nil {
		t.Fatal(err)
	}
	if n := findingCount(t, e); n != 0 {
		t.Fatalf("findings in graph after resolve = %d, want 0", n)
	}
}

func TestRunProjectsChangesAndResyncs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, e, asset := projectorFixture(t)
	p := NewProjector(s, e, WithProjectorTiming(20*time.Millisecond, time.Second, 50*time.Millisecond))
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()

	f := sample("f1")
	f.AssetID = asset
	if _, err := s.Report(ctx, ScanRef{JobID: "j"}, []Finding{f}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for findingCount(t, e) != 1 {
		if time.Now().After(deadline) {
			t.Fatal("finding never projected")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
}
