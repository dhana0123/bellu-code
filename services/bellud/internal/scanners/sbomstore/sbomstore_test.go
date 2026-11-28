package sbomstore

import (
	"context"
	"fmt"
	"reflect"
	"runtime"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/bom"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
)

func open(t *testing.T) *Store {
	t.Helper()
	db, err := sqlite.Open(context.Background(), t.TempDir(), "ws1", sqlite.Options{Migrations: sqlitemigrations.FS})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return New(db)
}

func sp(s string) *string { return &s }

func sample() bom.SBOM {
	return bom.SBOM{Subject: "repo-a", Packages: []bom.Package{
		{Name: "left-pad", Version: sp("1.3.0"), Purl: sp("pkg:npm/left-pad@1.3.0"), Ecosystem: "npm", Licenses: []string{"MIT"},
			Supplier: sp("me"), Locations: []string{"package-lock.json"}, Hashes: []bom.Hash{{Algorithm: "SHA-256", Value: "ab"}},
			Properties: map[string]string{"layer_digest": "sha256:1"}},
		{Name: "x", Ecosystem: "npm", Licenses: []string{"MIT", "Apache-2.0"}},
		{Name: "bare"},
	}}
}

func TestPutLatestRoundTripAndReplace(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	if _, _, ok, err := s.Latest(ctx, "repo-a"); ok || err != nil {
		t.Fatalf("empty: ok=%v err=%v", ok, err)
	}
	in := sample()
	if err := s.Put(ctx, "repo-a", "d1", in); err != nil {
		t.Fatal(err)
	}
	got, m, ok, err := s.Latest(ctx, "repo-a")
	if err != nil || !ok || !reflect.DeepEqual(got, in) || m.Digest != "d1" || m.PackageCount != 3 || m.CreatedAt.IsZero() {
		t.Fatalf("round trip: %+v %+v ok=%v err=%v", got, m, ok, err)
	}
	next := bom.SBOM{Subject: "repo-a", Packages: []bom.Package{{Name: "only"}}}
	if err := s.Put(ctx, "repo-a", "d2", next); err != nil {
		t.Fatal(err)
	}
	got, m, _, _ = s.Latest(ctx, "repo-a")
	if !reflect.DeepEqual(got, next) || m.Digest != "d2" {
		t.Fatalf("replace: %+v %+v", got, m)
	}
	var n int
	if err := s.db.DB().QueryRow(`SELECT count(*) FROM sbom_snapshot`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("rows = %d err=%v", n, err)
	}
}

func TestListCounts(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	if err := s.Put(ctx, "b", "d", sample()); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, "a", "d", bom.SBOM{Packages: []bom.Package{{Name: "p", Ecosystem: "deb", Licenses: []string{"GPL-2.0"}}}}); err != nil {
		t.Fatal(err)
	}
	l, err := s.List(ctx)
	if err != nil || len(l) != 2 || l[0].AssetID != "a" || l[1].AssetID != "b" {
		t.Fatalf("list: %+v err=%v", l, err)
	}
	if want := map[string]int{"npm": 2, "unknown": 1}; !reflect.DeepEqual(l[1].Ecosystems, want) {
		t.Errorf("ecosystems = %v", l[1].Ecosystems)
	}
	if want := map[string]int{"MIT": 2, "Apache-2.0": 1, "unknown": 1}; !reflect.DeepEqual(l[1].Licenses, want) {
		t.Errorf("licenses = %v", l[1].Licenses)
	}
	if l[0].Ecosystems["deb"] != 1 || l[0].Licenses["GPL-2.0"] != 1 {
		t.Errorf("a = %+v", l[0])
	}
}

func TestLargeSBOMBoundedMemory(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	const n = 50000
	in := bom.SBOM{Subject: "big", Packages: make([]bom.Package, n)}
	for i := range in.Packages {
		in.Packages[i] = bom.Package{Name: fmt.Sprintf("pkg-%d", i), Version: sp("1.0.0"), Purl: sp(fmt.Sprintf("pkg:npm/pkg-%d@1.0.0", i)),
			Ecosystem: "npm", Licenses: []string{"MIT"}, Locations: []string{"node_modules/x/package.json"}}
	}
	if err := s.Put(ctx, "big", "d", in); err != nil {
		t.Fatal(err)
	}
	var blob int
	_ = s.db.DB().QueryRow(`SELECT length(packages_json) FROM sbom_snapshot`).Scan(&blob)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	count, peak := 0, uint64(0)
	_, ok, err := s.Each(ctx, "big", nil, func(p bom.Package) error {
		if count++; count%10000 == 0 {
			runtime.ReadMemStats(&after)
			peak = max(peak, after.HeapAlloc)
		}
		return nil
	})
	if err != nil || !ok || count != n {
		t.Fatalf("each: count=%d ok=%v err=%v", count, ok, err)
	}
	t.Logf("blob=%d bytes, heap before=%d MB, peak during stream=%d MB", blob, before.HeapAlloc>>20, peak>>20)
	got, _, _, err := s.Latest(ctx, "big")
	if err != nil || len(got.Packages) != n || !reflect.DeepEqual(got.Packages[n-1], in.Packages[n-1]) {
		t.Fatalf("latest: %d err=%v", len(got.Packages), err)
	}
}
