package syft

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bom"
	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/scanners"
	"github.com/bellu/bellucode/services/bellud/internal/scanners/sbomstore"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
	"github.com/bellu/bellucode/services/bellud/internal/testutil/noexternal"
	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
)

func TestMain(m *testing.M) { noexternal.Main(m) }

const testdata = "../testdata"

type recSink struct {
	errs    [][2]string
	batches []batch.Batch
}

func (s *recSink) Findings([]findings.Finding) error { return nil }
func (s *recSink) ScannerError(input, cause string) error {
	s.errs = append(s.errs, [2]string{input, cause})
	return nil
}
func (s *recSink) Seen(string) {}
func (s *recSink) Batch(b batch.Batch) error {
	s.batches = append(s.batches, b)
	return nil
}

func repo(name string) scanners.Target {
	return scanners.Target{Type: scanners.TargetRepository, ID: "repo-" + name, Path: filepath.Join(testdata, "repos", name)}
}

func find(s bom.SBOM, name string) (bom.Package, bool) {
	for _, p := range s.Packages {
		if strings.EqualFold(p.Name, name) {
			return p, true
		}
	}
	return bom.Package{}, false
}

func TestInfo(t *testing.T) {
	a := New()
	i := a.Info()
	if a.Kind() != scanners.KindSBOM || i.Name != "syft" || i.License != "Apache-2.0" || i.Version == "" {
		t.Fatalf("info = %+v kind %s", i, a.Kind())
	}
	for _, tt := range []scanners.TargetType{scanners.TargetRepository, scanners.TargetImage, scanners.TargetHost} {
		if !a.Applies(tt) {
			t.Errorf("Applies(%s) = false", tt)
		}
	}
	if a.Applies(scanners.TargetCloudAccount) || a.Applies(scanners.TargetCluster) {
		t.Error("applies to cloud account or cluster")
	}
}

func TestScanEcosystems(t *testing.T) {
	tests := []struct {
		dir       string
		ecosystem string
		want      map[string]string
	}{
		{"go", "golang", map[string]string{"golang.org/x/text": "v0.3.5", "gopkg.in/yaml.v2": "v2.2.2"}},
		{"npm", "npm", map[string]string{"lodash": "4.17.20", "minimist": "1.2.5"}},
		{"python", "pypi", map[string]string{"requests": "2.19.0", "PyYAML": "5.3", "urllib3": "1.24.1"}},
		{"java", "maven", map[string]string{"log4j-core": "2.14.1", "commons-collections": "3.2.1"}},
		{"rust", "cargo", map[string]string{"smallvec": "0.6.9", "time": "0.1.43"}},
		{"ruby", "gem", map[string]string{"rack": "2.0.5", "nokogiri": "1.10.3", "mini_portile2": "2.4.0"}},
		{"php", "composer", map[string]string{"guzzlehttp/guzzle": "6.3.0", "monolog/monolog": "1.25.1"}},
		{"dotnet", "nuget", map[string]string{"Newtonsoft.Json": "12.0.1", "log4net": "2.0.8"}},
		{"apk", "apk", map[string]string{"libcrypto1.1": "1.1.1k-r0", "busybox": "1.32.1-r5"}},
		{"deb", "deb", map[string]string{"zlib1g": "1:1.2.11.dfsg-2", "tzdata": "2021a-1+deb11u1"}},
	}
	for _, tt := range tests {
		t.Run(tt.dir, func(t *testing.T) {
			s, err := New().Scan(context.Background(), repo(tt.dir))
			if err != nil {
				t.Fatal(err)
			}
			for name, ver := range tt.want {
				p, ok := find(s, name)
				if !ok {
					t.Errorf("package %s not found in %d packages", name, len(s.Packages))
					continue
				}
				if p.Version == nil || *p.Version != ver {
					t.Errorf("%s version = %v, want %s", name, p.Version, ver)
				}
				if p.Purl == nil || !strings.HasPrefix(*p.Purl, "pkg:"+tt.ecosystem+"/") {
					t.Errorf("%s purl = %v, want type %s", name, p.Purl, tt.ecosystem)
				}
				if p.Ecosystem != tt.ecosystem {
					t.Errorf("%s ecosystem = %q, want %s", name, p.Ecosystem, tt.ecosystem)
				}
			}
		})
	}
}

func TestScanRpmFixtureIsEmpty(t *testing.T) {
	s, err := New().Scan(context.Background(), repo("rpm"))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Packages) != 0 {
		t.Fatalf("packages = %d, want 0", len(s.Packages))
	}
}

func TestScanImageTar(t *testing.T) {
	tg := scanners.Target{Type: scanners.TargetImage, ID: "img-1", Path: filepath.Join(testdata, "images", "sample.tar")}
	s, err := New().Scan(context.Background(), tg)
	if err != nil {
		t.Fatal(err)
	}
	apk, ok := find(s, "libcrypto1.1")
	if !ok || apk.Version == nil || *apk.Version != "1.1.1k-r0" {
		t.Fatalf("libcrypto1.1 = %+v, %v", apk, ok)
	}
	lodash, ok := find(s, "lodash")
	if !ok || lodash.Version == nil || *lodash.Version != "4.17.20" {
		t.Fatalf("lodash = %+v, %v", lodash, ok)
	}
	if apk.Properties["layer_digest"] == "" || lodash.Properties["layer_digest"] == "" {
		t.Errorf("layer digests: %v %v", apk.Properties, lodash.Properties)
	}
	if apk.Properties["layer_digest"] == lodash.Properties["layer_digest"] {
		t.Error("the two packages come from different layers")
	}
}

func TestAbsentFieldsStayNil(t *testing.T) {
	s, err := New().Scan(context.Background(), repo("npm"))
	if err != nil {
		t.Fatal(err)
	}
	p, ok := find(s, "lodash")
	if !ok {
		t.Fatal("lodash missing")
	}
	// The lock file has no integrity hash, supplier or layer.
	if p.Supplier != nil || len(p.Hashes) != 0 || p.Properties != nil {
		t.Errorf("absent fields set: supplier=%v hashes=%v props=%v", p.Supplier, p.Hashes, p.Properties)
	}
	for _, p := range s.Packages {
		if p.Version != nil && *p.Version == "" || p.Purl != nil && *p.Purl == "" {
			t.Errorf("empty string pointer on %s", p.Name)
		}
	}
	if got := nonEmpty(""); got != nil {
		t.Error("nonEmpty(\"\") must be nil")
	}
	// An apk record carries a maintainer-less entry in the fixture or one with it; either way
	// the supplier is nil or non-empty.
	a, err := New().Scan(context.Background(), repo("apk"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range a.Packages {
		if p.Supplier != nil && *p.Supplier == "" {
			t.Errorf("empty supplier on %s", p.Name)
		}
	}
}

func TestBatchOneRelationPerPackage(t *testing.T) {
	tests := []struct {
		target   scanners.Target
		rel      string
		assetEnt string
	}{
		{repo("npm"), "declares_dependency", "repository"},
		{scanners.Target{Type: scanners.TargetImage, ID: "img-1", Path: filepath.Join(testdata, "images", "sample.tar")}, "contained_in", "image"},
		{scanners.Target{Type: scanners.TargetHost, ID: "host-1", Path: filepath.Join(testdata, "repos", "deb")}, "contained_in", "host"},
	}
	for _, tt := range tests {
		t.Run(tt.rel+"/"+tt.assetEnt, func(t *testing.T) {
			sink := &recSink{}
			if err := New().Run(context.Background(), tt.target, sink); err != nil {
				t.Fatal(err)
			}
			if len(sink.batches) != 1 || len(sink.errs) != 0 {
				t.Fatalf("batches=%d errs=%v", len(sink.batches), sink.errs)
			}
			b := sink.batches[0]
			var pkgs, assets int
			for _, e := range b.Entities {
				switch e.Type {
				case "package":
					pkgs++
					if e.Attributes["canonical_key"] == nil && e.Attributes["name"] == nil {
						t.Errorf("package attrs: %v", e.Attributes)
					}
				case tt.assetEnt:
					assets++
				}
			}
			if pkgs == 0 || assets != 1 || len(b.Relations) != pkgs {
				t.Fatalf("packages=%d assets=%d relations=%d", pkgs, assets, len(b.Relations))
			}
			to := map[string]int{}
			for _, r := range b.Relations {
				if r.Type != tt.rel {
					t.Errorf("relation type %s, want %s", r.Type, tt.rel)
				}
				if tt.rel == "declares_dependency" {
					to[r.To]++
				} else {
					to[r.From]++
				}
			}
			for id, n := range to {
				if n != 1 {
					t.Errorf("package %s has %d relations", id, n)
				}
			}
		})
	}
}

func TestUnreadableAsset(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	for _, tg := range []scanners.Target{
		{Type: scanners.TargetRepository, ID: "repo-x", Path: missing},
		{Type: scanners.TargetImage, ID: "img-x", Path: missing + ".tar"},
	} {
		sink := &recSink{}
		err := New().Run(context.Background(), tg, sink)
		if err == nil {
			t.Fatal("want an error")
		}
		if !strings.Contains(err.Error(), `"`+tg.ID+`"`) || !strings.Contains(err.Error(), "no such file") {
			t.Errorf("error does not name asset and reason: %v", err)
		}
		if !errors.Is(err, scanners.ErrTargetUnreachable) {
			t.Errorf("error does not match ErrTargetUnreachable: %v", err)
		}
		if len(sink.errs) != 1 || sink.errs[0][0] != tg.ID || len(sink.batches) != 0 {
			t.Errorf("errs=%v batches=%d", sink.errs, len(sink.batches))
		}
	}
}

func TestCorruptImageNamesAsset(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.tar")
	if err := os.WriteFile(p, []byte("not a tar"), 0o600); err != nil {
		t.Fatal(err)
	}
	sink := &recSink{}
	err := New().Run(context.Background(), scanners.Target{Type: scanners.TargetImage, ID: "img-bad", Path: p}, sink)
	if err == nil || !strings.Contains(err.Error(), `"img-bad"`) {
		t.Fatalf("err = %v", err)
	}
	if len(sink.errs) != 1 || len(sink.batches) != 0 {
		t.Fatalf("errs=%v batches=%d", sink.errs, len(sink.batches))
	}
}

func TestDigestStable(t *testing.T) {
	ctx := context.Background()
	a := New()
	for _, tg := range []scanners.Target{
		repo("npm"),
		{Type: scanners.TargetImage, ID: "img-1", Path: filepath.Join(testdata, "images", "sample.tar")},
	} {
		d1, err := a.Digest(ctx, tg)
		if err != nil || d1 == "" {
			t.Fatalf("digest %s = %q, %v", tg.ID, d1, err)
		}
		d2, _ := a.Digest(ctx, tg)
		if d1 != d2 {
			t.Errorf("digest %s changed: %s vs %s", tg.ID, d1, d2)
		}
	}
}

func TestDigestChangesWithManifest(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "package.json")
	if err := os.WriteFile(file, []byte(`{"name":"a"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	tg := scanners.Target{Type: scanners.TargetRepository, ID: "r", Path: dir}
	d1, err := New().Digest(context.Background(), tg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(`{"name":"ab"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(file, time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	d2, _ := New().Digest(context.Background(), tg)
	if d1 == d2 {
		t.Error("digest did not change after the manifest changed")
	}
	if d, err := New().Digest(context.Background(), scanners.Target{Type: scanners.TargetHost, ID: "h", Path: dir}); d != "" || err != nil {
		t.Errorf("host digest = %q, %v; want empty", d, err)
	}
}

func TestNoNetwork(t *testing.T) {
	// The Java fixture would fetch parent POMs from Maven Central with the
	// default configuration. TestMain fails the run when anything dials out.
	if _, err := New().Scan(context.Background(), repo("java")); err != nil {
		t.Fatal(err)
	}
	if v := noexternal.Violations(); len(v) != 0 {
		t.Fatalf("external connections attempted: %v", v)
	}
}

func openStore(t *testing.T) *sbomstore.Store {
	t.Helper()
	db, err := sqlite.Open(context.Background(), t.TempDir(), "ws1", sqlite.Options{Migrations: sqlitemigrations.FS})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return sbomstore.New(db)
}

func TestRunSavesSnapshot(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	sink := &recSink{}
	tg := repo("npm")
	if err := New().WithStore(st).Run(ctx, tg, sink); err != nil {
		t.Fatal(err)
	}
	got, m, ok, err := st.Latest(ctx, tg.ID)
	if err != nil || !ok || len(got.Packages) == 0 || m.Digest == "" || len(sink.batches) != 1 {
		t.Fatalf("snapshot ok=%v err=%v pkgs=%d meta=%+v batches=%d", ok, err, len(got.Packages), m, len(sink.batches))
	}
}

// Validates: Requirements 5.12, 5.15.
func TestTimeoutKeepsPreviousSnapshot(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	tg := repo("npm")
	prev := bom.SBOM{Subject: tg.ID, Packages: []bom.Package{{Name: "old"}}}
	if err := st.Put(ctx, tg.ID, "d0", prev); err != nil {
		t.Fatal(err)
	}
	a := New().WithStore(st).WithTimeout(20 * time.Millisecond)
	cancelled := false
	a.scan = func(c context.Context, _ scanners.Target) (bom.SBOM, error) {
		<-c.Done()
		cancelled = true
		return bom.SBOM{}, c.Err()
	}
	sink := &recSink{}
	err := a.Run(ctx, tg, sink)
	if !errors.Is(err, context.DeadlineExceeded) || !cancelled {
		t.Fatalf("err = %v cancelled=%v", err, cancelled)
	}
	if len(sink.errs) != 1 || sink.errs[0][0] != tg.ID || !strings.Contains(sink.errs[0][1], "timeout") || len(sink.batches) != 0 {
		t.Fatalf("rows = %v batches=%d", sink.errs, len(sink.batches))
	}
	got, m, _, _ := st.Latest(ctx, tg.ID)
	if m.Digest != "d0" || len(got.Packages) != 1 || got.Packages[0].Name != "old" {
		t.Fatalf("snapshot changed: %+v %+v", got, m)
	}
}

func TestFailedScanKeepsPreviousSnapshot(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	tg := scanners.Target{Type: scanners.TargetRepository, ID: "repo-gone", Path: filepath.Join(t.TempDir(), "missing")}
	if err := st.Put(ctx, tg.ID, "d0", bom.SBOM{Packages: []bom.Package{{Name: "old"}}}); err != nil {
		t.Fatal(err)
	}
	sink := &recSink{}
	if err := New().WithStore(st).Run(ctx, tg, sink); err == nil {
		t.Fatal("want error")
	}
	got, m, _, _ := st.Latest(ctx, tg.ID)
	if len(sink.errs) != 1 || sink.errs[0][0] != tg.ID || m.Digest != "d0" || len(got.Packages) != 1 {
		t.Fatalf("rows=%v snapshot=%+v %+v", sink.errs, got, m)
	}
}
