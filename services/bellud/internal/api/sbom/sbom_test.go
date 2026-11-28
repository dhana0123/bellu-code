package sbom

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/bom"
	"github.com/bellu/bellucode/services/bellud/internal/scanners/sbomstore"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
)

func setup(t *testing.T, enabled bool) http.Handler {
	t.Helper()
	db, err := sqlite.Open(context.Background(), t.TempDir(), "ws1", sqlite.Options{Migrations: sqlitemigrations.FS})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	st := sbomstore.New(db)
	v, p := "1.3.0", "pkg:npm/left-pad@1.3.0"
	err = st.Put(context.Background(), "repo-a", "d1", bom.SBOM{Subject: "repo-a", Packages: []bom.Package{
		{Name: "left-pad", Version: &v, Purl: &p, Ecosystem: "npm", Licenses: []string{"MIT"}},
		{Name: "bare"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return New(st, enabled)
}

func do(h http.Handler, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	return rec
}

func TestListAndGet(t *testing.T) {
	h := setup(t, true)
	rec := do(h, Prefix)
	var l struct{ Items []wireSummary }
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &l) != nil || len(l.Items) != 1 || l.Items[0].Ecosystems["npm"] != 1 || l.Items[0].Licenses["MIT"] != 1 {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	rec = do(h, Prefix+"/repo-a?limit=1")
	var d wireDetail
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &d) != nil || len(d.Items) != 1 || d.NextCursor != "1" || d.PackageCount != 2 {
		t.Fatalf("get: %d %s", rec.Code, rec.Body)
	}
}

func TestExportRoundTrip(t *testing.T) {
	h := setup(t, true)
	rec := do(h, Prefix+"/repo-a/export?format=cyclonedx&version=1.5")
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Disposition"), "repo-a.cdx.json") {
		t.Fatalf("cdx: %d %v", rec.Code, rec.Header())
	}
	if s, err := bom.ReadCycloneDX(bytes.NewReader(rec.Body.Bytes())); err != nil || len(s.Packages) != 2 {
		t.Fatalf("read cdx: %v %d", err, len(s.Packages))
	}
	rec = do(h, Prefix+"/repo-a/export?format=spdx")
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Disposition"), ".spdx.json") {
		t.Fatalf("spdx: %d", rec.Code)
	}
	if s, err := bom.ReadSPDX(bytes.NewReader(rec.Body.Bytes())); err != nil || len(s.Packages) != 2 {
		t.Fatalf("read spdx: %v %d", err, len(s.Packages))
	}
}

func TestExportErrors(t *testing.T) {
	h := setup(t, true)
	if rec := do(h, Prefix+"/nope/export?format=spdx"); rec.Code != 404 {
		t.Fatalf("unknown asset: %d", rec.Code)
	}
	for _, q := range []string{"format=xml", "format=cyclonedx&version=9.9"} {
		rec := do(h, Prefix+"/repo-a/export?"+q)
		if rec.Code != 400 || !strings.Contains(rec.Body.String(), "supported:") || rec.Header().Get("Content-Disposition") != "" || strings.Contains(rec.Body.String(), "bomFormat") {
			t.Fatalf("%s: %d %s", q, rec.Code, rec.Body)
		}
	}
}

func TestDisabled(t *testing.T) {
	h := setup(t, false)
	for _, p := range []string{Prefix, Prefix + "/repo-a", Prefix + "/repo-a/export"} {
		if rec := do(h, p); rec.Code != 404 {
			t.Fatalf("%s: %d", p, rec.Code)
		}
	}
}
