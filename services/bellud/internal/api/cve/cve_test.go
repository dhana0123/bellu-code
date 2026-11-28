package cve

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bskg"
	"github.com/bellu/bellucode/services/bellud/internal/bskg/bskgtest"
	"github.com/bellu/bellucode/services/bellud/internal/cvesource"
	"github.com/bellu/bellucode/services/bellud/internal/intel/store"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
)

const secretKey = "super-secret-bskg-key"

type env struct {
	h   http.Handler
	src *cvesource.DB
	db  *sqlite.Store
}

func setup(t *testing.T, mode cvesource.Mode, scanners, graphOn bool) env {
	t.Helper()
	ctx := context.Background()
	db, err := sqlite.Open(ctx, t.TempDir(), "ws1", sqlite.Options{Migrations: sqlitemigrations.FS})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	is, err := store.Open(filepath.Join(t.TempDir(), "intel"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { is.Close() })
	jsonl := `{"id":"CVE-2024-1000","summary":"lodash pollution","severity":"high","affected":[{"purl":"pkg:npm/lodash","ranges":[{"introduced":"0","fixed":"4.17.21"}]}]}` + "\n"
	if err := is.Replace(ctx, store.ImportInfo{Version: "v1", CreatedAt: time.Now()}, strings.NewReader(jsonl)); err != nil {
		t.Fatal(err)
	}
	srv := bskgtest.New(bskgtest.Options{})
	t.Cleanup(srv.Close)
	src, err := cvesource.New(cvesource.Options{Store: is, Mode: mode, Audit: db,
		BSKG: bskg.New(bskg.Config{URL: srv.URL, Key: secretKey, Timeout: 5 * time.Second})})
	if err != nil {
		t.Fatal(err)
	}
	return env{New(Deps{Source: src, Modes: src}, Flags{Scanners: scanners, Graph: graphOn}), src, db}
}

func do(h http.Handler, method, target, body string) (*httptest.ResponseRecorder, map[string]any) {
	r := httptest.NewRequest(method, Prefix+target, strings.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	return w, m
}

func TestLookupAndDetailDB(t *testing.T) {
	e := setup(t, cvesource.ModeDB, true, false)
	w, m := do(e.h, "GET", "/lookup?purl=pkg:npm/lodash&version=4.17.0", "")
	if w.Code != 200 || len(m["vulns"].([]any)) != 1 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	w, m = do(e.h, "GET", "/CVE-2024-1000", "")
	if w.Code != 200 || m["id"] != "CVE-2024-1000" || m["fieldFrom"].(map[string]any)["detail"] != "db" || m["gaps"] == nil || m["warnings"] == nil {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w, _ = do(e.h, "GET", "/CVE-1999-0001", ""); w.Code != 404 {
		t.Fatalf("missing id: %d", w.Code)
	}
	if w, _ = do(e.h, "GET", "/lookup", ""); w.Code != 400 {
		t.Fatalf("no query: %d", w.Code)
	}
}

func TestGraphEndpoint(t *testing.T) {
	e := setup(t, cvesource.ModeGraph, true, true)
	w, m := do(e.h, "GET", "/graph?id=CVE-2021-44228&depth=1&limit=10", "")
	if w.Code != 200 || len(m["nodes"].([]any)) == 0 || m["edges"] == nil {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w, _ = do(e.h, "GET", "/graph?id=CVE-2021-44228&depth=x", ""); w.Code != 400 {
		t.Fatalf("depth: %d", w.Code)
	}
}

func TestSetModeValidationAndAudit(t *testing.T) {
	e := setup(t, cvesource.ModeDB, true, true)
	w, m := do(e.h, "PUT", "/mode", `{"mode":"bogus"}`)
	if w.Code != 400 || m["field"] != "mode" || !strings.Contains(w.Body.String(), "db, graph, both") || e.src.Mode() != cvesource.ModeDB {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w, _ = do(e.h, "PUT", "/mode", `{"mode":"both"}`); w.Code != 200 || e.src.Mode() != cvesource.ModeBoth {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var n int
	var outcome string
	if err := e.db.DB().QueryRow(`SELECT count(*), max(detail) FROM audit WHERE action='cve.mode.set'`).Scan(&n, &outcome); err != nil || n != 1 || outcome != "db->both" {
		t.Fatalf("audit %d %q %v", n, outcome, err)
	}
}

func TestStatusHasNoKey(t *testing.T) {
	e := setup(t, cvesource.ModeGraph, true, true)
	do(e.h, "GET", "/graph?id=CVE-2021-44228", "")
	w, m := do(e.h, "GET", "/status", "")
	if w.Code != 200 || m["mode"] != "graph" || m["bskgReachable"] == nil || strings.Contains(w.Body.String(), secretKey) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestFlagGating(t *testing.T) {
	off := setup(t, cvesource.ModeDB, false, false)
	if w, _ := do(off.h, "GET", "/status", ""); w.Code != 404 {
		t.Fatalf("scanners off: %d", w.Code)
	}
	e := setup(t, cvesource.ModeDB, true, false)
	for _, c := range [][3]string{{"GET", "/CVE-2024-1000?mode=graph", ""}, {"GET", "/lookup?id=CVE-2024-1000&mode=both", ""}, {"GET", "/graph?id=CVE-2021-44228", ""}, {"PUT", "/mode", `{"mode":"graph"}`}} {
		if w, m := do(e.h, c[0], c[1], c[2]); w.Code != 400 || m["field"] != "mode" {
			t.Fatalf("%v: %d %s", c, w.Code, w.Body)
		}
	}
	if e.src.Mode() != cvesource.ModeDB {
		t.Fatal("mode changed")
	}
	if w, _ := do(e.h, "GET", "/CVE-2024-1000?mode=db", ""); w.Code != 200 {
		t.Fatalf("db mode: %d", w.Code)
	}
}
