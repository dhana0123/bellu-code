package contract_test

import (
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/contract"
	"github.com/bellu/bellucode/services/bellud/internal/server/routes"
)

// registry is the Go handler registry hook. Nil today: only Stage 0 (native graph) is go.
var registry contract.HandlerFor

func TestOwnerGate(t *testing.T) {
	table := routes.MustLoadEmbedded()
	fixtures, err := contract.LoadFixtures("testdata")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range contract.GateViolations(table, fixtures, registry, contract.Options{}) {
		t.Error(v)
	}
}

func TestOwnerGateStage0OnlyGraph(t *testing.T) {
	n := 0
	for _, r := range routes.MustLoadEmbedded().Routes() {
		if r.Owner != routes.OwnerGo {
			continue
		}
		n++
		if !strings.HasPrefix(r.Pattern, "/api/experimental/graph") && !strings.HasPrefix(r.Pattern, "/api/experimental/connectors") {
			t.Errorf("go-owned route outside Stage 0: %s %s", r.Method, r.Pattern)
		}
	}
	if n == 0 {
		t.Error("expected graph routes owned by go")
	}
}

func TestOwnerGateStageOrder(t *testing.T) {
	for i, s := range contract.Stages {
		if s.Index != i {
			t.Errorf("stage %q index %d != position %d", s.Name, s.Index, i)
		}
		if s.Promoted && i != 0 {
			t.Errorf("stage %d promoted before gate evidence; only Stage 0 may be promoted", i)
		}
	}
	last := contract.Stages[len(contract.Stages)-1]
	if len(last.Groups) != 1 || last.Groups[0] != "session" {
		t.Errorf("LLM session runtime must be the last stage, got %+v", last)
	}
	// Every route resolves to a stage.
	for _, r := range routes.MustLoadEmbedded().Routes() {
		if _, ok := contract.StageOf(r); !ok {
			t.Errorf("route %s %s (group %s) has no stage", r.Method, r.Pattern, r.Group)
		}
	}
}

func TestGateFailsOnUnpromotedGoRoute(t *testing.T) {
	tbl, err := routes.NewTable([]routes.Route{{Method: "GET", Pattern: "/api/info", Group: "server", Owner: routes.OwnerGo}})
	if err != nil {
		t.Fatal(err)
	}
	if v := contract.GateViolations(tbl, nil, nil, contract.Options{}); len(v) != 1 {
		t.Errorf("expected 1 violation, got %v", v)
	}
	_ = http.StatusOK
}

// Go must never open the TS SQLite store (bellucode-local.db compat name); session
// data comes from the child API. SQLite is allowed only in the packages below: the
// embedded per-workspace SQLite system of record of the three-graph design
// (Requirement 18) and the CVE update/adapter packages. Everywhere else it stays forbidden.
var sqliteAllowed = []string{
	"internal/store/sqlite",
	"migrations/sqlite",
	"internal/cveupdate",
	"internal/cvelocal",
}

var sqliteForbidden = regexp.MustCompile(`bellucode-local\.db|bellucode\.db|mattn/go-sqlite3|modernc\.org/sqlite|crawshaw|zombiezen\.com/go/sqlite|ncruces/go-sqlite3|"database/sql"`)

func TestNoSQLiteAccess(t *testing.T) {
	for _, v := range sqliteViolations(t, filepath.Join("..", "..")) {
		t.Error(v)
	}
}

// A package outside the allowlist that imports SQLite must still be reported, while an
// allowed one must not.
func TestNoSQLiteAccessForbiddenPackageFails(t *testing.T) {
	root := t.TempDir()
	src := "package x\n\nimport _ \"modernc.org/sqlite\"\n"
	for _, dir := range []string{"internal/lens", "internal/store/sqlite"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, dir, "x.go"), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	v := sqliteViolations(t, root)
	if len(v) != 1 || !strings.Contains(v[0], "lens") {
		t.Errorf("expected exactly one violation in internal/lens, got %v", v)
	}
}

func sqliteViolations(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if n := d.Name(); n == "vendor" || n == "testdata" || n == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		for _, a := range sqliteAllowed {
			if rel == a || strings.HasPrefix(rel, a+"/") {
				return nil
			}
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") || strings.HasSuffix(p, "stages.go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(b), "\n") {
			code := line
			if j := strings.Index(code, "//"); j >= 0 && !strings.Contains(code[:j], `"`) {
				code = code[:j]
			}
			if t := strings.TrimSpace(code); strings.HasPrefix(t, "*") || strings.HasPrefix(t, "/*") {
				continue
			}
			if m := sqliteForbidden.FindString(code); m != "" {
				out = append(out, fmt.Sprintf("%s:%d references %q", p, i+1, m))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
