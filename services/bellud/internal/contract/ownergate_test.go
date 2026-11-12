package contract_test

import (
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
		if !strings.HasPrefix(r.Pattern, "/api/experimental/graph") {
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

// Go must never open the TS SQLite store (opencode-local.db compat name); session
// data comes from the child API.
func TestNoSQLiteAccess(t *testing.T) {
	forbidden := regexp.MustCompile(`opencode-local\.db|opencode\.db|mattn/go-sqlite3|modernc\.org/sqlite|crawshaw|zombiezen\.com/go/sqlite|ncruces/go-sqlite3|"database/sql"`)
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == "vendor" || n == "testdata" || n == "node_modules" {
				return filepath.SkipDir
			}
			return nil
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
			if m := forbidden.FindString(code); m != "" {
				t.Errorf("%s:%d references %q", p, i+1, m)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
