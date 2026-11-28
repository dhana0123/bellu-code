package securitymcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/bom"
	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/scanners/sbomstore"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func setup(t *testing.T, d Deps) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	Extras(d)(srv)
	ct, st := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (map[string]any, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	text := res.Content[0].(*mcp.TextContent).Text
	var out map[string]any
	if !res.IsError {
		if err := json.Unmarshal([]byte(text), &out); err != nil {
			t.Fatal(err)
		}
	}
	return out, res.IsError
}

func TestTools(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, t.TempDir(), "ws1", sqlite.Options{Migrations: sqlitemigrations.FS})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	fs := findings.New(db)
	mk := func(id string, sev findings.Severity) findings.Finding {
		return findings.Finding{ID: id, RuleID: "r1", Title: "t" + id, Category: "code_and_dependencies",
			Type: findings.TypeVulnerability, Severity: sev, AssetID: "asset1", Source: "grype"}
	}
	if _, err := fs.Report(ctx, findings.ScanRef{}, []findings.Finding{mk("a", findings.SevHigh), mk("b", findings.SevLow)}); err != nil {
		t.Fatal(err)
	}
	sb := sbomstore.New(db)
	v := "1.0"
	if err := sb.Put(ctx, "asset1", "d1", bom.SBOM{Packages: []bom.Package{
		{Name: "p1", Version: &v, Ecosystem: "npm", Licenses: []string{"MIT"}}, {Name: "p2", Ecosystem: "npm"}, {Name: "p3"}}}); err != nil {
		t.Fatal(err)
	}
	now := "2026-01-01T00:00:00.000000000Z"
	if _, err := db.DB().Exec(`INSERT INTO issue(id,workspace_id,rule_id,title,severity,risk_score,status,category,path,created_at,updated_at)
		VALUES('i1','ws1','r','T','high',50,'open','vulnerabilities','[]',?,?)`, now, now); err != nil {
		t.Fatal(err)
	}
	cs := setup(t, Deps{Findings: fs, IssueDB: db.DB(), SBOM: sb, FindingsOn: true, ScannersOn: true})

	out, bad := call(t, cs, ListFindings, map[string]any{"severity": "high"})
	items, _ := out["items"].([]any)
	if bad || len(items) != 1 || items[0].(map[string]any)["id"] != "a" {
		t.Fatalf("list: %v bad=%v", out, bad)
	}
	if out, _ := call(t, cs, ListFindings, map[string]any{"limit": 1}); len(out["items"].([]any)) != 1 || out["truncated"] != true {
		t.Fatalf("limit: %v", out)
	}
	out, bad = call(t, cs, GetIssue, map[string]any{"id": "i1"})
	if bad || out["title"] != "T" || out["risk_score"] != float64(50) {
		t.Fatalf("issue: %v", out)
	}
	if _, bad = call(t, cs, GetIssue, map[string]any{"id": "nope"}); !bad {
		t.Fatal("missing issue must be an error result")
	}
	out, bad = call(t, cs, GetSBOM, map[string]any{"asset_id": "asset1", "limit": 2})
	if bad || out["package_count"] != float64(3) || len(out["packages"].([]any)) != 2 || out["truncated"] != true ||
		out["ecosystems"].(map[string]any)["npm"] != float64(2) {
		t.Fatalf("sbom: %v bad=%v", out, bad)
	}
	if _, bad = call(t, cs, GetSBOM, map[string]any{"asset_id": "zzz"}); !bad {
		t.Fatal("missing sbom must be an error result")
	}
	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range tools.Tools {
		if !tl.Annotations.ReadOnlyHint {
			t.Errorf("%s not read-only", tl.Name)
		}
	}
}

func TestGatingAndNames(t *testing.T) {
	for _, n := range Names() {
		for _, w := range []string{"set", "create", "update", "delete", "write", "add", "remove", "resolve", "ignore", "scan"} {
			if strings.Contains(n, "_"+w) {
				t.Errorf("tool %s implies a write", n)
			}
		}
	}
	cs := setup(t, Deps{FindingsOn: true, ScannersOn: true}) // no stores
	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil || len(tools.Tools) != 0 {
		t.Fatalf("no stores: %v %v", tools, err)
	}
}
