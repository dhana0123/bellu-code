// Package securitymcp serves the read-only security tools on the bellu-graph
// MCP server (Requirement 20.7). No tool writes.
package securitymcp

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/bellu/bellucode/services/bellud/internal/bom"
	"github.com/bellu/bellucode/services/bellud/internal/cvesource"
	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
	"github.com/bellu/bellucode/services/bellud/internal/scanners/sbomstore"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Tool names.
const (
	ListFindings = "security_list_findings"
	GetIssue     = "security_get_issue"
	GetSBOM      = "security_get_sbom"
)

// Limits.
const (
	DefaultLimit = 50
	MaxLimit     = 200
	DefaultPkgs  = 50
	MaxPkgs      = 500
)

// Deps are the stores and flags. A tool registers only when its flag is on
// and its store is set.
type Deps struct {
	Findings   *findings.Store
	IssueDB    *sql.DB // read-only use: SELECT on issue
	SBOM       *sbomstore.Store
	CVE        cvesource.Source // read-only: Lookup and Detail
	FindingsOn bool             // security_findings
	ScannersOn bool             // security_scanners
}

// Names lists every tool this package can register.
func Names() []string { return []string{ListFindings, GetIssue, GetSBOM} }

// Extras returns a function for facade.Config.MCPExtras.
func Extras(d Deps) func(*mcp.Server) {
	return func(s *mcp.Server) {
		if d.FindingsOn && d.Findings != nil {
			add(s, ListFindings, "List security findings, optionally filtered by severity, status and category. Read-only.", listSchema,
				func(ctx context.Context, raw json.RawMessage) (any, error) { return listFindings(ctx, d.Findings, raw) })
		}
		if d.FindingsOn && d.IssueDB != nil {
			add(s, GetIssue, "Get one security issue by id. Read-only.", issueSchema,
				func(ctx context.Context, raw json.RawMessage) (any, error) { return getIssue(ctx, d.IssueDB, raw) })
		}
		if d.ScannersOn && d.SBOM != nil {
			add(s, GetSBOM, "Get the SBOM summary of an asset with its first packages. Read-only.", sbomSchema,
				func(ctx context.Context, raw json.RawMessage) (any, error) { return getSBOM(ctx, d.SBOM, raw) })
		}
		if d.ScannersOn && d.CVE != nil {
			add(s, QueryCVE, "Query a CVE by id, or by purl and optional version, from the local DB; with id and mode, return the detail view. Read-only.", cveSchema,
				func(ctx context.Context, raw json.RawMessage) (any, error) { return queryCVE(ctx, d.CVE, raw) })
		}
	}
}

func add(s *mcp.Server, name, desc string, schema map[string]any, fn func(context.Context, json.RawMessage) (any, error)) {
	s.AddTool(&mcp.Tool{
		Name: name, Description: desc, InputSchema: schema,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		out, err := fn(ctx, req.Params.Arguments)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, nil
		}
		b, err := json.Marshal(out)
		if err != nil {
			return nil, err
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil
	})
}

func obj(required []string, props map[string]any) map[string]any {
	return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": props}
}

var (
	listSchema = obj([]string{}, map[string]any{
		"severity": map[string]any{"type": "string", "enum": []string{"critical", "high", "medium", "low", "info"}},
		"status":   map[string]any{"type": "string", "enum": []string{"open", "in_progress", "resolved", "ignored", "accepted_risk"}},
		"category": map[string]any{"type": "string"},
		"limit":    map[string]any{"type": "integer", "minimum": 1, "maximum": MaxLimit, "default": DefaultLimit},
	})
	issueSchema = obj([]string{"id"}, map[string]any{"id": map[string]any{"type": "string"}})
	sbomSchema  = obj([]string{"asset_id"}, map[string]any{
		"asset_id": map[string]any{"type": "string"},
		"limit":    map[string]any{"type": "integer", "minimum": 1, "maximum": MaxPkgs, "default": DefaultPkgs},
	})
)

func decode(raw json.RawMessage, into any) error {
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if err := d.Decode(into); err != nil {
		return fmt.Errorf("invalid arguments: %w", err)
	}
	return nil
}

func clamp(n, def, max int, name string) (int, error) {
	if n == 0 {
		return def, nil
	}
	if n < 0 || n > max {
		return 0, fmt.Errorf("invalid %s: must be 1 to %d", name, max)
	}
	return n, nil
}

type findingOut struct {
	ID        string   `json:"id"`
	RuleID    string   `json:"rule_id"`
	Title     string   `json:"title"`
	Category  string   `json:"category"`
	Type      string   `json:"type"`
	Severity  string   `json:"severity"`
	Status    string   `json:"status"`
	AssetID   string   `json:"asset_id"`
	Source    string   `json:"source"`
	FirstSeen string   `json:"first_seen"`
	LastSeen  string   `json:"last_seen"`
	RiskScore *float64 `json:"risk_score,omitempty"`
}

func listFindings(ctx context.Context, st *findings.Store, raw json.RawMessage) (any, error) {
	var a struct {
		Severity string `json:"severity"`
		Status   string `json:"status"`
		Category string `json:"category"`
		Limit    int    `json:"limit"`
	}
	if err := decode(raw, &a); err != nil {
		return nil, err
	}
	limit, err := clamp(a.Limit, DefaultLimit, MaxLimit, "limit")
	if err != nil {
		return nil, err
	}
	q := findings.ListQuery{Limit: limit}
	if a.Severity != "" {
		q.Severities = []findings.Severity{findings.Severity(a.Severity)}
	}
	if a.Status != "" {
		q.Statuses = []findings.Status{findings.Status(a.Status)}
	}
	if a.Category != "" {
		q.Categories = []schema.OverviewCategory{schema.OverviewCategory(a.Category)}
	}
	page, err := st.List(ctx, q)
	if err != nil {
		return nil, err
	}
	items := make([]findingOut, 0, len(page.Items))
	for _, f := range page.Items {
		items = append(items, findingOut{ID: f.ID, RuleID: f.RuleID, Title: f.Title, Category: string(f.Category),
			Type: string(f.Type), Severity: string(f.Severity), Status: string(f.Status), AssetID: f.AssetID,
			Source: f.Source, FirstSeen: f.FirstSeen.UTC().Format("2006-01-02T15:04:05Z"),
			LastSeen: f.LastSeen.UTC().Format("2006-01-02T15:04:05Z"), RiskScore: f.RiskScore})
	}
	return map[string]any{"items": items, "truncated": page.NextCursor != ""}, nil
}

func getIssue(ctx context.Context, db *sql.DB, raw json.RawMessage) (any, error) {
	var in struct {
		ID string `json:"id"`
	}
	if err := decode(raw, &in); err != nil {
		return nil, err
	}
	if in.ID == "" {
		return nil, errors.New("invalid id: required")
	}
	var id, ruleID, title, sev, status, category, path, created, updated string
	var risk float64
	var inferred int
	err := db.QueryRowContext(ctx, `SELECT id, rule_id, title, severity, risk_score, status, category, path, includes_inferred, created_at, updated_at
		FROM issue WHERE id=?`, in.ID).Scan(&id, &ruleID, &title, &sev, &risk, &status, &category, &path, &inferred, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("issue %q not found", in.ID)
	}
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `SELECT finding_id FROM issue_finding WHERE issue_id=? ORDER BY finding_id`, in.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var f string
		if err := rows.Scan(&f); err != nil {
			return nil, err
		}
		ids = append(ids, f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return map[string]any{"id": id, "rule_id": ruleID, "title": title, "severity": sev, "risk_score": risk,
		"status": status, "category": category, "path": json.RawMessage(path), "includes_inferred": inferred != 0,
		"created_at": created, "updated_at": updated, "finding_ids": ids}, nil
}

type pkgOut struct {
	Name      string   `json:"name"`
	Version   string   `json:"version,omitempty"`
	Purl      string   `json:"purl,omitempty"`
	Ecosystem string   `json:"ecosystem,omitempty"`
	Licenses  []string `json:"licenses"`
}

var errStop = errors.New("stop")

func getSBOM(ctx context.Context, st *sbomstore.Store, raw json.RawMessage) (any, error) {
	var in struct {
		AssetID string `json:"asset_id"`
		Limit   int    `json:"limit"`
	}
	if err := decode(raw, &in); err != nil {
		return nil, err
	}
	if in.AssetID == "" {
		return nil, errors.New("invalid asset_id: required")
	}
	limit, err := clamp(in.Limit, DefaultPkgs, MaxPkgs, "limit")
	if err != nil {
		return nil, err
	}
	sums, err := st.List(ctx)
	if err != nil {
		return nil, err
	}
	var sum *sbomstore.Summary
	for i := range sums {
		if sums[i].AssetID == in.AssetID {
			sum = &sums[i]
		}
	}
	if sum == nil {
		return nil, fmt.Errorf("no sbom for asset %q", in.AssetID)
	}
	pkgs := make([]pkgOut, 0, limit)
	_, _, err = st.Each(ctx, in.AssetID, nil, func(p bom.Package) error {
		if len(pkgs) >= limit {
			return errStop
		}
		o := pkgOut{Name: p.Name, Ecosystem: p.Ecosystem, Licenses: append([]string{}, p.Licenses...)}
		if p.Version != nil {
			o.Version = *p.Version
		}
		if p.Purl != nil {
			o.Purl = *p.Purl
		}
		pkgs = append(pkgs, o)
		return nil
	})
	if err != nil && !errors.Is(err, errStop) {
		return nil, err
	}
	return map[string]any{"asset_id": sum.AssetID, "digest": sum.Digest, "package_count": sum.PackageCount,
		"created_at": sum.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"), "ecosystems": sum.Ecosystems,
		"licenses": sum.Licenses, "packages": pkgs, "truncated": sum.PackageCount > len(pkgs)}, nil
}
