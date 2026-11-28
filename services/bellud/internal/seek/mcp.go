package seek

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ToolName is the MCP tool served on the bellu-graph server.
const ToolName = "seek_retrieve"

// inputSchema is informative only. ParsePlan and ParseTopK do the real
// validation so a bad Plan yields path-bearing issues, not a protocol error.
var inputSchema = map[string]any{
	"type":                 "object",
	"additionalProperties": false,
	"required":             []string{"plan"},
	"properties": map[string]any{
		"plan": map[string]any{
			"type":        "object",
			"description": "{language, reasoning, weaknesses:[{cwe_id, root_cause, code_snippet}]}; validated by the server.",
		},
		"top_k": map[string]any{
			"type":    "integer",
			"minimum": MinTopK,
			"maximum": MaxTopK,
			"default": DefaultTopK,
		},
	},
}

// Register adds seek_retrieve to srv with the low-level AddTool so that raw
// arguments reach our validator.
func Register(srv *mcp.Server, r *Retriever) {
	srv.AddTool(&mcp.Tool{
		Name:        ToolName,
		Description: "Retrieve CVE evidence for the weaknesses in a vulnerability-analysis plan from the BSKG, ranked and allocated to top_k candidates. Read-only.",
		InputSchema: inputSchema,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handle(ctx, r, req.Params.Arguments), nil
	})
}

// Extras returns a function suitable for the facade's MCPExtras hook.
func Extras(r *Retriever) func(*mcp.Server) {
	return func(s *mcp.Server) { Register(s, r) }
}

func handle(ctx context.Context, r *Retriever, raw json.RawMessage) *mcp.CallToolResult {
	var args map[string]json.RawMessage
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil || args == nil {
			return reply(Result{Status: "invalid_plan", Issues: []Issue{{Path: "plan", Reason: "arguments must be a JSON object"}}})
		}
	}
	var issues []Issue
	names := make([]string, 0, len(args))
	for k := range args {
		if k != "plan" && k != "top_k" {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	for _, k := range names {
		issues = append(issues, Issue{Path: k, Reason: "unknown argument"})
	}

	var (
		plan     Plan
		rejected []Dropped
	)
	if p, ok := args["plan"]; !ok {
		issues = append(issues, Issue{Path: "plan", Reason: "required field is missing"})
	} else {
		var pi []Issue
		plan, rejected, pi = ParsePlan(p)
		issues = append(issues, pi...)
	}
	topK, ti := ParseTopK(args["top_k"])
	issues = append(issues, ti...)
	if len(issues) > 0 {
		return reply(Result{Status: "invalid_plan", Issues: issues})
	}

	res := r.Run(ctx, plan, topK)
	if res.Status != "invalid_plan" {
		res.Rejected = rejected
	}
	return reply(res)
}

// reply returns res as structuredContent and identical text content. Only
// invalid_plan sets isError.
func reply(res Result) *mcp.CallToolResult {
	b, err := json.Marshal(res)
	if err != nil {
		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "internal error encoding result"}}}
	}
	return &mcp.CallToolResult{
		IsError:           res.Status == "invalid_plan",
		StructuredContent: json.RawMessage(b),
		Content:           []mcp.Content{&mcp.TextContent{Text: string(b)}},
	}
}
