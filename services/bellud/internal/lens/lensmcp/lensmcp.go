// Package lensmcp registers the lens-backed MCP tools: slice, attack_paths,
// blast_radius, reachable_vulns, and exposed_resources. Every tool is
// read-only, answers with at most Limit nodes (default 100, maximum 200), tags
// each edge and path with an "extracted" or "inferred" confidence, and lists
// the registered-only data categories the answer depends on in missing_data.
package lensmcp

import (
	"context"
	"sort"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bellu/bellucode/services/bellud/internal/lens"
)

// Limits on the answer size.
const (
	DefaultLimit = 100
	MaxLimit     = 200
)

// Tool names.
const (
	ToolSlice          = "slice"
	ToolAttackPaths    = "attack_paths"
	ToolBlastRadius    = "blast_radius"
	ToolReachableVulns = "reachable_vulns"
	ToolExposed        = "exposed_resources"
)

// Names lists the tools Register adds.
var Names = []string{ToolSlice, ToolAttackPaths, ToolBlastRadius, ToolReachableVulns, ToolExposed}

// Slicer is the part of lens.Service the tools need.
type Slicer interface {
	Slice(ctx context.Context, id string, p lens.Params) (lens.Slice, error)
	Exposed(ctx context.Context, p lens.Params) (lens.Slice, error)
}

// Extras returns a function for facade.Config.MCPExtras that registers the
// tools on a server.
func Extras(svc Slicer) func(*mcp.Server) {
	return func(s *mcp.Server) { Register(s, svc) }
}

// Register adds the tools to s.
func Register(s *mcp.Server, svc Slicer) {
	ro := func() *mcp.ToolAnnotations { return &mcp.ToolAnnotations{ReadOnlyHint: true} }
	mcp.AddTool(s, &mcp.Tool{
		Name:        ToolSlice,
		Description: "Return a bounded Lens_Slice (nodes, edges, groups, paths). Every edge and path carries confidence: extracted or inferred.",
		Annotations: ro(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in sliceIn) (*mcp.CallToolResult, lens.Slice, error) {
		out, err := run(ctx, svc, in.Lens, lens.Params{Entity: in.Entity, Target: in.Target, TargetType: in.TargetType,
			Depth: in.Depth, CollapseRules: in.CollapseRules}, in.Limit)
		return nil, out, err
	})
	mcp.AddTool(s, &mcp.Tool{
		Name:        ToolAttackPaths,
		Description: "List paths from internet-exposed entities to a target entity, or to every entity of target_type (for example rds:instance). Each edge and path carries confidence: extracted or inferred.",
		Annotations: ro(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in attackIn) (*mcp.CallToolResult, attackOut, error) {
		sl, err := run(ctx, svc, "attack-path", lens.Params{Target: in.Target, TargetType: in.TargetType, CollapseRules: in.CollapseRules}, in.Limit)
		if err != nil {
			return nil, attackOut{}, err
		}
		return nil, attackPaths(sl, clamp(in.Limit)), nil
	})
	mcp.AddTool(s, &mcp.Tool{
		Name:        ToolBlastRadius,
		Description: "List entities affected by a change to an entity, up to depth hops (default 3, maximum 6). Each item carries confidence: extracted or inferred.",
		Annotations: ro(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in blastIn) (*mcp.CallToolResult, blastOut, error) {
		sl, err := run(ctx, svc, "blast-radius", lens.Params{Entity: in.Entity, Depth: in.Depth, CollapseRules: in.CollapseRules}, in.Limit)
		if err != nil {
			return nil, blastOut{}, err
		}
		return nil, blastRadius(in.Entity, sl), nil
	})
	mcp.AddTool(s, &mcp.Tool{
		Name:        ToolReachableVulns,
		Description: "List vulnerabilities reachable from internet-exposed entities, ordered by risk score. Each item carries confidence: extracted or inferred.",
		Annotations: ro(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in limitIn) (*mcp.CallToolResult, vulnOut, error) {
		sl, err := run(ctx, svc, "vulnerability-reachability", lens.Params{}, in.Limit)
		if err != nil {
			return nil, vulnOut{}, err
		}
		return nil, reachable(sl, clamp(in.Limit)), nil
	})
	mcp.AddTool(s, &mcp.Tool{
		Name:        ToolExposed,
		Description: "List entities with an attached security group that has an ingress rule open to the internet (0.0.0.0/0 or ::/0), with the group and rule. Each path carries confidence: extracted or inferred.",
		Annotations: ro(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in limitIn) (*mcp.CallToolResult, exposedOut, error) {
		n := clamp(in.Limit)
		sl, err := svc.Exposed(ctx, lens.Params{MaxNodes: n, MaxEdges: 2 * n})
		if err != nil {
			return nil, exposedOut{}, err
		}
		return nil, exposed(lens.Budget(sl, n, 2*n), n), nil
	})
}

type limitIn struct {
	Limit int `json:"limit,omitempty" jsonschema:"maximum nodes in the answer, default 100, maximum 200"`
}

type sliceIn struct {
	Lens          string `json:"lens,omitempty" jsonschema:"lens id, default code-to-cloud"`
	Entity        string `json:"entity,omitempty" jsonschema:"root entity for the blast-radius lens"`
	Target        string `json:"target,omitempty" jsonschema:"target entity for the attack-path lens"`
	TargetType    string `json:"target_type,omitempty" jsonschema:"target resource type for the attack-path lens, for example rds:instance"`
	Depth         int    `json:"depth,omitempty" jsonschema:"hops to traverse"`
	CollapseRules *bool  `json:"collapse_rules,omitempty" jsonschema:"replace security group rule nodes with group-to-peer edges; default true for the cloud lens only"`
	Limit         int    `json:"limit,omitempty" jsonschema:"maximum nodes in the answer, default 100, maximum 200"`
}

type attackIn struct {
	Target        string `json:"target,omitempty" jsonschema:"entity the paths lead to; target or target_type is required"`
	TargetType    string `json:"target_type,omitempty" jsonschema:"resource type the paths lead to, for example rds:instance"`
	CollapseRules *bool  `json:"collapse_rules,omitempty" jsonschema:"replace security group rule nodes with group-to-peer edges"`
	Limit         int    `json:"limit,omitempty" jsonschema:"maximum nodes in the answer, default 100, maximum 200"`
}

type blastIn struct {
	Entity        string `json:"entity" jsonschema:"entity whose change is assessed"`
	Depth         int    `json:"depth,omitempty" jsonschema:"hops to traverse, default 3, maximum 6"`
	CollapseRules *bool  `json:"collapse_rules,omitempty" jsonschema:"replace security group rule nodes with group-to-peer edges"`
	Limit         int    `json:"limit,omitempty" jsonschema:"maximum nodes in the answer, default 100, maximum 200"`
}

type nodeRef struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Label string `json:"label"`
}

type attackPath struct {
	Nodes      []nodeRef        `json:"nodes"`
	Edges      []lens.SliceEdge `json:"edges"`
	Confidence string           `json:"confidence"`
}

type attackOut struct {
	Paths       []attackPath `json:"paths"`
	Truncated   bool         `json:"truncated"`
	MissingData []string     `json:"missing_data"`
}

type blastItem struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	Label      string `json:"label"`
	Hops       int    `json:"hops"`
	Confidence string `json:"confidence"`
	// Via is "network" for an item reached only through network reach.
	Via string `json:"via,omitempty"`
}

type blastOut struct {
	Entity      string           `json:"entity"`
	Items       []blastItem      `json:"items"`
	Edges       []lens.SliceEdge `json:"edges"`
	Truncated   bool             `json:"truncated"`
	MissingData []string         `json:"missing_data"`
}

type vulnItem struct {
	Vulnerability string   `json:"vulnerability"`
	Package       string   `json:"package"`
	Score         float64  `json:"score"`
	Severity      string   `json:"severity"`
	KEV           bool     `json:"kev"`
	EPSS          float64  `json:"epss"`
	Path          []string `json:"path"`
	Confidence    string   `json:"confidence"`
}

type vulnOut struct {
	Items       []vulnItem `json:"items"`
	Truncated   bool       `json:"truncated"`
	MissingData []string   `json:"missing_data"`
}

type exposedItem struct {
	nodeRef
	Path       []nodeRef        `json:"path"`
	Edges      []lens.SliceEdge `json:"edges"`
	Confidence string           `json:"confidence"`
}

type exposedOut struct {
	Items       []exposedItem `json:"items"`
	Truncated   bool          `json:"truncated"`
	MissingData []string      `json:"missing_data"`
}

func clamp(limit int) int {
	switch {
	case limit <= 0:
		return DefaultLimit
	case limit > MaxLimit:
		return MaxLimit
	}
	return limit
}

// run builds the slice and applies the MCP budget: limit nodes, twice that
// many edges.
func run(ctx context.Context, svc Slicer, id string, p lens.Params, limit int) (lens.Slice, error) {
	n := clamp(limit)
	p.MaxNodes, p.MaxEdges = n, 2*n
	s, err := svc.Slice(ctx, id, p)
	if err != nil {
		return lens.Slice{}, err
	}
	return lens.Budget(s, n, 2*n), nil
}

func attackPaths(s lens.Slice, limit int) attackOut {
	refs := map[string]nodeRef{}
	for _, n := range s.Nodes {
		refs[n.ID] = nodeRef{ID: n.ID, Kind: n.Kind, Label: n.Label}
	}
	out := attackOut{Paths: []attackPath{}, Truncated: s.Truncated, MissingData: missing(s)}
	for _, p := range s.Paths {
		if len(out.Paths) >= limit {
			out.Truncated = true
			break
		}
		ap := attackPath{Nodes: []nodeRef{}, Edges: []lens.SliceEdge{}, Confidence: p.Confidence}
		for i, id := range p.Nodes {
			ap.Nodes = append(ap.Nodes, refs[id])
			if i > 0 {
				if e, ok := edgeBetween(s.Edges, p.Nodes[i-1], id); ok {
					ap.Edges = append(ap.Edges, e)
				}
			}
		}
		out.Paths = append(out.Paths, ap)
	}
	return out
}

func edgeBetween(edges []lens.SliceEdge, a, b string) (lens.SliceEdge, bool) {
	for _, e := range edges {
		if (e.From == a && e.To == b) || (e.From == b && e.To == a) {
			return e, true
		}
	}
	return lens.SliceEdge{}, false
}

func blastRadius(entity string, s lens.Slice) blastOut {
	byEnd := map[string]string{}
	for _, p := range s.Paths {
		if len(p.Nodes) > 0 {
			byEnd[p.Nodes[len(p.Nodes)-1]] = p.Confidence
		}
	}
	out := blastOut{Entity: entity, Items: []blastItem{}, Edges: s.Edges, Truncated: s.Truncated, MissingData: missing(s)}
	if out.Edges == nil {
		out.Edges = []lens.SliceEdge{}
	}
	for _, n := range s.Nodes {
		if n.ID == s.Root {
			continue
		}
		conf, ok := byEnd[n.ID]
		if !ok {
			conf = lens.ConfExtracted
			for _, e := range s.Edges {
				if (e.From == n.ID || e.To == n.ID) && e.Confidence == lens.ConfInferred {
					conf = lens.ConfInferred
				}
			}
		}
		out.Items = append(out.Items, blastItem{ID: n.ID, Kind: n.Kind, Label: n.Label, Hops: n.Hops, Confidence: conf, Via: n.Attrs["via"]})
	}
	return out
}

func reachable(s lens.Slice, limit int) vulnOut {
	nodes := map[string]lens.Node{}
	for _, n := range s.Nodes {
		nodes[n.ID] = n
	}
	out := vulnOut{Items: []vulnItem{}, Truncated: s.Truncated, MissingData: missing(s)}
	for _, p := range s.Paths {
		if len(p.Nodes) == 0 {
			continue
		}
		v, ok := nodes[p.Nodes[0]]
		if !ok || v.Kind != "vulnerability" || v.Risk == nil {
			continue
		}
		pkg := ""
		for _, id := range p.Nodes[1:] {
			if nodes[id].Kind == "package" {
				pkg = id
				break
			}
		}
		out.Items = append(out.Items, vulnItem{
			Vulnerability: v.ID, Package: pkg, Score: v.Risk.Score, Severity: v.Risk.Severity,
			KEV: v.Risk.KEV, EPSS: v.Risk.EPSS, Path: p.Nodes, Confidence: p.Confidence,
		})
	}
	sort.SliceStable(out.Items, func(i, j int) bool {
		if out.Items[i].Score != out.Items[j].Score {
			return out.Items[i].Score > out.Items[j].Score
		}
		return out.Items[i].Vulnerability < out.Items[j].Vulnerability
	})
	if len(out.Items) > limit {
		out.Items, out.Truncated = out.Items[:limit], true
	}
	return out
}

func exposed(s lens.Slice, limit int) exposedOut {
	refs := map[string]nodeRef{}
	for _, n := range s.Nodes {
		refs[n.ID] = nodeRef{ID: n.ID, Kind: n.Kind, Label: n.Label}
	}
	out := exposedOut{Items: []exposedItem{}, Truncated: s.Truncated, MissingData: missing(s)}
	for _, p := range s.Paths {
		if len(out.Items) >= limit {
			out.Truncated = true
			break
		}
		it := exposedItem{nodeRef: refs[p.Nodes[0]], Path: []nodeRef{}, Edges: []lens.SliceEdge{}, Confidence: p.Confidence}
		for i, id := range p.Nodes {
			it.Path = append(it.Path, refs[id])
			if i > 0 {
				if e, ok := edgeBetween(s.Edges, p.Nodes[i-1], id); ok {
					it.Edges = append(it.Edges, e)
				}
			}
		}
		out.Items = append(out.Items, it)
	}
	return out
}

// missing returns the slice's missing_data, never nil.
func missing(s lens.Slice) []string {
	if s.MissingData == nil {
		return []string{}
	}
	return s.MissingData
}
