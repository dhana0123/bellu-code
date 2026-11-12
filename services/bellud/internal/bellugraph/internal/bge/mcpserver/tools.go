package mcpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/engine"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
)

// Recent-changes byte budget (response items only).
const (
	DefaultBudget = 16 << 10
	MaxBudget     = 256 << 10
	defaultSince  = time.Hour
)

// ToolNames lists the 12 tools in registration order.
var ToolNames = []string{
	"describe_schema", "describe_type", "find_entities", "get_entity", "annotate_entity", "get_neighbors",
	"find_path", "impact_of", "entity_history", "recent_changes", "graph_diff", "telemetry_keys",
}

// ---- argument and result types ----

type verb struct {
	Verbosity string `json:"verbosity,omitempty" jsonschema:"detail tier: brief, normal (default) or full"`
}

type paging struct {
	PageSize int    `json:"page_size,omitempty" jsonschema:"items per page, default 100, max 1000"`
	Cursor   string `json:"cursor,omitempty" jsonschema:"next_cursor of the previous page"`
}

type describeSchemaIn struct{}

type kindInfo struct {
	Kind               string   `json:"kind"`
	IdentityAttributes []string `json:"identity_attributes"`
	Count              int      `json:"count" jsonschema:"live entities of this kind"`
}

type relTypeInfo struct {
	Type            string `json:"type"`
	ImpactDirection string `json:"impact_direction" jsonschema:"forward (from to to) or reverse (to to from)"`
	Default         bool   `json:"default,omitempty" jsonschema:"true for the undeclared-type default"`
}

type describeSchemaOut struct {
	Kinds         []kindInfo    `json:"kinds"`
	RelationTypes []relTypeInfo `json:"relation_types"`
}

type describeTypeIn struct {
	Kind string `json:"kind" jsonschema:"entity kind, see describe_schema"`
}

type describeTypeOut struct {
	Kind                string         `json:"kind"`
	IdentityAttributes  []string       `json:"identity_attributes"`
	ObservedAttributes  []string       `json:"observed_attributes" jsonschema:"descriptive attribute names seen on live entities (first 1000)"`
	RelationsOut        map[string]int `json:"relations_out" jsonschema:"relation types leaving entities of this kind (sample of 50), with counts"`
	RelationsIn         map[string]int `json:"relations_in" jsonschema:"relation types entering entities of this kind (sample of 50), with counts"`
	Count               int            `json:"count"`
	SampledEntityCounts int            `json:"sampled_entities"`
}

type findEntitiesIn struct {
	Kind       string            `json:"kind,omitempty" jsonschema:"entity kind filter"`
	Attributes map[string]string `json:"attributes,omitempty" jsonschema:"attribute filters, all must match"`
	AsOf       string            `json:"as_of,omitempty" jsonschema:"RFC 3339 instant; answer from the state at that time"`
	paging
	verb
}

type findEntitiesOut struct {
	Items []EntityOut `json:"items"`
	PageInfo
}

type getEntityIn struct {
	EntityID string `json:"entity_id" jsonschema:"entity reference: identity_fingerprint, @local id or bellugraph:// URI"`
	AsOf     string `json:"as_of,omitempty" jsonschema:"RFC 3339 instant; answer from the state at that time"`
	verb
}

type getEntityOut struct {
	Entity        EntityOut   `json:"entity"`
	ConnectedFrom []EntityOut `json:"connected_from,omitempty" jsonschema:"full only: entities whose depends_on endpoints resolve to this port or process"`
}

type annotateIn struct {
	EntityID    string            `json:"entity_id" jsonschema:"entity reference"`
	Annotations map[string]string `json:"annotations,omitempty" jsonschema:"keys to set; keys match [a-z0-9_.-]{1,64}, values up to 1024 bytes"`
	Remove      []string          `json:"remove,omitempty" jsonschema:"annotation keys to remove"`
	verb
}

type annotateOut struct {
	Entity EntityOut `json:"entity"`
}

type neighborsIn struct {
	EntityID     string `json:"entity_id" jsonschema:"entity reference"`
	Direction    string `json:"direction,omitempty" jsonschema:"out, in or both (default)"`
	RelationType string `json:"relation_type,omitempty" jsonschema:"only relations of this type"`
	Depth        int    `json:"depth,omitempty" jsonschema:"hops 1 to 10, default 1"`
	Resolve      *bool  `json:"resolve,omitempty" jsonschema:"include derived resolves_to relations from endpoint resolution, default true"`
	AsOf         string `json:"as_of,omitempty" jsonschema:"RFC 3339 instant"`
	paging
	verb
}

type neighborsOut struct {
	Items []EdgeOut `json:"items"`
	PageInfo
}

type findPathIn struct {
	From     string `json:"from" jsonschema:"entity reference of the start"`
	To       string `json:"to" jsonschema:"entity reference of the end"`
	MaxDepth int    `json:"max_depth,omitempty" jsonschema:"search depth 1 to 10, default 6"`
	verb
}

type findPathOut struct {
	Connected        bool              `json:"connected"`
	Path             []EdgeOut         `json:"path,omitempty"`
	Exhausted        *bool             `json:"exhausted,omitempty" jsonschema:"not connected only: true when the whole connected component was searched"`
	DepthSearched    *int              `json:"depth_searched,omitempty" jsonschema:"not connected only: levels searched"`
	SharedNeighbors  []string          `json:"shared_neighbors" jsonschema:"empty when connected; otherwise entities adjacent to both ends"`
	SharedAttributes map[string]string `json:"shared_attributes" jsonschema:"empty when connected; otherwise non-secret attributes both ends share"`
}

type impactIn struct {
	EntityID string `json:"entity_id" jsonschema:"entity reference of the failing entity"`
	Depth    int    `json:"depth,omitempty" jsonschema:"hops 1 to 10, default 3"`
	verb
}

type impactedOut struct {
	ID                  string    `json:"id"`
	IdentityFingerprint string    `json:"identity_fingerprint"`
	Kind                string    `json:"kind"`
	Hops                int       `json:"hops"`
	Via                 []EdgeOut `json:"via,omitempty" jsonschema:"relation path from the start entity (normal and full)"`
}

type impactOut struct {
	Items []impactedOut `json:"items"`
}

type historyIn struct {
	EntityID string `json:"entity_id" jsonschema:"entity reference"`
	From     string `json:"from,omitempty" jsonschema:"RFC 3339 start, inclusive"`
	To       string `json:"to,omitempty" jsonschema:"RFC 3339 end, inclusive"`
	paging
	verb
}

type changesOut struct {
	Items []ChangeOut `json:"items"`
	PageInfo
}

type recentIn struct {
	Since      string `json:"since,omitempty" jsonschema:"RFC 3339 instant or a duration such as 30m or 2h, default 1h"`
	Kind       string `json:"kind,omitempty" jsonschema:"added, changed or removed"`
	Subject    string `json:"subject,omitempty" jsonschema:"entity or relation"`
	EntityKind string `json:"entity_kind,omitempty" jsonschema:"entity kind of entity changes"`
	MaxBytes   int    `json:"max_bytes,omitempty" jsonschema:"response byte budget, default 16384, max 262144"`
	Cursor     string `json:"cursor,omitempty" jsonschema:"next_cursor of the previous response"`
	verb
}

type digestOut struct {
	Total        int            `json:"total"`
	ByKind       map[string]int `json:"by_kind"`
	BySubject    map[string]int `json:"by_subject"`
	ByEntityKind map[string]int `json:"by_entity_kind"`
	Top          []flapOut      `json:"top_entities" jsonschema:"the 10 entities with the most changes"`
}

type flapOut struct {
	Entity  string `json:"entity"`
	Changes int    `json:"changes"`
}

type recentOut struct {
	Digest     *digestOut  `json:"digest,omitempty" jsonschema:"over the full matching set; first page only"`
	Items      []ChangeOut `json:"items" jsonschema:"newest first"`
	Total      int         `json:"total"`
	Truncated  bool        `json:"truncated"`
	NextCursor string      `json:"next_cursor,omitempty"`
}

type diffIn struct {
	From string `json:"from" jsonschema:"RFC 3339 window start"`
	To   string `json:"to" jsonschema:"RFC 3339 window end"`
	verb
}

type diffOut struct {
	From      string      `json:"from"`
	To        string      `json:"to"`
	Added     []EntityOut `json:"added"`
	Changed   []EntityOut `json:"changed"`
	Removed   []string    `json:"removed"`
	Flapping  []flapOut   `json:"flapping" jsonschema:"entities with 2+ changes whose end state equals their start state"`
	Truncated bool        `json:"truncated"`
}

type telemetryIn struct {
	EntityID string `json:"entity_id" jsonschema:"entity reference"`
	verb
}

type telemetryOut struct {
	Entity EntityOut         `json:"entity"`
	Keys   map[string]string `json:"keys" jsonschema:"identity attributes that locate the entity's metrics and logs; secret-named attributes omitted"`
}

// ---- registration ----

func (s *Server) registerTools() {
	add := func(name, desc string, h any) {
		switch f := h.(type) {
		case func(context.Context, *mcp.CallToolRequest, describeSchemaIn) (*mcp.CallToolResult, describeSchemaOut, error):
			mcp.AddTool(s.srv, tool(name, desc, true), f)
		case func(context.Context, *mcp.CallToolRequest, describeTypeIn) (*mcp.CallToolResult, describeTypeOut, error):
			mcp.AddTool(s.srv, tool(name, desc, true), f)
		case func(context.Context, *mcp.CallToolRequest, findEntitiesIn) (*mcp.CallToolResult, findEntitiesOut, error):
			mcp.AddTool(s.srv, tool(name, desc, true), f)
		case func(context.Context, *mcp.CallToolRequest, getEntityIn) (*mcp.CallToolResult, getEntityOut, error):
			mcp.AddTool(s.srv, tool(name, desc, true), f)
		case func(context.Context, *mcp.CallToolRequest, annotateIn) (*mcp.CallToolResult, annotateOut, error):
			mcp.AddTool(s.srv, tool(name, desc, false), f)
		case func(context.Context, *mcp.CallToolRequest, neighborsIn) (*mcp.CallToolResult, neighborsOut, error):
			mcp.AddTool(s.srv, tool(name, desc, true), f)
		case func(context.Context, *mcp.CallToolRequest, findPathIn) (*mcp.CallToolResult, findPathOut, error):
			mcp.AddTool(s.srv, tool(name, desc, true), f)
		case func(context.Context, *mcp.CallToolRequest, impactIn) (*mcp.CallToolResult, impactOut, error):
			mcp.AddTool(s.srv, tool(name, desc, true), f)
		case func(context.Context, *mcp.CallToolRequest, historyIn) (*mcp.CallToolResult, changesOut, error):
			mcp.AddTool(s.srv, tool(name, desc, true), f)
		case func(context.Context, *mcp.CallToolRequest, recentIn) (*mcp.CallToolResult, recentOut, error):
			mcp.AddTool(s.srv, tool(name, desc, true), f)
		case func(context.Context, *mcp.CallToolRequest, diffIn) (*mcp.CallToolResult, diffOut, error):
			mcp.AddTool(s.srv, tool(name, desc, true), f)
		case func(context.Context, *mcp.CallToolRequest, telemetryIn) (*mcp.CallToolResult, telemetryOut, error):
			mcp.AddTool(s.srv, tool(name, desc, true), f)
		default:
			panic("mcpserver: unknown handler type for " + name)
		}
	}
	add("describe_schema", "List the entity kinds with their identity attributes and live counts, and the relation types with their impact direction. Start here.", s.describeSchema)
	add("describe_type", "Describe one entity kind: identity attributes, descriptive attribute names seen, and the relation types in and out.", s.describeType)
	add("find_entities", "Find live entities by kind and attribute values (all must match), ordered by identity_fingerprint, with paging. as_of answers from a past instant.", s.findEntities)
	add("get_entity", "Get one entity by identity_fingerprint, @local id or bellugraph:// URI. verbosity=full adds timestamps, the URI and, for ports and processes, connected_from: the entities that depend on them through endpoints.", s.getEntity)
	add("annotate_entity", "Set or remove operator annotations on an entity. Annotations survive collector runs. Needs the write role.", s.annotateEntity)
	add("get_neighbors", "List the relations around an entity up to depth 10, each once at its fewest hops. resolve (default true) adds derived resolves_to relations that join network endpoints to the live listeners.", s.getNeighbors)
	add("find_path", "Find a shortest path by hop count between two entities. When none exists it says whether the whole connected component was searched or the depth bound stopped it, and lists shared neighbors and shared attributes.", s.findPath)
	add("impact_of", "List the entities affected if an entity fails: follows each relation type in its declared impact direction, with the hop count and relation path of each.", s.impactOf)
	add("entity_history", "List the change history of an entity, including changes of relations touching it, oldest first, within an optional time range.", s.entityHistory)
	add("recent_changes", "List recent changes newest first within a response byte budget (default 16 KiB, max 256 KiB), with a digest over the whole matching set. When truncated, pass next_cursor to continue.", s.recentChanges)
	add("graph_diff", "Compare the graph at two instants: added, changed and removed entities, and flapping entities that changed repeatedly but ended where they began.", s.graphDiff)
	add("telemetry_keys", "Return the identity attribute names and values that locate an entity's metrics and logs. Secret-named attributes are omitted.", s.telemetryKeys)
}

func tool(name, desc string, readOnly bool) *mcp.Tool {
	t := &mcp.Tool{Name: name, Description: desc, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: readOnly}}
	if !readOnly {
		f := false
		t.Annotations.DestructiveHint = &f
		t.Annotations.IdempotentHint = true
	}
	return t
}

// ---- handlers ----

func (s *Server) describeSchema(ctx context.Context, _ *mcp.CallToolRequest, _ describeSchemaIn) (*mcp.CallToolResult, describeSchemaOut, error) {
	out := describeSchemaOut{Kinds: []kindInfo{}, RelationTypes: []relTypeInfo{}}
	for _, k := range ident.Kinds() {
		attrs, _ := ident.IdentityAttributes(k)
		p, err := s.cfg.Core.Find(ctx, engine.FindQuery{Kind: k, Paging: engine.Paging{PageSize: 1}}, nil)
		if err != nil {
			return nil, out, err
		}
		out.Kinds = append(out.Kinds, kindInfo{Kind: k, IdentityAttributes: attrs, Count: p.Total})
	}
	for _, t := range ident.RelationTypes() {
		d, def := ident.DirectionOf(t)
		out.RelationTypes = append(out.RelationTypes, relTypeInfo{Type: t, ImpactDirection: d.String(), Default: def})
	}
	return nil, out, nil
}

func (s *Server) describeType(ctx context.Context, _ *mcp.CallToolRequest, in describeTypeIn) (*mcp.CallToolResult, describeTypeOut, error) {
	var out describeTypeOut
	idAttrs, ok := ident.IdentityAttributes(in.Kind)
	if !ok {
		return nil, out, fmt.Errorf("%w: unknown kind %q; see describe_schema", errs.Validation, in.Kind)
	}
	p, err := s.cfg.Core.Find(ctx, engine.FindQuery{Kind: in.Kind, Paging: engine.Paging{PageSize: engine.MaxPageSize}}, nil)
	if err != nil {
		return nil, out, err
	}
	identity := map[string]bool{}
	for _, a := range idAttrs {
		identity[a] = true
	}
	names := map[string]bool{}
	for _, e := range p.Items {
		for k := range e.Attributes {
			if !identity[k] {
				names[k] = true
			}
		}
	}
	out = describeTypeOut{
		Kind: in.Kind, IdentityAttributes: idAttrs, ObservedAttributes: sortedKeys(names), Count: p.Total,
		RelationsOut: map[string]int{}, RelationsIn: map[string]int{},
	}
	const sample = 50
	for i, e := range p.Items {
		if i == sample {
			break
		}
		nb, err := s.cfg.Core.Neighbors(ctx, e.ID, engine.NeighborOpts{Depth: 1, Paging: engine.Paging{PageSize: engine.MaxPageSize}}, nil)
		if err != nil {
			return nil, out, err
		}
		out.SampledEntityCounts++
		for _, ed := range nb.Items {
			if ed.From == e.ID {
				out.RelationsOut[ed.Type]++
			}
			if ed.To == e.ID {
				out.RelationsIn[ed.Type]++
			}
		}
	}
	return nil, out, nil
}

func (s *Server) findEntities(ctx context.Context, _ *mcp.CallToolRequest, in findEntitiesIn) (*mcp.CallToolResult, findEntitiesOut, error) {
	var out findEntitiesOut
	v, at, err := s.common(in.Verbosity, in.AsOf)
	if err != nil {
		return nil, out, err
	}
	p, err := s.cfg.Core.Find(ctx, engine.FindQuery{Kind: in.Kind, Attributes: in.Attributes,
		Paging: engine.Paging{PageSize: in.PageSize, Cursor: in.Cursor}}, at)
	if err != nil {
		return nil, out, err
	}
	return nil, findEntitiesOut{Items: s.projectAll(p.Items, v), PageInfo: pageInfo(p)}, nil
}

func (s *Server) getEntity(ctx context.Context, _ *mcp.CallToolRequest, in getEntityIn) (*mcp.CallToolResult, getEntityOut, error) {
	var out getEntityOut
	v, at, err := s.common(in.Verbosity, in.AsOf)
	if err != nil {
		return nil, out, err
	}
	id, err := s.ref("entity_id", in.EntityID)
	if err != nil {
		return nil, out, err
	}
	e, err := s.cfg.Core.Entity(ctx, id, at)
	if err != nil {
		return nil, out, err
	}
	out.Entity = s.project(e, v)
	if v == Full && at == nil {
		deps, err := s.cfg.Core.Dependents(ctx, id)
		if err != nil {
			return nil, out, err
		}
		for _, d := range deps {
			de, err := s.cfg.Core.Entity(ctx, d, nil)
			if err != nil {
				if errors.Is(err, errs.NotFound) {
					continue
				}
				return nil, out, err
			}
			out.ConnectedFrom = append(out.ConnectedFrom, s.project(de, Brief))
		}
	}
	return nil, out, nil
}

func (s *Server) annotateEntity(ctx context.Context, _ *mcp.CallToolRequest, in annotateIn) (*mcp.CallToolResult, annotateOut, error) {
	var out annotateOut
	if s.cfg.CallerRole == nil || s.cfg.CallerRole(ctx) != RoleWrite {
		return nil, out, errors.New(ForbiddenMessage)
	}
	if s.cfg.Annotate == nil {
		return nil, out, fmt.Errorf("%w: annotation is not available", errs.Unavailable)
	}
	v, err := ParseVerbosity(in.Verbosity)
	if err != nil {
		return nil, out, err
	}
	if len(in.Annotations) == 0 && len(in.Remove) == 0 {
		return nil, out, fmt.Errorf("%w: give annotations to set or keys to remove", errs.Validation)
	}
	id, err := s.ref("entity_id", in.EntityID)
	if err != nil {
		return nil, out, err
	}
	if err := s.cfg.Annotate(ctx, id, in.Annotations, in.Remove); err != nil {
		return nil, out, err
	}
	e, err := s.cfg.Core.Entity(ctx, id, nil)
	if err != nil {
		return nil, out, err
	}
	out.Entity = s.project(e, v)
	return nil, out, nil
}

func (s *Server) getNeighbors(ctx context.Context, _ *mcp.CallToolRequest, in neighborsIn) (*mcp.CallToolResult, neighborsOut, error) {
	var out neighborsOut
	v, at, err := s.common(in.Verbosity, in.AsOf)
	if err != nil {
		return nil, out, err
	}
	id, err := s.ref("entity_id", in.EntityID)
	if err != nil {
		return nil, out, err
	}
	p, err := s.cfg.Core.Neighbors(ctx, id, engine.NeighborOpts{
		Direction: in.Direction, RelationType: in.RelationType, Depth: in.Depth,
		Resolve: in.Resolve == nil || *in.Resolve,
		Paging:  engine.Paging{PageSize: in.PageSize, Cursor: in.Cursor},
	}, at)
	if err != nil {
		return nil, out, err
	}
	return nil, neighborsOut{Items: projectEdges(p.Items, v), PageInfo: pageInfo(p)}, nil
}

func (s *Server) findPath(ctx context.Context, _ *mcp.CallToolRequest, in findPathIn) (*mcp.CallToolResult, findPathOut, error) {
	var out findPathOut
	v, err := ParseVerbosity(in.Verbosity)
	if err != nil {
		return nil, out, err
	}
	from, err := s.ref("from", in.From)
	if err != nil {
		return nil, out, err
	}
	to, err := s.ref("to", in.To)
	if err != nil {
		return nil, out, err
	}
	r, err := s.cfg.Core.Path(ctx, from, to, engine.PathOpts{MaxDepth: in.MaxDepth})
	if err != nil {
		return nil, out, err
	}
	if r.Connected {
		return nil, findPathOut{Connected: true, Path: projectEdges(r.Path, v), SharedNeighbors: []string{}, SharedAttributes: map[string]string{}}, nil
	}
	shared := map[string]string{}
	for k, val := range r.SharedAttributes {
		if !ident.IsSecretName(k) {
			shared[k] = val
		}
	}
	nb := r.SharedNeighbors
	if nb == nil {
		nb = []string{}
	}
	return nil, findPathOut{
		Connected: false, Exhausted: &r.Exhausted, DepthSearched: &r.DepthSearched,
		SharedNeighbors: nb, SharedAttributes: shared,
	}, nil
}

func (s *Server) impactOf(ctx context.Context, _ *mcp.CallToolRequest, in impactIn) (*mcp.CallToolResult, impactOut, error) {
	var out impactOut
	v, err := ParseVerbosity(in.Verbosity)
	if err != nil {
		return nil, out, err
	}
	id, err := s.ref("entity_id", in.EntityID)
	if err != nil {
		return nil, out, err
	}
	r, err := s.cfg.Core.Impact(ctx, id, engine.ImpactOpts{Depth: in.Depth})
	if err != nil {
		return nil, out, err
	}
	out.Items = make([]impactedOut, len(r.Items))
	for i, it := range r.Items {
		o := impactedOut{ID: s.cfg.Core.LocalID(it.ID), IdentityFingerprint: it.ID, Kind: it.Kind, Hops: it.Hops}
		if v != Brief {
			o.Via = projectEdges(it.Via, v)
		}
		out.Items[i] = o
	}
	return nil, out, nil
}

func (s *Server) entityHistory(ctx context.Context, _ *mcp.CallToolRequest, in historyIn) (*mcp.CallToolResult, changesOut, error) {
	var out changesOut
	v, err := ParseVerbosity(in.Verbosity)
	if err != nil {
		return nil, out, err
	}
	id, err := s.ref("entity_id", in.EntityID)
	if err != nil {
		return nil, out, err
	}
	from, err := parseTime("from", in.From)
	if err != nil {
		return nil, out, err
	}
	to, err := parseTime("to", in.To)
	if err != nil {
		return nil, out, err
	}
	p, err := s.cfg.Core.History(ctx, id, engine.TimeRange{From: zeroIfNil(from), To: zeroIfNil(to)},
		engine.Paging{PageSize: in.PageSize, Cursor: in.Cursor})
	if err != nil {
		return nil, out, err
	}
	return nil, changesOut{Items: projectChanges(p.Items, v), PageInfo: pageInfo(p)}, nil
}

func projectChanges(cs []engine.ChangeView, v Verbosity) []ChangeOut {
	out := make([]ChangeOut, len(cs))
	for i, c := range cs {
		out[i] = projectChange(c, v)
	}
	return out
}

func (s *Server) recentChanges(ctx context.Context, _ *mcp.CallToolRequest, in recentIn) (*mcp.CallToolResult, recentOut, error) {
	var out recentOut
	v, err := ParseVerbosity(in.Verbosity)
	if err != nil {
		return nil, out, err
	}
	budget, err := clampBudget(in.MaxBytes)
	if err != nil {
		return nil, out, err
	}
	since, err := parseSince(in.Since)
	if err != nil {
		return nil, out, err
	}
	filter := engine.ChangeFilter{Kind: engine.ChangeKind(in.Kind), Subject: engine.ChangeSubject(in.Subject), EntityKind: in.EntityKind}
	if err := checkChangeFilter(filter); err != nil {
		return nil, out, err
	}
	rng := engine.TimeRange{From: since}
	var skipNS int64
	var skipSeq uint64
	hasCursor := in.Cursor != ""
	if hasCursor {
		if skipNS, skipSeq, err = decodeRecentCursor(in.Cursor); err != nil {
			return nil, out, err
		}
		rng.To = time.Unix(0, skipNS).UTC()
	}
	if !hasCursor {
		d, err := s.cfg.Core.Digest(ctx, rng, filter)
		if err != nil {
			return nil, out, err
		}
		out.Digest = &digestOut{Total: d.Total, ByKind: d.ByKind, BySubject: d.BySubject, ByEntityKind: d.ByEntityKind, Top: flaps(d.Top)}
	}
	out.Items = []ChangeOut{}
	used := 0
	var last engine.ChangeView
	page := engine.Paging{PageSize: engine.MaxPageSize}
	for {
		f := filter
		f.Paging = page
		p, err := s.cfg.Core.Changes(ctx, rng, f, engine.OrderDesc)
		if err != nil {
			return nil, out, err
		}
		if out.Total == 0 || !hasCursor {
			out.Total = p.Total
		}
		for _, c := range p.Items {
			if hasCursor && (c.ObservedAt.UnixNano() > skipNS || (c.ObservedAt.UnixNano() == skipNS && c.Seq >= skipSeq)) {
				continue
			}
			item := projectChange(c, v)
			b, err := json.Marshal(item)
			if err != nil {
				return nil, out, err
			}
			if len(out.Items) > 0 && used+len(b) > budget {
				out.Truncated = true
				out.NextCursor = encodeRecentCursor(last)
				return nil, out, nil
			}
			used += len(b)
			out.Items = append(out.Items, item)
			last = c
		}
		if !p.Truncated {
			return nil, out, nil
		}
		page.Cursor = p.NextCursor
	}
}

func clampBudget(n int) (int, error) {
	switch {
	case n < 0:
		return 0, fmt.Errorf("%w: max_bytes %d is negative", errs.Validation, n)
	case n == 0:
		return DefaultBudget, nil
	case n > MaxBudget:
		return MaxBudget, nil
	}
	return n, nil
}

// parseSince accepts an RFC 3339 instant or a Go duration before now.
func parseSince(v string) (time.Time, error) {
	if v == "" {
		return time.Now().Add(-defaultSince).UTC(), nil
	}
	if d, err := time.ParseDuration(v); err == nil {
		if d < 0 {
			return time.Time{}, fmt.Errorf("%w: since %q is negative", errs.Validation, v)
		}
		return time.Now().Add(-d).UTC(), nil
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: since %q is neither an RFC 3339 time nor a duration", errs.Validation, v)
	}
	return t, nil
}

func checkChangeFilter(f engine.ChangeFilter) error {
	switch f.Kind {
	case "", engine.ChangeAdded, engine.ChangeChanged, engine.ChangeRemoved:
	default:
		return fmt.Errorf("%w: kind %q must be added, changed or removed", errs.Validation, f.Kind)
	}
	switch f.Subject {
	case "", engine.SubjectEntity, engine.SubjectRelation:
	default:
		return fmt.Errorf("%w: subject %q must be entity or relation", errs.Validation, f.Subject)
	}
	return nil
}

func encodeRecentCursor(c engine.ChangeView) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(c.ObservedAt.UnixNano(), 10) + ":" + strconv.FormatUint(c.Seq, 10)))
}

func decodeRecentCursor(s string) (int64, uint64, error) {
	bad := fmt.Errorf("%w: malformed cursor", errs.Validation)
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return 0, 0, bad
	}
	a, c, ok := strings.Cut(string(b), ":")
	if !ok {
		return 0, 0, bad
	}
	ns, err1 := strconv.ParseInt(a, 10, 64)
	seq, err2 := strconv.ParseUint(c, 10, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, bad
	}
	return ns, seq, nil
}

func flaps(fs []engine.Flap) []flapOut {
	out := make([]flapOut, len(fs))
	for i, f := range fs {
		out[i] = flapOut{Entity: f.ID, Changes: f.Changes}
	}
	return out
}

func (s *Server) graphDiff(ctx context.Context, _ *mcp.CallToolRequest, in diffIn) (*mcp.CallToolResult, diffOut, error) {
	var out diffOut
	v, err := ParseVerbosity(in.Verbosity)
	if err != nil {
		return nil, out, err
	}
	from, err := parseTime("from", in.From)
	if err != nil {
		return nil, out, err
	}
	to, err := parseTime("to", in.To)
	if err != nil {
		return nil, out, err
	}
	if from == nil || to == nil {
		return nil, out, fmt.Errorf("%w: from and to are required", errs.Validation)
	}
	d, err := s.cfg.Core.Diff(ctx, *from, *to)
	if err != nil {
		return nil, out, err
	}
	return nil, diffOut{
		From: d.From.UTC().Format(time.RFC3339Nano), To: d.To.UTC().Format(time.RFC3339Nano),
		Added: s.projectAll(d.Added, v), Changed: s.projectAll(d.Changed, v),
		Removed: d.Removed, Flapping: flaps(d.Flapping), Truncated: d.Truncated,
	}, nil
}

func (s *Server) telemetryKeys(ctx context.Context, _ *mcp.CallToolRequest, in telemetryIn) (*mcp.CallToolResult, telemetryOut, error) {
	var out telemetryOut
	v, err := ParseVerbosity(in.Verbosity)
	if err != nil {
		return nil, out, err
	}
	id, err := s.ref("entity_id", in.EntityID)
	if err != nil {
		return nil, out, err
	}
	e, err := s.cfg.Core.Entity(ctx, id, nil)
	if err != nil {
		return nil, out, err
	}
	keys := map[string]string{}
	attrs, _ := ident.IdentityAttributes(e.Kind)
	for _, a := range attrs {
		if ident.IsSecretName(a) {
			continue
		}
		if val, ok := e.Attributes[a].(string); ok {
			keys[a] = val
		}
	}
	return nil, telemetryOut{Entity: s.project(withoutSecrets(e), v), Keys: keys}, nil
}

// common parses verbosity and as_of.
func (s *Server) common(verbosity, asOf string) (Verbosity, *time.Time, error) {
	v, err := ParseVerbosity(verbosity)
	if err != nil {
		return "", nil, err
	}
	at, err := parseTime("as_of", asOf)
	return v, at, err
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
