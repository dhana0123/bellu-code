package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/engine"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/uri"
)

// SchemaURI is the schema resource.
const SchemaURI = "bellugraph://schema"

const (
	entityTemplate = "bellugraph://{kind}/{hex}"
	jsonMIME       = "application/json"
	viewChanges    = 10
)

// EntityResource is the body of an entity resource.
type EntityResource struct {
	Entity  EntityOut   `json:"entity"`
	Edges   []EdgeOut   `json:"edges"`
	Changes []ChangeOut `json:"changes"`
}

// registerExtras registers the resources and prompts.
func (s *Server) registerExtras() {
	s.srv.AddResource(&mcp.Resource{
		Name: "schema", Title: "Graph schema", URI: SchemaURI, MIMEType: jsonMIME,
		Description: "Entity kinds with identity attributes and counts, and relation types with impact directions (same as describe_schema).",
	}, s.readSchema)
	s.srv.AddResourceTemplate(&mcp.ResourceTemplate{
		Name: "entity", Title: "Entity", URITemplate: entityTemplate, MIMEType: jsonMIME,
		Description: "One entity at normal verbosity with its annotations, 1-hop relations and 10 latest changes.",
	}, s.readEntity)

	s.srv.AddPrompt(&mcp.Prompt{
		Name: "investigate_incident", Title: "Investigate an incident",
		Description: "Step-by-step guide to find what changed and what is affected.",
		Arguments: []*mcp.PromptArgument{
			{Name: "entity_id", Description: "Entity at the centre of the incident (id, @local id or bellugraph:// URI)"},
			{Name: "since", Description: "Look-back start: RFC 3339 time or a duration such as 1h"},
		},
	}, s.promptInvestigate)
	s.srv.AddPrompt(&mcp.Prompt{
		Name: "blast_radius", Title: "Blast radius",
		Description: "Step-by-step guide to assess what an entity change would affect.",
		Arguments: []*mcp.PromptArgument{
			{Name: "entity_id", Description: "Entity to assess (id, @local id or bellugraph:// URI)", Required: true},
			{Name: "depth", Description: "Hops to traverse, a positive integer"},
		},
	}, s.promptBlast)
	s.srv.AddPrompt(&mcp.Prompt{
		Name: "explain_entity", Title: "Explain an entity",
		Description: "Step-by-step guide to explain what an entity is and how it connects.",
		Arguments: []*mcp.PromptArgument{
			{Name: "entity_id", Description: "Entity to explain (id, @local id or bellugraph:// URI)", Required: true},
		},
	}, s.promptExplain)
}

func (s *Server) readSchema(ctx context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	_, out, err := s.describeSchema(ctx, nil, describeSchemaIn{})
	if err != nil {
		return nil, err
	}
	return jsonResource(SchemaURI, out)
}

func jsonResource(u string, v any) (*mcp.ReadResourceResult, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: u, MIMEType: jsonMIME, Text: string(b)}}}, nil
}

func (s *Server) readEntity(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	u := req.Params.URI
	r, err := uri.Parse(u)
	if err != nil {
		return nil, mcp.ResourceNotFoundError(u)
	}
	ent, ok := r.(uri.Entity)
	if !ok {
		return nil, mcp.ResourceNotFoundError(u)
	}
	body, err := s.entityBody(ctx, ent.Kind+":"+ent.Hex)
	if err != nil {
		if errors.Is(err, errs.NotFound) || errors.Is(err, errs.Validation) {
			return nil, mcp.ResourceNotFoundError(u)
		}
		return nil, err
	}
	return jsonResource(u, body)
}

func (s *Server) entityBody(ctx context.Context, id string) (EntityResource, error) {
	var out EntityResource
	e, err := s.cfg.Core.Entity(ctx, id, nil)
	if err != nil {
		return out, err
	}
	out.Entity = s.project(withoutSecrets(e), Normal)
	edges, err := s.cfg.Core.Neighbors(ctx, id, engine.NeighborOpts{Direction: engine.DirBoth, Depth: 1, Resolve: true}, nil)
	if err != nil {
		return out, err
	}
	out.Edges = projectEdges(edges.Items, Normal)
	// History is oldest first: walk to the end and keep the last 10.
	var all []engine.ChangeView
	cursor := ""
	for {
		p, err := s.cfg.Core.History(ctx, id, engine.TimeRange{}, engine.Paging{PageSize: 1000, Cursor: cursor})
		if err != nil {
			return out, err
		}
		all = append(all, p.Items...)
		if len(all) > viewChanges {
			all = all[len(all)-viewChanges:]
		}
		if !p.Truncated || p.NextCursor == "" {
			break
		}
		cursor = p.NextCursor
	}
	out.Changes = projectChanges(all, Normal)
	return out, nil
}

// withoutSecrets drops secret-named attributes and annotations, so resources
// and prompts never carry secret values.
func withoutSecrets(e engine.EntityView) engine.EntityView {
	attrs := make(map[string]any, len(e.Attributes))
	for k, v := range e.Attributes {
		if !ident.IsSecretName(k) {
			attrs[k] = v
		}
	}
	e.Attributes = attrs
	if e.Annotations != nil {
		ann := make(map[string]string, len(e.Annotations))
		for k, v := range e.Annotations {
			if !ident.IsSecretName(k) {
				ann[k] = v
			}
		}
		e.Annotations = ann
	}
	return e
}

const secretRule = "Never request secret values (passwords, tokens, keys); attributes with secret-like names are not exposed, so do not ask for them."

// entityMessages builds the prompt messages: guidance text plus, when an
// entity is given, its embedded resource.
func (s *Server) entityMessages(ctx context.Context, text, entityArg string) ([]*mcp.PromptMessage, error) {
	msgs := []*mcp.PromptMessage{{Role: "user", Content: &mcp.TextContent{Text: text}}}
	if strings.TrimSpace(entityArg) == "" {
		return msgs, nil
	}
	id, err := s.ref("entity_id", entityArg)
	if err != nil {
		return nil, err
	}
	body, err := s.entityBody(ctx, id)
	if err != nil {
		return nil, err
	}
	u := entityURI(id)
	res, err := jsonResource(u, body)
	if err != nil {
		return nil, err
	}
	return append(msgs, &mcp.PromptMessage{Role: "user", Content: &mcp.EmbeddedResource{Resource: res.Contents[0]}}), nil
}

func (s *Server) promptInvestigate(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	a := req.Params.Arguments
	since := strings.TrimSpace(a["since"])
	if since != "" {
		if _, err := parseSince(since); err != nil {
			return nil, err
		}
	}
	var b strings.Builder
	b.WriteString("Investigate an incident in the infrastructure graph.\n")
	if since != "" {
		fmt.Fprintf(&b, "Focus on changes since %s.\n", since)
	}
	b.WriteString("Steps:\n1. Call describe_schema to learn the kinds and relation types.\n")
	if strings.TrimSpace(a["entity_id"]) != "" {
		fmt.Fprintf(&b, "2. Start from the embedded entity %s; call get_entity with verbosity=full for details.\n", a["entity_id"])
		b.WriteString("3. Call entity_history for it, then get_neighbors to see what it connects to.\n")
	} else {
		b.WriteString("2. Call find_entities to locate the suspect entities.\n3. Call get_entity and get_neighbors on the best candidates.\n")
	}
	b.WriteString("4. Call recent_changes")
	if since != "" {
		fmt.Fprintf(&b, " with since=%s", since)
	}
	b.WriteString(" to see what changed, and graph_diff to compare before and after.\n")
	b.WriteString("5. Call impact_of on the likely root cause to list what depends on it.\n")
	b.WriteString("6. Summarize the timeline, the probable cause and the affected entities.\n")
	b.WriteString(secretRule + "\n")
	msgs, err := s.entityMessages(ctx, b.String(), a["entity_id"])
	if err != nil {
		return nil, err
	}
	return &mcp.GetPromptResult{Description: "Investigate an incident", Messages: msgs}, nil
}

func (s *Server) promptBlast(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	a := req.Params.Arguments
	if strings.TrimSpace(a["entity_id"]) == "" {
		return nil, fmt.Errorf("%w: entity_id is required", errs.Validation)
	}
	depth := strings.TrimSpace(a["depth"])
	if depth != "" {
		if n, err := strconv.Atoi(depth); err != nil || n < 1 {
			return nil, fmt.Errorf("%w: depth %q must be a positive integer", errs.Validation, depth)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Assess the blast radius of %s.\nSteps:\n", a["entity_id"])
	b.WriteString("1. Review the embedded entity, then call get_entity if you need more detail.\n")
	b.WriteString("2. Call impact_of")
	if depth != "" {
		fmt.Fprintf(&b, " with depth=%s", depth)
	}
	b.WriteString(" to list entities that would be affected.\n")
	b.WriteString("3. Call get_neighbors with direction=in and direction=out for the direct relations.\n")
	b.WriteString("4. Call find_path between the entity and anything critical to see how they connect.\n")
	b.WriteString("5. Use recent_changes to check whether the area is already unstable.\n")
	b.WriteString("6. Report affected entities grouped by kind, most critical first.\n")
	b.WriteString(secretRule + "\n")
	msgs, err := s.entityMessages(ctx, b.String(), a["entity_id"])
	if err != nil {
		return nil, err
	}
	return &mcp.GetPromptResult{Description: "Blast radius", Messages: msgs}, nil
}

func (s *Server) promptExplain(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	a := req.Params.Arguments
	if strings.TrimSpace(a["entity_id"]) == "" {
		return nil, fmt.Errorf("%w: entity_id is required", errs.Validation)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Explain what %s is and how it fits in the system.\nSteps:\n", a["entity_id"])
	b.WriteString("1. Read the embedded entity: its kind, label, attributes and annotations.\n")
	b.WriteString("2. Call describe_type for its kind to understand the attributes.\n")
	b.WriteString("3. Call get_neighbors to see what it runs on, owns or depends on.\n")
	b.WriteString("4. Call entity_history to see how it changed.\n")
	b.WriteString("5. Summarize its purpose, relations and recent changes in plain language.\n")
	b.WriteString(secretRule + "\n")
	msgs, err := s.entityMessages(ctx, b.String(), a["entity_id"])
	if err != nil {
		return nil, err
	}
	return &mcp.GetPromptResult{Description: "Explain an entity", Messages: msgs}, nil
}
