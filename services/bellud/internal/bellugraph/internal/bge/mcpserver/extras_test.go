package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func (f *fixture) read(t *testing.T, u string) (*mcp.ReadResourceResult, error) {
	t.Helper()
	return f.cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: u})
}

func TestSchemaResourceMatchesTool(t *testing.T) {
	f := newFixture(t)
	res, err := f.read(t, SchemaURI)
	if err != nil {
		t.Fatal(err)
	}
	c := res.Contents[0]
	if c.MIMEType != "application/json" || c.URI != SchemaURI {
		t.Fatalf("contents = %+v", c)
	}
	var got, want map[string]any
	if err := json.Unmarshal([]byte(c.Text), &got); err != nil {
		t.Fatal(err)
	}
	want, _, isErr := f.call(t, "describe_schema", nil)
	if isErr {
		t.Fatal("describe_schema failed")
	}
	g, _ := json.Marshal(got)
	w, _ := json.Marshal(want)
	if string(g) != string(w) {
		t.Errorf("schema resource differs:\n%s\n%s", g, w)
	}
}

func TestEntityResource(t *testing.T) {
	f := newFixture(t)
	u := entityURI(f.ids["lone"])
	res, err := f.read(t, u)
	if err != nil {
		t.Fatal(err)
	}
	var body EntityResource
	if err := json.Unmarshal([]byte(res.Contents[0].Text), &body); err != nil {
		t.Fatal(err)
	}
	if body.Entity.IdentityFingerprint != f.ids["lone"] || len(body.Changes) == 0 || len(body.Changes) > 10 {
		t.Fatalf("body = %+v", body)
	}
	if strings.Contains(res.Contents[0].Text, "s3cret") {
		t.Error("secret attribute value leaked")
	}
	host, err := f.read(t, entityURI(f.ids["host"]))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(host.Contents[0].Text, f.ids["lp"]) {
		t.Error("expected 1-hop edge to listening port")
	}
}

func TestEntityResourceNotFound(t *testing.T) {
	f := newFixture(t)
	for _, u := range []string{"bellugraph://host/" + strings.Repeat("0", 64), "bellugraph://nokind/zz"} {
		_, err := f.read(t, u)
		if err == nil {
			t.Fatalf("%s: want error", u)
		}
		if !strings.Contains(strings.ToLower(err.Error()), "not found") {
			t.Errorf("%s: err = %v", u, err)
		}
	}
}

func (f *fixture) prompt(t *testing.T, name string, args map[string]string) (*mcp.GetPromptResult, error) {
	t.Helper()
	return f.cs.GetPrompt(context.Background(), &mcp.GetPromptParams{Name: name, Arguments: args})
}

func TestPrompts(t *testing.T) {
	f := newFixture(t)
	list, err := f.cs.ListPrompts(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	args := map[string][]string{}
	for _, p := range list.Prompts {
		for _, a := range p.Arguments {
			args[p.Name] = append(args[p.Name], a.Name)
		}
	}
	if len(list.Prompts) != 3 || len(args["investigate_incident"]) != 2 || len(args["blast_radius"]) != 2 || len(args["explain_entity"]) != 1 {
		t.Fatalf("prompts = %v", args)
	}
	lone := f.ids["lone"]
	for name, a := range map[string]map[string]string{
		"investigate_incident": {"entity_id": lone, "since": "1h"},
		"blast_radius":         {"entity_id": lone, "depth": "2"},
		"explain_entity":       {"entity_id": lone},
	} {
		r, err := f.prompt(t, name, a)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var text string
		embedded := false
		for _, m := range r.Messages {
			switch c := m.Content.(type) {
			case *mcp.TextContent:
				text += c.Text
			case *mcp.EmbeddedResource:
				embedded = true
				if strings.Contains(c.Resource.Text, "s3cret") {
					t.Errorf("%s leaks secret", name)
				}
			}
		}
		if !embedded || !strings.Contains(text, "Never request secret values") || !strings.Contains(text, "Call ") {
			t.Errorf("%s: embedded=%v text=%q", name, embedded, text)
		}
	}
	r, err := f.prompt(t, "investigate_incident", nil)
	if err != nil || len(r.Messages) != 1 {
		t.Fatalf("no-entity investigate: %v %+v", err, r)
	}
	if _, err := f.prompt(t, "blast_radius", nil); err == nil {
		t.Error("blast_radius without entity_id should fail")
	}
	if _, err := f.prompt(t, "explain_entity", map[string]string{"entity_id": "host:" + strings.Repeat("0", 64)}); err == nil {
		t.Error("unknown entity should fail")
	}
}

func TestToolSchemasDeclareVerbosity(t *testing.T) {
	f := newFixture(t)
	list, err := f.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range list.Tools {
		b, _ := json.Marshal(tl.InputSchema)
		var s struct {
			Type       string                    `json:"type"`
			Properties map[string]map[string]any `json:"properties"`
		}
		if err := json.Unmarshal(b, &s); err != nil || s.Type != "object" {
			t.Errorf("%s: schema %s", tl.Name, b)
		}
		_, hasVerb := s.Properties["verbosity"]
		if tl.Name == "get_entity" && !hasVerb {
			t.Errorf("get_entity lacks verbosity")
		}
	}
}

func TestResourceListing(t *testing.T) {
	f := newFixture(t)
	rs, err := f.cs.ListResources(context.Background(), nil)
	if err != nil || len(rs.Resources) != 1 || rs.Resources[0].URI != SchemaURI {
		t.Fatalf("resources = %+v %v", rs, err)
	}
	ts, err := f.cs.ListResourceTemplates(context.Background(), nil)
	if err != nil || len(ts.ResourceTemplates) != 1 || ts.ResourceTemplates[0].URITemplate != "bellugraph://{kind}/{hex}" {
		t.Fatalf("templates = %+v %v", ts, err)
	}
}

func TestInvalidVerbosityRejectedByReadTools(t *testing.T) {
	f := newFixture(t)
	h := f.ids["host"]
	for name, args := range map[string]map[string]any{
		"describe_schema": {},
		"describe_type":   {"kind": "host"},
		"find_entities":   {"kind": "host"},
		"get_entity":      {"entity_id": h},
		"get_neighbors":   {"entity_id": h},
		"find_path":       {"from": h, "to": f.ids["lone"]},
		"impact_of":       {"entity_id": h},
		"entity_history":  {"entity_id": h},
		"recent_changes":  {},
		"graph_diff":      {"from": "2024-12-31T00:00:00Z", "to": "2025-01-02T00:00:00Z"},
		"telemetry_keys":  {"entity_id": h},
	} {
		args["verbosity"] = "loud"
		if _, txt, isErr := f.call(t, name, args); !isErr || !strings.Contains(txt, "verbosity") {
			t.Errorf("%s: isErr=%v %q", name, isErr, txt)
		}
	}
}
