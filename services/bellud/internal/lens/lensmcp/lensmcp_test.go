package lensmcp

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bellu/bellucode/services/bellud/internal/lens"
)

type fake struct{ got lens.Params }

func (f *fake) Slice(_ context.Context, id string, p lens.Params) (lens.Slice, error) {
	f.got = p
	return lens.Slice{
		Lens: id, Root: "r",
		Nodes: []lens.Node{{ID: "r", Kind: "host"}, {ID: "a", Kind: "host", Hops: 1}},
		Edges: []lens.SliceEdge{{From: "r", To: "a", Type: "likely_same_as", Confidence: lens.ConfInferred}},
		Paths: []lens.Path{{Nodes: []string{"r", "a"}, Confidence: lens.ConfInferred}},
	}, nil
}

func (f *fake) Exposed(_ context.Context, p lens.Params) (lens.Slice, error) {
	f.got = p
	return lens.Slice{
		Nodes:       []lens.Node{{ID: "i", Kind: "aws_resource"}, {ID: "e", Kind: "aws_resource"}},
		Edges:       []lens.SliceEdge{{From: "i", To: "e", Type: "aws_has_eni", Confidence: lens.ConfExtracted, Evidence: "x"}},
		Paths:       []lens.Path{{Nodes: []string{"i", "e"}, Confidence: lens.ConfExtracted}},
		MissingData: []string{},
	}, nil
}

func TestExposedResourcesTool(t *testing.T) {
	out := exposed(lens.Slice{
		Nodes: []lens.Node{{ID: "i"}, {ID: "e"}},
		Edges: []lens.SliceEdge{{From: "i", To: "e", Confidence: lens.ConfExtracted, Evidence: "ev", ObservedAt: "2026-01-01T00:00:00Z"}},
		Paths: []lens.Path{{Nodes: []string{"i", "e"}, Confidence: lens.ConfExtracted}},
	}, 10)
	if len(out.Items) != 1 || out.Items[0].ID != "i" || out.Items[0].Edges[0].Evidence != "ev" || out.MissingData == nil {
		t.Fatalf("%+v", out)
	}
}

func TestToolsReadOnlyLimitsAndConfidence(t *testing.T) {
	ctx := context.Background()
	f := &fake{}
	srv := mcp.NewServer(&mcp.Implementation{Name: "t"}, nil)
	Register(srv, f)
	ct, st := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	sess, err := mcp.NewClient(&mcp.Implementation{Name: "c"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	tools, err := sess.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) != len(Names) {
		t.Fatalf("got %d tools", len(tools.Tools))
	}
	for _, tl := range tools.Tools {
		if tl.Annotations == nil || !tl.Annotations.ReadOnlyHint {
			t.Fatalf("%s not read-only", tl.Name)
		}
	}
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: ToolBlastRadius, Arguments: map[string]any{"entity": "r", "limit": 999}})
	if err != nil || res.IsError {
		t.Fatalf("blast_radius: %v %+v", err, res)
	}
	if f.got.MaxNodes != MaxLimit {
		t.Fatalf("limit not clamped: %d", f.got.MaxNodes)
	}
	res, err = sess.CallTool(ctx, &mcp.CallToolParams{Name: ToolAttackPaths, Arguments: map[string]any{"target": "a"}})
	if err != nil || res.IsError {
		t.Fatalf("attack_paths: %v %+v", err, res)
	}
	if f.got.MaxNodes != DefaultLimit {
		t.Fatalf("default limit: %d", f.got.MaxNodes)
	}
	out := attackPaths(lens.Slice{
		Nodes: []lens.Node{{ID: "r"}, {ID: "a"}},
		Edges: []lens.SliceEdge{{From: "r", To: "a", Confidence: lens.ConfInferred}},
		Paths: []lens.Path{{Nodes: []string{"r", "a"}, Confidence: lens.ConfInferred}},
	}, 10)
	if len(out.Paths) != 1 || out.Paths[0].Confidence != lens.ConfInferred || out.Paths[0].Edges[0].Confidence != lens.ConfInferred {
		t.Fatalf("%+v", out)
	}
}
