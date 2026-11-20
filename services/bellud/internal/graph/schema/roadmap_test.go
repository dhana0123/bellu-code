package schema_test

import (
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schemaall"
)

var update = flag.Bool("update", false, "rewrite the roadmap block in the README")

const (
	readmePath  = "../../../../../docs/features/security-graph/README.md"
	roadmapFrom = "<!-- roadmap:start -->"
	roadmapTo   = "<!-- roadmap:end -->"
)

func TestRoadmapMatchesREADME(t *testing.T) {
	r, err := schemaall.Default()
	if err != nil {
		t.Fatal(err)
	}
	want := schema.RoadmapMarkdown(r)
	b, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	i, j := strings.Index(doc, roadmapFrom), strings.Index(doc, roadmapTo)
	if i < 0 || j < i {
		t.Fatalf("README has no %s ... %s block", roadmapFrom, roadmapTo)
	}
	if *update {
		doc = doc[:i+len(roadmapFrom)] + "\n" + want + doc[j:]
		if err := os.WriteFile(readmePath, []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	got := strings.TrimPrefix(doc[i+len(roadmapFrom):j], "\n")
	if got != want {
		t.Fatalf("roadmap block is stale; run go test ./internal/graph/schema -update\n got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRoadmapRows(t *testing.T) {
	r, err := schemaall.Default()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range r.Categories() {
		switch c.Status {
		case schema.Implemented:
		case schema.RegisteredOnly:
			if len(c.ReadOps) == 0 {
				t.Errorf("category %s is registered-only with no read operation", c.ID)
			}
		default:
			t.Errorf("category %s has status %q", c.ID, c.Status)
		}
	}
	md := schema.RoadmapMarkdown(r)
	if n := strings.Count(md, "\n") - 2; n != len(r.Categories()) {
		t.Errorf("table has %d rows, want %d", n, len(r.Categories()))
	}
}

// The README documents the registry rules (Requirement 15.3).
func TestREADMESections(t *testing.T) {
	b, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	for _, h := range []string{
		"## Per-source registry", "### Naming convention", "### Direction_Rule",
		"### Edge_Attributes", "### Reified_Node rule", "## Roadmap",
	} {
		if !strings.Contains(doc, "\n"+h+"\n") {
			t.Errorf("README lacks the section %q", h)
		}
	}
	if strings.Contains(doc, "Relations have no confidence attribute") {
		t.Error("README still says relations have no attributes")
	}
	r, err := schemaall.Default()
	if err != nil {
		t.Fatal(err)
	}
	i, j := strings.Index(doc, roadmapFrom), strings.Index(doc, roadmapTo)
	if i < 0 || j < i || strings.TrimPrefix(doc[i+len(roadmapFrom):j], "\n") != schema.RoadmapMarkdown(r) {
		t.Error("the roadmap block does not equal RoadmapMarkdown")
	}
}
