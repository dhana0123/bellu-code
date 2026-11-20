package awsschema

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
)

const designPath = "../../../../../../.kiro/specs/aws-relationship-registry/design.md"

var rowRE = regexp.MustCompile("^\\| (\\d+) \\| `(\\w+)` \\| (.*?) \\| (.*?) \\| (Forward|Reverse) \\| ([EI]) \\| (.*) \\|$")

type designRow struct {
	name, dir, conf, text string
}

func designRows(t *testing.T) []designRow {
	t.Helper()
	b, err := os.ReadFile(designPath)
	if err != nil {
		t.Fatal(err)
	}
	var rows []designRow
	for _, l := range strings.Split(string(b), "\n") {
		if m := rowRE.FindStringSubmatch(l); m != nil {
			rows = append(rows, designRow{name: m[2], dir: m[5], conf: m[6], text: m[7]})
		}
	}
	return rows
}

func TestRelationTableMatchesDesign(t *testing.T) {
	rows := designRows(t)
	if len(rows) != 59 {
		t.Fatalf("design table has %d rows, want 59", len(rows))
	}
	decl := map[string]schema.RelationDeclaration{}
	for _, r := range Declaration().Relations {
		decl[r.Name] = r
	}
	if len(decl) != len(rows) {
		t.Fatalf("declaration has %d relation types, design has %d", len(decl), len(rows))
	}
	for _, row := range rows {
		d, ok := decl[row.name]
		if !ok {
			t.Errorf("%s: not declared", row.name)
			continue
		}
		if d.Direction.String() != strings.ToLower(row.dir) {
			t.Errorf("%s: direction %s, design %s", row.name, d.Direction, row.dir)
		}
		wantConf := schema.Extracted
		if row.conf == "I" {
			wantConf = schema.Inferred
		}
		if d.Confidence != wantConf {
			t.Errorf("%s: confidence %s, design %s", row.name, d.Confidence, wantConf)
		}
		if n := utf8.RuneCountInString(row.text); n > 200 {
			t.Errorf("%s: justification has %d characters, want at most 200", row.name, n)
		}
		if d.Description != row.text {
			t.Errorf("%s: description differs from the design justification", row.name)
		}
	}
}

func TestDeclarationFacts(t *testing.T) {
	d := Declaration()
	rels := map[string]schema.RelationDeclaration{}
	for _, r := range d.Relations {
		rels[r.Name] = r
	}
	for _, n := range []string{"aws_allows_ingress_from", "aws_allows_egress_to", "aws_can_access"} {
		if !rels[n].Derived {
			t.Errorf("%s must be derived", n)
		}
	}
	if !strings.Contains(rels["aws_attached_policy"].Description, "does not establish effective access") {
		t.Error("aws_attached_policy must say it does not establish effective access")
	}
	if rels["aws_allows_ingress_from"].Direction != schema.Reverse || rels["aws_allows_egress_to"].Direction != schema.Forward {
		t.Error("allows_ingress_from must be reverse and allows_egress_to forward")
	}
	if rels["aws_attached_igw"].Direction != schema.Forward || rels["aws_associated_subnet"].Direction != schema.Forward {
		t.Error("aws_attached_igw and aws_associated_subnet must be forward")
	}
	if _, ok := rels["attached_to"]; ok {
		t.Error("attached_to stays in core, not aws")
	}
	for _, c := range d.Categories {
		if c.Status == schema.RegisteredOnly && len(c.ReadOps) == 0 {
			t.Errorf("category %s is registered-only with no read operations", c.ID)
		}
		if c.Status == schema.Implemented && len(c.ReadOps) != 0 {
			t.Errorf("category %s is implemented but lists read operations", c.ID)
		}
	}
	if len(d.Categories) != 7 {
		t.Errorf("got %d categories, want 7", len(d.Categories))
	}
}
