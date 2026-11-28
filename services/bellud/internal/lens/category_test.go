package lens

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/facade"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schemaall"
)

type awsGraph struct {
	eng *Engine
	ids map[string]string // short name to entity id
}

func resourceEntity(name, typ string) (batch.Entity, map[string]string) {
	id := map[string]string{"connection": "c1", "arn": "arn:" + name}
	return batch.Entity{Type: "aws_resource", Identity: id, Attributes: map[string]any{"resource_type": typ}}, id
}

// newAWSGraph opens a real graph engine and writes:
//
//	i1 (ec2:instance) -aws_has_eni-> e1 (ec2:eni) -aws_member_of_sg-> s1 (ec2:security-group)
//	rule1, rule2 (aws_sg_rule) -aws_rule_of-> s1
//	b1 (s3:bucket), r1 (iam:role) with no relations
func newAWSGraph(t *testing.T) awsGraph {
	t.Helper()
	ctx := context.Background()
	en, err := facade.Open(ctx, facade.Config{Enabled: true, Dir: filepath.Join(t.TempDir(), "g")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { en.Close(ctx) })

	ids := map[string]string{}
	var b batch.Batch
	b.Collector = "aws"
	b.ObservedAt = time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	for name, typ := range map[string]string{
		"i1": "ec2:instance", "e1": "ec2:eni", "s1": "ec2:security-group", "b1": "s3:bucket", "r1": "iam:role",
	} {
		en, id := resourceEntity(name, typ)
		h, err := facade.Hash("aws_resource", id)
		if err != nil {
			t.Fatal(err)
		}
		ids[name] = string(h)
		b.Entities = append(b.Entities, en)
	}
	for _, name := range []string{"rule1", "rule2"} {
		id := map[string]string{"connection": "c1", "sg": "arn:s1", "rule_id": name}
		h, err := facade.Hash("aws_sg_rule", id)
		if err != nil {
			t.Fatal(err)
		}
		ids[name] = string(h)
		b.Entities = append(b.Entities, batch.Entity{Type: "aws_sg_rule", Identity: id})
	}
	rel := func(typ, from, to string) {
		b.Relations = append(b.Relations, batch.Relation{Type: typ, From: ids[from], To: ids[to]})
	}
	rel("aws_has_eni", "i1", "e1")
	rel("aws_member_of_sg", "e1", "s1")
	rel("aws_rule_of", "rule1", "s1")
	rel("aws_rule_of", "rule2", "s1")
	if _, err := en.Ingest().Apply(ctx, b); err != nil {
		t.Fatal(err)
	}

	src, err := NewSource(en)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := schemaall.Default()
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine(src)
	eng.BindCategories(reg)
	return awsGraph{eng: eng, ids: ids}
}

// byHops returns the short names of the nodes of s per hop count.
func (g awsGraph) byHops(t *testing.T, s Slice) map[int][]string {
	t.Helper()
	short := map[string]string{}
	for n, id := range g.ids {
		short[id] = n
	}
	out := map[int][]string{}
	seen := map[string]bool{}
	for _, n := range s.Nodes {
		if seen[n.ID] {
			t.Fatalf("node %s appears twice", short[n.ID])
		}
		seen[n.ID] = true
		out[n.Hops] = append(out[n.Hops], short[n.ID])
	}
	for _, v := range out {
		slices.Sort(v)
	}
	return out
}

func slice(t *testing.T, g awsGraph, id string) Slice {
	t.Helper()
	s, err := g.eng.Slice(context.Background(), id, Params{})
	if err != nil {
		t.Fatalf("%s: %v", id, err)
	}
	return s
}

func TestCategoryLensesGenerated(t *testing.T) {
	reg, err := schemaall.Default()
	if err != nil {
		t.Fatal(err)
	}
	defs := CategoryLenses(reg)
	if len(defs) != len(schema.OverviewOrder) {
		t.Fatalf("%d lenses", len(defs))
	}
	for i, d := range defs {
		c := schema.OverviewOrder[i]
		if d.ID != "category-"+strings.ReplaceAll(string(c), "_", "-") || d.Overview != c || d.Select != SelectCategory {
			t.Errorf("%d: %+v", i, d)
		}
	}
	byID := map[string]Def{}
	for _, d := range defs {
		byID[d.ID] = d
	}
	if !slices.Contains(byID["category-identity"].Kinds, "aws_resource") ||
		!slices.Contains(byID["category-data-security"].Kinds, "aws_resource") ||
		!slices.Contains(byID["category-cloud-infrastructure"].Kinds, "aws_resource") ||
		slices.Contains(byID["category-network-exposure"].Kinds, "aws_resource") {
		t.Errorf("kinds: %v", byID)
	}
	if !slices.Contains(byID["category-network-exposure"].Relations, "aws_rule_of") ||
		!slices.Contains(byID["category-cloud-infrastructure"].Relations, "aws_has_eni") {
		t.Errorf("relations: %v", byID)
	}
	if !slices.Contains(byID["category-data-security"].Needs, "data") || !slices.Contains(byID["category-identity"].Needs, "identity") {
		t.Errorf("needs: %v / %v", byID["category-data-security"].Needs, byID["category-identity"].Needs)
	}
	if CategoryLenses(nil) != nil {
		t.Error("nil registry")
	}
}

func TestCategorySliceMembershipUsesTypeOverrides(t *testing.T) {
	g := newAWSGraph(t)
	cases := map[string]map[int][]string{
		// instance, eni and group are cloud_infrastructure; both rules are one hop away.
		"category-cloud-infrastructure": {0: {"e1", "i1", "s1"}, 1: {"rule1", "rule2"}},
		// s3:bucket is data_security and iam:role is identity, not cloud_infrastructure.
		"category-data-security": {0: {"b1"}},
		"category-identity":      {0: {"r1"}},
		"category-secrets":       {},
	}
	for id, want := range cases {
		s := slice(t, g, id)
		got := g.byHops(t, s)
		if len(got) != len(want) {
			t.Errorf("%s: %v, want %v", id, got, want)
			continue
		}
		for h, names := range want {
			if !slices.Equal(got[h], names) {
				t.Errorf("%s hop %d: %v, want %v", id, h, got[h], names)
			}
		}
		if s.Truncated || s.Reason != "" || s.Lens != id {
			t.Errorf("%s: truncated=%v reason=%q lens=%q", id, s.Truncated, s.Reason, s.Lens)
		}
	}
}

func TestCategorySliceNeighboursDeduplicated(t *testing.T) {
	g := newAWSGraph(t)
	// Both rules are primaries of network_exposure; s1 neighbours both but appears once.
	s := slice(t, g, "category-network-exposure")
	got := g.byHops(t, s)
	if !slices.Equal(got[0], []string{"rule1", "rule2"}) || !slices.Equal(got[1], []string{"s1"}) || len(s.Nodes) != 3 {
		t.Fatalf("%v", got)
	}
	if len(s.Edges) != 2 {
		t.Fatalf("edges %+v", s.Edges)
	}
	// Cloud: e1 and s1 are both primary and neighbours of each other; each stays at hop 0.
	cloud := slice(t, g, "category-cloud-infrastructure")
	edges := 0
	for _, e := range cloud.Edges {
		if e.Type == "aws_member_of_sg" {
			edges++
		}
	}
	if edges != 1 {
		t.Fatalf("aws_member_of_sg edges: %d", edges)
	}
}

func TestCategorySliceEntityLimit(t *testing.T) {
	g := newAWSGraph(t)
	g.eng.catMax = 2
	s := slice(t, g, "category-cloud-infrastructure")
	if !s.Truncated || s.Reason != ReasonEntityLimit || len(s.Nodes) != 2 {
		t.Fatalf("truncated=%v reason=%q nodes=%d", s.Truncated, s.Reason, len(s.Nodes))
	}
	// Primary entities are kept before neighbours: limit 3 keeps the three members.
	g.eng.catMax = 3
	s = slice(t, g, "category-cloud-infrastructure")
	if !s.Truncated || s.Reason != ReasonEntityLimit || !slices.Equal(g.byHops(t, s)[0], []string{"e1", "i1", "s1"}) || len(s.Nodes) != 3 {
		t.Fatalf("limit 3: %v %q %v", s.Truncated, s.Reason, g.byHops(t, s))
	}
}

func TestCategorySliceTimeLimit(t *testing.T) {
	g := newAWSGraph(t)
	g.eng.catTime = time.Nanosecond
	s := slice(t, g, "category-cloud-infrastructure")
	if !s.Truncated || s.Reason != ReasonTimeLimit {
		t.Fatalf("truncated=%v reason=%q", s.Truncated, s.Reason)
	}
	// A cancelled caller is an error, not a truncation.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	g.eng.catTime = 0
	if _, err := g.eng.Slice(ctx, "category-cloud-infrastructure", Params{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

func TestCategoryUnknownLensHasNoEntities(t *testing.T) {
	g := newAWSGraph(t)
	s, err := g.eng.Slice(context.Background(), "category-nope", Params{})
	var unknown ErrUnknownLens
	if !errors.As(err, &unknown) || unknown.ID != "category-nope" || len(s.Nodes) != 0 || len(s.Edges) != 0 {
		t.Fatalf("%+v %v", s, err)
	}
}

func TestExistingLensesUnchanged(t *testing.T) {
	g := newAWSGraph(t)
	static := Catalog()
	ids := []string{"code-to-cloud", "cloud", "blast-radius", "attack-path", "vulnerability-reachability"}
	if len(static) != len(ids) {
		t.Fatalf("static catalog has %d lenses", len(static))
	}
	for i, d := range static {
		if d.ID != ids[i] || d.Relations != nil || d.Overview != "" {
			t.Errorf("%d: %+v", i, d)
		}
	}
	all := g.eng.Catalog()
	if len(all) != len(ids)+9 {
		t.Fatalf("engine catalog has %d lenses", len(all))
	}
	for i, d := range all[:len(ids)] {
		if d.ID != ids[i] {
			t.Errorf("order %d: %s", i, d.ID)
		}
	}
	// The cloud lens still selects by kinds and its JSON has no reason field.
	s := slice(t, g, "cloud")
	b, err := json.Marshal(s)
	if err != nil || strings.Contains(string(b), `"reason"`) || len(s.Nodes) != 5 || s.Counts.OmittedRules != 2 { // rule nodes collapse
		t.Fatalf("cloud: %d nodes, err %v, %s", len(s.Nodes), err, b)
	}
	if _, err := g.eng.Slice(context.Background(), DefaultLens, Params{}); err != nil {
		t.Fatal(err)
	}
}

func TestServiceServesCategoryLensesAfterBind(t *testing.T) {
	svc := NewService()
	if len(svc.Catalog()) != len(Catalog()) {
		t.Fatal("unbound catalog should hold only the static lenses")
	}
	if _, err := svc.Slice(context.Background(), "category-identity", Params{}); !errors.As(err, new(ErrUnknownLens)) {
		t.Fatalf("unbound: %v", err)
	}
	ctx := context.Background()
	en, err := facade.Open(ctx, facade.Config{Enabled: true, Dir: filepath.Join(t.TempDir(), "g")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { en.Close(ctx) })
	if err := svc.Bind(en); err != nil {
		t.Fatal(err)
	}
	if len(svc.Catalog()) != len(Catalog())+9 {
		t.Fatalf("bound catalog %d", len(svc.Catalog()))
	}
	s, err := svc.Slice(ctx, "category-identity", Params{})
	if err != nil || len(s.Nodes) != 0 || s.Truncated {
		t.Fatalf("%+v %v", s, err)
	}
	if _, err := svc.Slice(ctx, "category-nope", Params{}); !errors.As(err, new(ErrUnknownLens)) {
		t.Fatalf("%v", err)
	}
}
