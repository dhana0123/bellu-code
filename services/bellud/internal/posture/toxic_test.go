package posture

import (
	"context"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/facade"
)

// memGraph is a small in-memory graph: entities by id and stored edges.
type memGraph struct {
	ents  map[string]facade.Entity
	edges []facade.Edge
}

func newGraph() *memGraph { return &memGraph{ents: map[string]facade.Entity{}} }

func (g *memGraph) add(id, typ string, attrs map[string]any) *memGraph {
	g.ents[id] = facade.Entity{ID: facade.EntityID(id), Type: typ, Attributes: attrs}
	return g
}

func (g *memGraph) link(from, rel, to string) *memGraph {
	g.edges = append(g.edges, facade.Edge{From: facade.EntityID(from), To: facade.EntityID(to), Type: rel, Direction: facade.DirBoth})
	return g
}

func (g *memGraph) Entity(_ context.Context, id facade.EntityID, _ *time.Time) (facade.Entity, error) {
	e, ok := g.ents[string(id)]
	if !ok {
		return facade.Entity{}, context.Canceled
	}
	return e, nil
}

func (g *memGraph) Find(context.Context, facade.FindQuery) (facade.Page[facade.Entity], error) {
	return facade.Page[facade.Entity]{}, nil
}

func (g *memGraph) Neighbors(_ context.Context, id facade.EntityID, o facade.NeighborOpts) (facade.Page[facade.Edge], error) {
	var out []facade.Edge
	for _, e := range g.edges {
		if (e.From == id || e.To == id) && (o.RelationType == "" || e.Type == o.RelationType) {
			out = append(out, e)
		}
	}
	return facade.Page[facade.Edge]{Items: out}, nil
}

func toxicMatches(t *testing.T, g *memGraph, id string) []Match {
	t.Helper()
	ps, errs, err := LoadAll(Bundled())
	if err != nil || len(errs) != 0 {
		t.Fatalf("load: %v %v", err, errs)
	}
	e, cerrs := NewEngine(context.Background(), ps, g)
	if len(cerrs) != 0 {
		t.Fatal(cerrs)
	}
	ent := g.ents[id]
	ms, ees := e.EvalEntity(context.Background(), Input{ID: id, Type: ent.Type, Attributes: ent.Attributes})
	if len(ees) != 0 {
		t.Fatal(ees)
	}
	var out []Match
	for _, m := range ms {
		if m.PackID == "bellu" && len(m.RuleID) > 6 && m.RuleID[:6] == "toxic_" {
			out = append(out, m)
		}
	}
	return out
}

func wantPath(t *testing.T, ms []Match, rule string, want []Hop) {
	t.Helper()
	if len(ms) != 1 || ms[0].RuleID != rule {
		t.Fatalf("want one %s match, got %+v", rule, ms)
	}
	got := ms[0].Path
	if len(got) != len(want) {
		t.Fatalf("path %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("path %v, want %v", got, want)
		}
	}
}

func TestToxicExposedVuln(t *testing.T) {
	build := func(vuln map[string]any, exposed string) *memGraph {
		return newGraph().
			add("w", "aws_resource", map[string]any{"internet_exposed": exposed}).
			add("img", "image", nil).add("pkg", "package", nil).add("v", "vulnerability", vuln).
			link("w", "aws_uses_image", "img").link("pkg", "contained_in", "img").link("pkg", "affected_by", "v")
	}
	hops := []Hop{{"w", ""}, {"img", "aws_uses_image"}, {"pkg", "contained_in"}, {"v", "affected_by"}}
	wantPath(t, toxicMatches(t, build(map[string]any{"kev": true, "epss": 0.1}, "true"), "w"), "toxic_exposed_vuln", hops)
	wantPath(t, toxicMatches(t, build(map[string]any{"kev": false, "epss": 0.5}, "true"), "w"), "toxic_exposed_vuln", hops)
	if ms := toxicMatches(t, build(map[string]any{"kev": false, "epss": 0.49}, "true"), "w"); len(ms) != 0 {
		t.Fatalf("low epss fired: %+v", ms)
	}
	if ms := toxicMatches(t, build(map[string]any{"kev": true, "epss": 0.9}, "false"), "w"); len(ms) != 0 {
		t.Fatalf("unexposed fired: %+v", ms)
	}
}

func TestToxicExposedDataAccess(t *testing.T) {
	build := func(classes []any, withEdge bool) *memGraph {
		g := newGraph().
			add("w", "aws_resource", map[string]any{"internet_exposed": "true"}).
			add("role", "aws_resource", nil).
			add("db", "aws_resource", map[string]any{"data_classes": classes}).
			link("w", "aws_exec_role", "role")
		if withEdge {
			g.link("role", "aws_can_access", "db")
		}
		return g
	}
	wantPath(t, toxicMatches(t, build([]any{"PII"}, true), "w"), "toxic_exposed_data_access",
		[]Hop{{"w", ""}, {"role", "aws_exec_role"}, {"db", "aws_can_access"}})
	if ms := toxicMatches(t, build([]any{"PII"}, false), "w"); len(ms) != 0 {
		t.Fatalf("no access edge fired: %+v", ms)
	}
	if ms := toxicMatches(t, build([]any{"public_docs"}, true), "w"); len(ms) != 0 {
		t.Fatalf("non-sensitive fired: %+v", ms)
	}
}

func TestToxicPublicSensitiveBucket(t *testing.T) {
	build := func(public string, classes []any) *memGraph {
		return newGraph().add("b", "aws_resource", map[string]any{"resource_type": "s3:bucket", "public_access": public, "data_classes": classes})
	}
	wantPath(t, toxicMatches(t, build("enabled", []any{"phi"}), "b"), "toxic_public_sensitive_bucket", []Hop{{"b", ""}})
	if ms := toxicMatches(t, build("disabled", []any{"phi"}), "b"); len(ms) != 0 {
		t.Fatalf("private fired: %+v", ms)
	}
	if ms := toxicMatches(t, build("enabled", nil), "b"); len(ms) != 0 {
		t.Fatalf("no classes fired: %+v", ms)
	}
}

func TestToxicSecretReachable(t *testing.T) {
	build := func(withEgress bool) *memGraph {
		g := newGraph().
			add("f", "finding", map[string]any{"finding_type": "secret", "status": "open", "target_id": "db"}).
			add("w", "aws_resource", nil).add("db", "aws_resource", nil).
			link("f", "affects", "w")
		if withEgress {
			g.link("w", "aws_allows_egress_to", "db")
		}
		return g
	}
	wantPath(t, toxicMatches(t, build(true), "f"), "toxic_secret_reachable",
		[]Hop{{"f", ""}, {"w", "affects"}, {"db", "aws_allows_egress_to"}})
	if ms := toxicMatches(t, build(false), "f"); len(ms) != 0 {
		t.Fatalf("unreachable fired: %+v", ms)
	}
}

// Rules (e) and (f) target kinds that arrive in Phases 7 and 9. They must be
// loaded (so they compile) and must not fire on an unrelated graph.
func TestToxicPhaseRulesCompile(t *testing.T) {
	ps, errs, err := LoadAll(Bundled())
	if err != nil || len(errs) != 0 {
		t.Fatalf("load: %v %v", err, errs)
	}
	found := map[string]bool{}
	for _, p := range ps {
		for _, r := range p.Rules {
			if p.ID == "bellu" && r.Kind == KindToxicCombination {
				found[r.ID] = true
			}
		}
	}
	for _, id := range []string{"toxic_k8s_privileged_admin", "toxic_ai_agent_write_external"} {
		if !found[id] {
			t.Errorf("%s not loaded", id)
		}
	}
	if len(found) != 6 {
		t.Errorf("want 6 toxic rules, got %v", found)
	}
}
