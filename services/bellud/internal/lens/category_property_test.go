package lens

import (
	"context"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/facade"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schemaall"
)

// awsResourceTypes mixes values that hit the type overrides (iam:*, s3:bucket,
// rds:*, dynamodb:table) with values that fall back to the kind default.
var awsResourceTypes = []string{
	"iam:role", "iam:user", "iam:policy", "s3:bucket", "rds:instance", "rds:cluster",
	"dynamodb:table", "ec2:instance", "ec2:eni", "ec2:security-group", "lambda:function", "unknown:thing",
}

// endpointMatches reports whether an entity of kind with discriminator value
// typ can sit at a relation endpoint list (empty means any).
func endpointMatches(names []string, kind, typ string) bool {
	return len(names) == 0 || slices.Contains(names, kind) || (typ != "" && slices.Contains(names, typ))
}

// Feature: bellu-wiz-security-platform, Property 10: Category card count is a subset of its lens result
// Validates: Requirements 2.4
func TestPropertyCategoryCardCountSubsetOfLens(t *testing.T) {
	reg, err := schemaall.Default()
	if err != nil {
		t.Fatal(err)
	}
	kinds := reg.Kinds()
	var rels []schema.RelationDeclaration
	for _, r := range reg.Relations() {
		if !r.Derived {
			rels = append(rels, r)
		}
	}
	root := t.TempDir()
	ctx := context.Background()

	type ent struct{ id, kind, typ string }

	rapid.Check(t, func(rt *rapid.T) {
		n := rapid.IntRange(0, 40).Draw(rt, "entities")
		var b batch.Batch
		b.Collector = "prop"
		b.ObservedAt = time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
		var ents []ent
		for i := 0; i < n; i++ {
			var k schema.KindDeclaration
			var typ string
			if rapid.Bool().Draw(rt, "aws") {
				k, _ = reg.Kind("aws_resource")
				typ = rapid.SampledFrom(awsResourceTypes).Draw(rt, "resource_type")
			} else {
				k = rapid.SampledFrom(kinds).Draw(rt, "kind")
				if k.Discriminator != "" {
					opts := []string{"other"}
					for _, tp := range k.Types {
						opts = append(opts, tp.Name)
					}
					typ = rapid.SampledFrom(opts).Draw(rt, "type")
				}
			}
			identity := map[string]string{}
			for _, a := range k.Identity {
				identity[a] = fmt.Sprintf("%s-%d", a, i)
			}
			id, err := facade.Hash(k.Name, identity)
			if err != nil {
				rt.Fatal(err)
			}
			e := batch.Entity{Type: k.Name, Identity: identity}
			if k.Discriminator != "" {
				e.Attributes = map[string]any{k.Discriminator: typ}
			}
			b.Entities = append(b.Entities, e)
			ents = append(ents, ent{string(id), k.Name, typ})
		}
		if n > 1 && len(rels) > 0 {
			for range rapid.IntRange(0, 40).Draw(rt, "relations") {
				r := rapid.SampledFrom(rels).Draw(rt, "relation")
				var from, to []ent
				for _, e := range ents {
					if endpointMatches(r.From, e.kind, e.typ) {
						from = append(from, e)
					}
					if endpointMatches(r.To, e.kind, e.typ) {
						to = append(to, e)
					}
				}
				if len(from) == 0 || len(to) == 0 {
					continue
				}
				f := rapid.SampledFrom(from).Draw(rt, "from")
				d := rapid.SampledFrom(to).Draw(rt, "to")
				if f.id == d.id {
					continue
				}
				b.Relations = append(b.Relations, batch.Relation{Type: r.Name, From: f.id, To: d.id})
			}
		}

		dir, err := os.MkdirTemp(root, "g")
		if err != nil {
			rt.Fatal(err)
		}
		en, err := facade.Open(ctx, facade.Config{Enabled: true, Dir: dir})
		if err != nil {
			rt.Fatal(err)
		}
		defer en.Close(ctx)
		if _, err := en.Ingest().Apply(ctx, b); err != nil {
			rt.Fatal(err)
		}
		src, err := NewSource(en)
		if err != nil {
			rt.Fatal(err)
		}
		eng := NewEngine(src)
		eng.BindCategories(reg)

		for _, c := range schema.OverviewOrder {
			// Card membership: primary category via OverviewOf, no neighbours.
			counted := map[string]bool{}
			for _, e := range ents {
				k, _ := reg.Kind(e.kind)
				tv := ""
				if k.Discriminator != "" {
					tv = e.typ
				}
				if reg.OverviewOf(e.kind, tv) == c {
					counted[e.id] = true
				}
			}
			lensID := "category-" + string(c)
			for _, d := range CategoryLenses(reg) {
				if d.Overview == c {
					lensID = d.ID
				}
			}
			s, err := eng.Slice(ctx, lensID, Params{})
			if err != nil {
				rt.Fatalf("%s: %v", c, err)
			}
			if s.Truncated {
				rt.Fatalf("%s: truncated (%s)", c, s.Reason)
			}
			inSlice := map[string]bool{}
			hop0 := 0
			for _, nd := range s.Nodes {
				inSlice[nd.ID] = true
				if nd.Hops == 0 {
					hop0++
					if !counted[nd.ID] {
						rt.Fatalf("%s: hop-0 node %s is not a card member", c, nd.ID)
					}
				}
			}
			for id := range counted {
				if !inSlice[id] {
					rt.Fatalf("%s: counted entity %s missing from lens result", c, id)
				}
			}
			if hop0 != len(counted) {
				rt.Fatalf("%s: card count %d, hop-0 members %d (slice has %d nodes)", c, len(counted), hop0, len(s.Nodes))
			}
			if len(counted) > len(s.Nodes) {
				rt.Fatalf("%s: count %d exceeds lens size %d", c, len(counted), len(s.Nodes))
			}
		}
	})
}
