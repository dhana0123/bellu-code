package lens

import (
	"context"
	"errors"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/facade"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
)

// SelectCategory selects the entities of one Overview category plus their
// one-hop neighbours over the included relations.
const SelectCategory = "category"

// Reasons recorded in Slice.Reason when a category slice is truncated.
const (
	ReasonTimeLimit   = "time_limit"
	ReasonEntityLimit = "entity_limit"
)

// Budget of one category slice (Requirement 2.5).
const (
	categoryTimeBudget = 5000 * time.Millisecond
	categoryMaxEntity  = collectCap
	// categoryMaxEdges bounds the edges of one category slice.
	categoryMaxEdges = 20000
)

// categoryTitles are the display names of the nine Overview categories.
var categoryTitles = map[schema.OverviewCategory]string{
	schema.OvCloud:    "Cloud infrastructure",
	schema.OvIdentity: "Identity",
	schema.OvVuln:     "Vulnerabilities",
	schema.OvNetwork:  "Network exposure",
	schema.OvSecrets:  "Secrets",
	schema.OvData:     "Data security",
	schema.OvCode:     "Code and dependencies",
	schema.OvRuntime:  "Runtime",
	schema.OvAI:       "AI security",
}

// CategoryLenses builds the nine category lenses, in schema.OverviewOrder,
// from reg. Kinds, Relations and Needs are read from the registry. The lens
// id is "category-" plus the category with "_" replaced by "-".
func CategoryLenses(reg *schema.Registry) []Def {
	if reg == nil {
		return nil
	}
	out := make([]Def, 0, len(schema.OverviewOrder))
	for _, c := range schema.OverviewOrder {
		out = append(out, categoryDef(reg, c))
	}
	return out
}

func categoryDef(reg *schema.Registry, c schema.OverviewCategory) Def {
	var kinds []string
	names := map[string]bool{} // kind names and type names that can hold category c
	needs := map[string]bool{}
	for _, k := range reg.Kinds() {
		member := k.Overview == c
		for _, t := range k.Types {
			if reg.OverviewOf(k.Name, t.Name) != c {
				continue
			}
			member = true
			names[t.Name] = true
			if t.Category != "" {
				needs[t.Category] = true
			}
		}
		if member {
			kinds = append(kinds, k.Name)
			names[k.Name] = true
		}
	}
	var relations []string
	for _, r := range reg.Relations() {
		if !slices.ContainsFunc(r.From, func(n string) bool { return names[n] }) &&
			!slices.ContainsFunc(r.To, func(n string) bool { return names[n] }) {
			continue
		}
		relations = append(relations, r.Name)
		if r.Category != "" {
			needs[r.Category] = true
		}
	}
	id := "category-" + strings.ReplaceAll(string(c), "_", "-")
	return Def{
		ID: id, Name: categoryTitles[c], Layout: LayoutForce,
		Description: "Assets in the " + categoryTitles[c] + " category and their direct neighbours.",
		Kinds:       kinds, Relations: relations, Overview: c,
		Select: SelectCategory, Params: []Param{},
		Needs: sortedKeys(needs),
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// BindCategories installs the category lenses generated from reg. A nil reg
// removes them.
func (e *Engine) BindCategories(reg *schema.Registry) {
	e.reg = reg
	e.cats = CategoryLenses(reg)
}

// lookup finds a static lens, then a category lens.
func (e *Engine) lookup(id string) (Def, bool) {
	if d, ok := lookup(id); ok {
		return d, true
	}
	for _, d := range e.cats {
		if d.ID == id {
			return d, true
		}
	}
	return Def{}, false
}

// categoryBudget returns the time and entity limits of a category slice.
func (e *Engine) categoryBudget() (time.Duration, int) {
	t, n := categoryTimeBudget, categoryMaxEntity
	if e.catTime != 0 {
		t = e.catTime
	}
	if e.catMax != 0 {
		n = e.catMax
	}
	return t, n
}

// selectCategory collects the entities whose primary Overview category is the
// lens category (OverviewOf with the entity's discriminator value), then adds
// each one's neighbours over the lens relations. Primary entities are
// collected first, so the entity limit drops neighbours before members.
func (b *builder) selectCategory(ctx context.Context, e *Engine) error {
	if e.reg == nil {
		return ErrUnavailable
	}
	limit, maxEntities := e.categoryBudget()
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	b.maxEntities = maxEntities

	primary, err := b.collectPrimary(ctx, e.reg)
	if err != nil || b.reason != "" {
		return b.stopOrFail(err)
	}
	sort.Strings(primary)
	rels := map[string]bool{}
	for _, r := range b.def.Relations {
		rels[r] = true
	}
	for _, id := range primary {
		if err := b.expandNeighbours(ctx, id, rels); err != nil || b.reason != "" {
			return b.stopOrFail(err)
		}
	}
	return nil
}

// stopOrFail turns an expired deadline into a time_limit truncation and
// returns any other error unchanged.
func (b *builder) stopOrFail(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		b.stop(ReasonTimeLimit)
		return nil
	}
	return err
}

// stop records the first truncation reason.
func (b *builder) stop(reason string) {
	b.truncated = true
	if b.reason == "" {
		b.reason = reason
	}
}

// EntityCategory is the primary Overview category of an entity of kind k with
// attributes attrs. The category lenses and the Overview card counts both use
// it, so a card count equals the number of primary entities of its lens.
func EntityCategory(reg *schema.Registry, k schema.KindDeclaration, attrs map[string]any) schema.OverviewCategory {
	tv := ""
	if k.Discriminator != "" {
		tv, _ = attrs[k.Discriminator].(string)
	}
	return reg.OverviewOf(k.Name, tv)
}
func (b *builder) collectPrimary(ctx context.Context, reg *schema.Registry) ([]string, error) {
	var primary []string
	for _, kind := range b.def.Kinds {
		k, ok := reg.Kind(kind)
		if !ok {
			continue
		}
		q := facade.FindQuery{Type: kind}
		q.PageSize = facade.MaxPageSize
		for {
			if err := ctx.Err(); err != nil {
				return primary, err
			}
			pg, err := b.src.Find(ctx, q)
			if err != nil {
				return primary, err
			}
			for i := range pg.Items {
				en := pg.Items[i]
				if EntityCategory(reg, k, en.Attributes) != b.def.Overview {
					continue
				}
				if len(b.nodes) >= b.maxEntities {
					b.stop(ReasonEntityLimit)
					return primary, nil
				}
				b.nodes[string(en.ID)] = &en
				b.hops[string(en.ID)] = 0
				primary = append(primary, string(en.ID))
			}
			if !pg.Truncated || pg.NextCursor == "" {
				break
			}
			q.Cursor = pg.NextCursor
		}
	}
	return primary, nil
}

func (b *builder) expandNeighbours(ctx context.Context, id string, rels map[string]bool) error {
	var cursor string
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		pg, err := b.src.Neighbors(ctx, facade.EntityID(id), facade.NeighborOpts{
			Direction: facade.DirBoth, Depth: 1, Paging: facade.Paging{PageSize: facade.MaxPageSize, Cursor: cursor},
		})
		if err != nil {
			return err
		}
		for _, edge := range pg.Items {
			if edge.Derived || !rels[edge.Type] {
				continue
			}
			other := string(edge.To)
			if other == id {
				other = string(edge.From)
			}
			if _, seen := b.nodes[other]; !seen {
				if len(b.nodes) >= b.maxEntities {
					b.stop(ReasonEntityLimit)
					return nil
				}
				b.add(other, 1)
			}
			b.addEdge(edge)
		}
		if !pg.Truncated || pg.NextCursor == "" {
			return nil
		}
		cursor = pg.NextCursor
	}
}
