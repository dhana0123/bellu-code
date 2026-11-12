package engine

import (
	"context"
	"fmt"
	"pgregory.net/rapid"
	"sort"
	"strconv"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/codec"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/internal/gen"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/internal/gen/model"
)

// propFixture is an Engine and the reference model folded from the same inputs.
type propFixture struct {
	c      *Core
	m      *model.Model
	events []model.Event
}

// buildPropFixture applies a random schedule (and some annotations) to an
// Engine and to the model. Steps the model rejects are skipped in both.
func buildPropFixture(t *rapid.T, withAnnotations bool) *propFixture {
	steps := gen.Options{ForeignEndpoints: true}.Schedule(1, 12).Draw(t, "schedule")
	clk := &stepClock{t: gen.Epoch}
	f := &propFixture{c: propEngine(t, clk.now), m: model.New()}
	ctx := context.Background()
	n := 0
	for i, s := range steps {
		clk.t = s.Now
		mevs, merr := f.m.Fold(s.Batch, s.Mode, s.Now)
		_, err := f.c.Apply(ctx, s.Batch, engineMode(s.Mode))
		if (err != nil) != (merr != nil) {
			t.Fatalf("step %d: engine err %v, model err %v", i, err, merr)
		}
		f.events = append(f.events, mevs...)
		if !withAnnotations || rapid.IntRange(0, 2).Draw(t, "annotate") != 0 {
			continue
		}
		live := f.m.Current().LiveIDs()
		if len(live) == 0 {
			continue
		}
		id := rapid.SampledFrom(live).Draw(t, "annotated")
		n++
		set := map[string]string{"note": fmt.Sprintf("v%d", n)} // always a real change
		if _, err := f.c.Annotate(ctx, id, set, nil, "op"); err != nil {
			t.Fatal(err)
		}
		ev, err := f.m.Annotate(id, "op", set, nil, s.Now)
		if err != nil {
			t.Fatal(err)
		}
		f.events = append(f.events, ev)
	}
	return f
}

// pageSize draws a page size from 1 to 1000, often small so results span pages.
func pageSize(t *rapid.T) int {
	return rapid.OneOf(rapid.IntRange(1, 4), rapid.IntRange(1, 1000)).Draw(t, "pageSize")
}

// walkPages follows cursors to the end and checks the pagination law: every
// page reports the same Total, Truncated is false only on the last page, and
// the concatenation has Total items.
func walkPages[T any](t *rapid.T, size int, fetch func(cursor string) (Page[T], error)) ([]T, int) {
	var all []T
	cursor, total := "", -1
	for i := 0; ; i++ {
		pg, err := fetch(cursor)
		if err != nil {
			t.Fatalf("page %d: %v", i, err)
		}
		if total >= 0 && pg.Total != total {
			t.Fatalf("page %d: Total %d, previous %d", i, pg.Total, total)
		}
		total = pg.Total
		if len(pg.Items) > size {
			t.Fatalf("page %d: %d items exceed size %d", i, len(pg.Items), size)
		}
		all = append(all, pg.Items...)
		if pg.Truncated != (pg.NextCursor != "") {
			t.Fatalf("page %d: Truncated=%v with cursor %q", i, pg.Truncated, pg.NextCursor)
		}
		if !pg.Truncated {
			break
		}
		if len(pg.Items) != size {
			t.Fatalf("page %d: truncated page has %d items, size %d", i, len(pg.Items), size)
		}
		if i > total+2 {
			t.Fatalf("pagination does not terminate (total %d)", total)
		}
		cursor = pg.NextCursor
	}
	if len(all) != total {
		t.Fatalf("concatenation has %d items, Total %d", len(all), total)
	}
	return all, total
}

func attrString(v codec.Value) []string {
	switch v.T {
	case codec.TagString:
		return []string{v.S}
	case codec.TagBool:
		return []string{strconv.FormatBool(v.B)}
	case codec.TagInt:
		return []string{strconv.FormatInt(v.I, 10)}
	case codec.TagFloat:
		return []string{strconv.FormatFloat(v.F, 'g', -1, 64)}
	case codec.TagList:
		return v.L
	}
	return nil
}

// modelMatches is the naive attribute match: identity first, then descriptive
// attributes by string form (a list matches any element).
func modelMatches(e *model.Entity, attrs map[string]string) bool {
	for k, want := range attrs {
		if v, ok := e.Identity[k]; ok {
			if v != want {
				return false
			}
			continue
		}
		v, ok := e.Attrs[k]
		if !ok {
			return false
		}
		found := false
		for _, s := range attrString(v) {
			if s == want {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Feature: bellu-graph-native, Property 13: Find and pagination
// Validates: Requirements 6.1, 6.2, 6.8
func TestPropFindPagination(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		f := buildPropFixture(t, false)
		ms := f.m.Current()
		kind := rapid.SampledFrom(append([]string{""}, gen.DefaultUniverse().Kinds...)).Draw(t, "kind")
		attrs := map[string]string{}
		if live := ms.LiveIDs(); len(live) > 0 {
			for i, n := 0, rapid.IntRange(0, 2).Draw(t, "nattrs"); i < n; i++ {
				e := ms.Entities[rapid.SampledFrom(live).Draw(t, "src")]
				pool := map[string][]string{}
				for k, v := range e.Identity {
					pool[k] = []string{v}
				}
				for k, v := range e.Attrs {
					pool[k] = attrString(v)
				}
				var keys []string
				for k, vs := range pool {
					if len(vs) > 0 {
						keys = append(keys, k)
					}
				}
				sort.Strings(keys)
				if len(keys) == 0 {
					continue
				}
				k := rapid.SampledFrom(keys).Draw(t, "key")
				attrs[k] = rapid.SampledFrom(pool[k]).Draw(t, "value")
			}
		}
		var want []string
		for _, id := range ms.LiveIDs() {
			e := ms.Entities[id]
			if (kind == "" || e.Kind == kind) && modelMatches(e, attrs) {
				want = append(want, id)
			}
		}
		sort.Strings(want)
		size := pageSize(t)
		items, total := walkPages(t, size, func(cursor string) (Page[EntityView], error) {
			return f.c.Find(context.Background(), FindQuery{Kind: kind, Attributes: attrs, Paging: Paging{PageSize: size, Cursor: cursor}}, nil)
		})
		if total != len(want) {
			t.Fatalf("Total %d, model %d (kind %q attrs %v)", total, len(want), kind, attrs)
		}
		for i, it := range items {
			if i >= len(want) || it.ID != want[i] {
				t.Fatalf("item %d is %s, model list %v", i, it.ID, want)
			}
			if it.Kind != ms.Entities[it.ID].Kind {
				t.Fatalf("item %s kind %q, model %q", it.ID, it.Kind, ms.Entities[it.ID].Kind)
			}
		}
	})
}
