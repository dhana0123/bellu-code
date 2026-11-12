package engine

import (
	"context"
	"sort"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/internal/gen"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/internal/gen/model"
)

func drawBound(t *rapid.T, name string) time.Time {
	if rapid.IntRange(0, 2).Draw(t, name+"Zero") == 0 {
		return time.Time{}
	}
	return gen.ValidTime().Draw(t, name)
}

func inRange(v time.Time, r TimeRange) bool {
	return (r.From.IsZero() || v.UnixNano() >= r.From.UnixNano()) && (r.To.IsZero() || v.UnixNano() <= r.To.UnixNano())
}

func sortChanges(cs []model.Change, desc bool) {
	sort.SliceStable(cs, func(i, j int) bool {
		a, b := cs[i], cs[j]
		less := a.Valid.UnixNano() < b.Valid.UnixNano() || (a.Valid.UnixNano() == b.Valid.UnixNano() && a.Seq < b.Seq)
		if desc {
			return !less && (a.Valid.UnixNano() != b.Valid.UnixNano() || a.Seq != b.Seq)
		}
		return less
	})
}

func checkChanges(t *rapid.T, ms *model.State, got []ChangeView, want []model.Change) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d changes, model %d", len(got), len(want))
	}
	for i, w := range want {
		g := got[i]
		if g.Seq != w.Seq || string(g.Kind) != w.Kind || string(g.Subject) != w.Subject || g.ObservedAt.UnixNano() != w.Valid.UnixNano() {
			t.Fatalf("change %d: got %+v, model %+v", i, g, w)
		}
		if w.Subject == "entity" {
			if g.Entity != w.ID || g.EntityKind != ms.Entities[w.ID].Kind {
				t.Fatalf("change %d: entity %s/%s, model %s/%s", i, g.Entity, g.EntityKind, w.ID, ms.Entities[w.ID].Kind)
			}
		} else if g.From != w.Rel.From || g.To != w.Rel.To || g.RelationType != w.Rel.Type {
			t.Fatalf("change %d: relation %+v, model %+v", i, g, w.Rel)
		}
	}
}

func touches(c model.Change, id string) bool {
	if c.Subject == "entity" {
		return c.ID == id
	}
	return c.Rel.From == id || c.Rel.To == id
}

// Feature: bellu-graph-native, Property 14: History and Changes filters
// Validates: Requirements 6.6, 6.7
func TestPropHistoryChangesFilters(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		f := buildPropFixture(t, true)
		ms := f.m.Current()
		all := model.Changes(f.events)
		r := TimeRange{From: drawBound(t, "from"), To: drawBound(t, "to")}
		ctx := context.Background()
		size := pageSize(t)

		// Changes with kind, subject, entity kind and entity filters.
		flt := ChangeFilter{
			Kind:       rapid.SampledFrom([]ChangeKind{"", ChangeAdded, ChangeChanged, ChangeRemoved}).Draw(t, "kind"),
			Subject:    rapid.SampledFrom([]ChangeSubject{"", SubjectEntity, SubjectRelation}).Draw(t, "subject"),
			EntityKind: rapid.SampledFrom(append([]string{""}, gen.DefaultUniverse().Kinds...)).Draw(t, "entityKind"),
			Entity:     rapid.SampledFrom(append([]string{""}, gen.DefaultUniverse().IDs()...)).Draw(t, "entity"),
		}
		order := rapid.SampledFrom([]Order{OrderAsc, OrderDesc}).Draw(t, "order")
		var want []model.Change
		for _, c := range all {
			if !inRange(c.Valid, r) || (flt.Kind != "" && c.Kind != string(flt.Kind)) || (flt.Subject != "" && c.Subject != string(flt.Subject)) {
				continue
			}
			// Relation changes have no entity kind, so a kind filter never matches them.
			if flt.EntityKind != "" && (c.Subject != "entity" || ms.Entities[c.ID].Kind != flt.EntityKind) {
				continue
			}
			if flt.Entity != "" && !touches(c, flt.Entity) {
				continue
			}
			want = append(want, c)
		}
		sortChanges(want, order == OrderDesc)
		got, total := walkPages(t, size, func(cursor string) (Page[ChangeView], error) {
			ff := flt
			ff.Paging = Paging{PageSize: size, Cursor: cursor}
			return f.c.Changes(ctx, r, ff, order)
		})
		if total != len(want) {
			t.Fatalf("Changes Total %d, model %d", total, len(want))
		}
		checkChanges(t, ms, got, want)

		// History of an entity that exists (live or removed).
		var known []string
		for id := range ms.Entities {
			known = append(known, id)
		}
		if len(known) == 0 {
			return
		}
		sort.Strings(known)
		id := rapid.SampledFrom(known).Draw(t, "historyID")
		want = nil
		for _, c := range all {
			if inRange(c.Valid, r) && touches(c, id) {
				want = append(want, c)
			}
		}
		sortChanges(want, false)
		got, total = walkPages(t, size, func(cursor string) (Page[ChangeView], error) {
			return f.c.History(ctx, id, r, Paging{PageSize: size, Cursor: cursor})
		})
		if total != len(want) {
			t.Fatalf("History Total %d, model %d", total, len(want))
		}
		checkChanges(t, ms, got, want)
	})
}
