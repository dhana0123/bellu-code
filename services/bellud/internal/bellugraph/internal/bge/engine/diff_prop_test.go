package engine

import (
	"context"
	"reflect"
	"sort"
	"testing"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/internal/gen/model"
)

// Feature: bellu-graph-native, Property 11: Diff and flapping match the model
// Validates: Requirements 4.5, 8.3
func TestPropDiffMatchesModel(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		f := buildSnapFixture(t)
		for i := 0; i < 3; i++ {
			from := drawInstant(t, f.events, "from")
			to := drawInstant(t, f.events, "to")
			if to.Before(from) {
				from, to = to, from
			}
			want := f.m.Diff(from, to)
			got, err := f.c.Diff(context.Background(), from, to)
			if err != nil {
				t.Fatalf("Diff(%v, %v): %v", from, to, err)
			}
			ids := func(vs []EntityView) []string {
				out := []string{}
				for _, v := range vs {
					out = append(out, v.ID)
				}
				sort.Strings(out)
				return out
			}
			norm := func(s []string) []string {
				if s == nil {
					return []string{}
				}
				return s
			}
			if g := ids(got.Added); !reflect.DeepEqual(g, norm(want.Added)) {
				t.Fatalf("Diff(%v, %v) added %v, model %v", from, to, g, want.Added)
			}
			if g := ids(got.Changed); !reflect.DeepEqual(g, norm(want.Changed)) {
				t.Fatalf("Diff(%v, %v) changed %v, model %v", from, to, g, want.Changed)
			}
			if g := append([]string{}, got.Removed...); !reflect.DeepEqual(g, norm(want.Removed)) && len(g)+len(want.Removed) > 0 {
				sort.Strings(g)
				if !reflect.DeepEqual(g, norm(want.Removed)) {
					t.Fatalf("Diff(%v, %v) removed %v, model %v", from, to, g, want.Removed)
				}
			}
			var gf []model.Flap
			for _, fl := range got.Flapping {
				gf = append(gf, model.Flap{ID: fl.ID, Count: fl.Changes})
			}
			if !reflect.DeepEqual(gf, want.Flapping) && len(gf)+len(want.Flapping) > 0 {
				t.Fatalf("Diff(%v, %v) flapping %v, model %v", from, to, gf, want.Flapping)
			}
		}
	})
}
