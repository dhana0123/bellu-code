package engine

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/uri"
)

// Feature: bellu-graph-native, Property 24: Entity references are interchangeable
// Validates: Requirements 11.5
func TestPropEntityReferencesInterchangeable(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		f := buildPropFixture(t, true)
		live := f.m.Current().LiveIDs()
		if len(live) == 0 {
			return
		}
		ctx := context.Background()
		id := rapid.SampledFrom(live).Draw(t, "entity")
		kind, hex, ok := strings.Cut(id, ":")
		if !ok {
			t.Fatalf("entity id %q has no kind", id)
		}
		u, err := uri.Format(uri.Entity{Kind: kind, Hex: hex})
		if err != nil {
			t.Fatal(err)
		}
		refs := []string{id, u, f.c.LocalID(id)}
		opts := NeighborOpts{Paging: Paging{PageSize: 1000}}
		var wantEnt EntityView
		var wantNb Page[EdgeView]
		for i, ref := range refs {
			got, err := f.c.Resolve(ref)
			if err != nil {
				t.Fatalf("Resolve(%q): %v", ref, err)
			}
			if got != id {
				t.Fatalf("Resolve(%q) = %q, want %q", ref, got, id)
			}
			ev, err := f.c.Entity(ctx, got, nil)
			if err != nil {
				t.Fatal(err)
			}
			nb, err := f.c.Neighbors(ctx, got, opts, nil)
			if err != nil {
				t.Fatal(err)
			}
			if i == 0 {
				wantEnt, wantNb = ev, nb
				continue
			}
			if !reflect.DeepEqual(ev, wantEnt) || !reflect.DeepEqual(nb, wantNb) {
				t.Fatalf("reads via %q differ from reads via %q", ref, refs[0])
			}
		}
	})
}
