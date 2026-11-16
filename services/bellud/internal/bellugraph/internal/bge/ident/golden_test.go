package ident

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func loadGolden(t *testing.T) golden {
	t.Helper()
	b, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	var g golden
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	return g
}

// Every golden kind must hash to the pinned Entity_ID.
func TestGoldenHashes(t *testing.T) {
	for kind, want := range loadGolden(t).Kinds {
		got, err := Hash(kind, want.Attrs)
		if err != nil {
			t.Errorf("%s: %v", kind, err)
			continue
		}
		if got != want.Hash {
			t.Errorf("%s: hash %s, golden %s", kind, got, want.Hash)
		}
	}
}

// The registered kinds and their ordered identity lists must equal the golden set.
func TestGoldenIdentityLists(t *testing.T) {
	g := loadGolden(t)
	kinds := Kinds()
	if len(kinds) != len(g.Kinds) {
		t.Errorf("registry has %d kinds, golden has %d", len(kinds), len(g.Kinds))
	}
	for _, k := range kinds {
		want, ok := g.Kinds[k]
		if !ok {
			t.Errorf("kind %s is not in golden", k)
			continue
		}
		got, _ := IdentityAttributes(k)
		if !reflect.DeepEqual(got, want.Identity) {
			t.Errorf("%s: identity %v, golden %v", k, got, want.Identity)
		}
	}
}

// The registered relation types and their directions must equal the golden set.
func TestGoldenRelationDirections(t *testing.T) {
	g := loadGolden(t)
	types := RelationTypes()
	if len(types) != len(g.Relations) {
		t.Errorf("registry has %d relation types, golden has %d", len(types), len(g.Relations))
	}
	for _, r := range types {
		want, ok := g.Relations[r]
		if !ok {
			t.Errorf("relation %s is not in golden", r)
			continue
		}
		if d, isDefault := DirectionOf(r); isDefault || d.String() != want {
			t.Errorf("%s: direction %s (default=%v), golden %s", r, d, isDefault, want)
		}
	}
}
