package ident

import (
	"encoding/json"
	"flag"
	"os"
	"testing"
)

// update regenerates testdata/golden.json from the current registry. It must
// only be run against the pre-feature baseline; golden_test.go then pins it.
var update = flag.Bool("update", false, "regenerate testdata/golden.json")

const goldenPath = "testdata/golden.json"

type goldenKind struct {
	Identity []string          `json:"identity"`
	Attrs    map[string]string `json:"attrs"`
	Hash     string            `json:"hash"`
}

type golden struct {
	Kinds     map[string]goldenKind `json:"kinds"`
	Relations map[string]string     `json:"relations"`
}

// goldenAttrs builds a deterministic attribute map for a kind.
func goldenAttrs(identity []string) map[string]string {
	m := make(map[string]string, len(identity))
	for _, a := range identity {
		m[a] = "golden-" + a
	}
	return m
}

func TestGenerateGolden(t *testing.T) {
	if !*update {
		t.Skip("run with -update to regenerate " + goldenPath)
	}
	g := golden{Kinds: map[string]goldenKind{}, Relations: map[string]string{}}
	for _, k := range Kinds() {
		id, _ := IdentityAttributes(k)
		attrs := goldenAttrs(id)
		h, err := Hash(k, attrs)
		if err != nil {
			t.Fatalf("hash %s: %v", k, err)
		}
		g.Kinds[k] = goldenKind{Identity: id, Attrs: attrs, Hash: h}
	}
	for _, r := range RelationTypes() {
		d, _ := DirectionOf(r)
		g.Relations[r] = d.String()
	}
	b, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(goldenPath, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
