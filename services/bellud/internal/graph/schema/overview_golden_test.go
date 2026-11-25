package schema_test

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schemaall"
)

// The in-package roadmap test already registers -update; registering it again
// in this external test package would panic, so share the existing flag.
func updateGolden() bool {
	f := flag.Lookup("update")
	return f != nil && f.Value.String() == "true"
}

// Feature: bellu-wiz-security-platform, Property 9: Category assignment is total
//
// **Validates: Requirements 1.8, 23.4**
func TestEveryKindHasOneCategory(t *testing.T) {
	r, err := schemaall.Default()
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Kinds()) == 0 {
		t.Fatal("default registry has no kinds")
	}
	for _, k := range r.Kinds() {
		if got := r.OverviewOf(k.Name, ""); !slices.Contains(schema.OverviewOrder[:], got) {
			t.Errorf("kind %q resolves to %q, not one of the nine categories", k.Name, got)
		}
		for _, ty := range k.Types {
			if got := r.OverviewOf(k.Name, ty.Name); !slices.Contains(schema.OverviewOrder[:], got) {
				t.Errorf("(%q, %q) resolves to %q, not one of the nine categories", k.Name, ty.Name, got)
			}
		}
	}
}

// **Validates: Requirements 1.8, 23.4**
func TestOverviewMappingGolden(t *testing.T) {
	r, err := schemaall.Default()
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, k := range r.Kinds() {
		lines = append(lines, fmt.Sprintf("kind\t%s\t%s", k.Name, r.OverviewOf(k.Name, "")))
		for _, ty := range k.Types {
			if ty.Overview != "" {
				lines = append(lines, fmt.Sprintf("type\t%s/%s\t%s", k.Name, ty.Name, r.OverviewOf(k.Name, ty.Name)))
			}
		}
	}
	// Registry has no finding-type lookup, so read the source declarations.
	ft := map[string]schema.OverviewCategory{}
	for _, d := range schemaall.Sources() {
		for _, f := range d.FindingTypes {
			ft[f.Type] = f.Overview
		}
	}
	for _, name := range slices.Sorted(func(yield func(string) bool) {
		for n := range ft {
			if !yield(n) {
				return
			}
		}
	}) {
		lines = append(lines, fmt.Sprintf("finding_type\t%s\t%s", name, ft[name]))
	}
	slices.Sort(lines)
	got := "# kind|type|finding_type <TAB> name <TAB> overview category. Regenerate: go test ./internal/graph/schema -run TestOverviewMappingGolden -update\n" +
		strings.Join(lines, "\n") + "\n"

	path := filepath.Join("testdata", "overview_mapping.golden")
	if updateGolden() {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update to create): %v", err)
	}
	if string(want) != got {
		t.Fatalf("overview mapping changed; review and run with -update.\n--- want\n%s\n--- got\n%s", want, got)
	}
}
