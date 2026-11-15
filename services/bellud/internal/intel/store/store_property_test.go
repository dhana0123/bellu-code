package store

import (
	"context"
	"sort"
	"testing"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/intel/model"
)

// Feature: unified-security-graph, Property 7: Import then lookup round trips by id and purl
//
// **Validates: Requirements 4.3**
func TestProperty7ImportRoundTripsByIDAndPurl(t *testing.T) {
	s, err := Open(t.TempDir() + "/intel")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	allPurls := []string{
		"pkg:npm/lodash", "pkg:npm/lodash-es", "pkg:pypi/requests",
		"pkg:golang/github.com/a/b", "pkg:maven/org.x/y", "pkg:cargo/serde",
	}
	purlGen := rapid.SampledFrom(allPurls)

	rapid.Check(t, func(rt *rapid.T) {
		ids := rapid.SliceOfNDistinct(rapid.StringMatching(`[A-Z]{3,5}-[0-9]{1,6}`), 0, 25, rapid.ID[string]).Draw(rt, "ids")
		vulns := make([]model.Vuln, len(ids))
		want := map[string][]string{} // purl -> sorted ids
		for i, id := range ids {
			purls := rapid.SliceOf(purlGen).Draw(rt, "purls")
			v := model.Vuln{ID: id}
			seen := map[string]bool{}
			for _, p := range purls {
				v.Affected = append(v.Affected, model.AffectedPackage{Purl: p})
				if !seen[p] {
					seen[p] = true
					want[p] = append(want[p], id)
				}
			}
			vulns[i] = v
		}
		for _, ids := range want {
			sort.Strings(ids)
		}

		if err := s.Replace(context.Background(), ImportInfo{Version: "p"}, jsonl(t, vulns...)); err != nil {
			rt.Fatalf("Replace: %v", err)
		}

		for _, v := range vulns {
			got, ok, err := s.Get(v.ID)
			if err != nil || !ok || got.ID != v.ID {
				rt.Fatalf("Get(%q) = %v, %v, %v", v.ID, got, ok, err)
			}
		}

		for _, p := range allPurls {
			got, err := s.ByPurl(p)
			if err != nil {
				rt.Fatalf("ByPurl(%q): %v", p, err)
			}
			gotIDs := make([]string, len(got))
			for i, g := range got {
				gotIDs[i] = g.ID
			}
			if len(gotIDs) != len(want[p]) {
				rt.Fatalf("ByPurl(%q) ids = %v, want %v", p, gotIDs, want[p])
			}
			for i := range gotIDs {
				if gotIDs[i] != want[p][i] {
					rt.Fatalf("ByPurl(%q) ids = %v, want %v", p, gotIDs, want[p])
				}
			}
		}
	})
}
