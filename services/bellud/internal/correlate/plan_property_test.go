package correlate

import (
	"fmt"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
	"github.com/bellu/bellucode/services/bellud/internal/intel/model"
	"pgregory.net/rapid"
)

// Feature: unified-security-graph, Property 10: The correlation plan contains
// exactly the matching vulnerabilities.
//
// **Validates: Requirements 5.3, 5.6**

var (
	planNames    = []string{"pkg:npm/a", "pkg:npm/b", "pkg:pypi/c", "pkg:golang/d"}
	planVersions = []string{"0.5.0", "1.0.0", "1.5.0", "2.0.0", "2.5.0", "3.0.0"}
)

// planCorpus is an in-memory Lookup that indexes vulnerabilities by affected purl.
type planCorpus []model.Vuln

func (c planCorpus) ByPurl(name string) ([]model.Vuln, error) {
	var out []model.Vuln
	for _, v := range c {
		for _, a := range v.Affected {
			if a.Purl == name {
				out = append(out, v)
				break
			}
		}
	}
	return out, nil
}

func planAffectedGen() *rapid.Generator[model.AffectedPackage] {
	rng := rapid.Custom(func(t *rapid.T) model.SemverRange {
		return model.SemverRange{
			Introduced: rapid.SampledFrom([]string{"", "0", "1.0.0", "2.0.0"}).Draw(t, "introduced"),
			Fixed:      rapid.SampledFrom([]string{"", "1.0.0", "2.0.0", "3.0.0"}).Draw(t, "fixed"),
		}
	})
	return rapid.Custom(func(t *rapid.T) model.AffectedPackage {
		return model.AffectedPackage{
			Purl:   rapid.SampledFrom(planNames).Draw(t, "purl"),
			Ranges: rapid.SliceOfN(rng, 0, 2).Draw(t, "ranges"),
		}
	})
}

func planCorpusGen() *rapid.Generator[planCorpus] {
	return rapid.Custom(func(t *rapid.T) planCorpus {
		n := rapid.IntRange(0, 5).Draw(t, "nvulns")
		out := make(planCorpus, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, model.Vuln{
				ID:             fmt.Sprintf("CVE-2024-%04d", i+1),
				Affected:       rapid.SliceOfN(planAffectedGen(), 0, 3).Draw(t, "affected"),
				CVSS:           model.CVSS{Score: float64(rapid.IntRange(0, 100).Draw(t, "cvss")) / 10},
				EPSS:           float64(rapid.IntRange(0, 100).Draw(t, "epss")) / 100,
				KnownExploited: rapid.Bool().Draw(t, "kev"),
			})
		}
		return out
	})
}

func planPkgsGen() *rapid.Generator[[]Pkg] {
	return rapid.Custom(func(t *rapid.T) []Pkg {
		n := rapid.IntRange(0, 6).Draw(t, "npkgs")
		out := make([]Pkg, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, Pkg{
				ID:         fmt.Sprintf("pkg-%d", i),
				Connection: "c1",
				Purl:       rapid.SampledFrom(planNames).Draw(t, "name") + "@" + rapid.SampledFrom(planVersions).Draw(t, "version"),
			})
		}
		return out
	})
}

func TestPlanContainsExactlyMatchingVulnsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		pkgs := planPkgsGen().Draw(t, "pkgs")
		corpus := planCorpusGen().Draw(t, "corpus")

		got, err := Plan(pkgs, corpus)
		if err != nil {
			t.Fatal(err)
		}

		// Independent oracle: every (package, vuln) pair that matches.
		wantEdges := map[[2]string]bool{}
		wantVulns := map[string]model.Vuln{}
		for _, p := range pkgs {
			name, version := model.SplitPurl(p.Purl)
			for _, v := range corpus {
				if ok, _ := model.MatchPackage(v.Affected, name, version); !ok {
					continue
				}
				h, err := identity.Hash(KindVulnerability, map[string]string{"id": v.ID})
				if err != nil {
					t.Fatal(err)
				}
				wantEdges[[2]string{p.ID, string(h)}] = true
				wantVulns[v.ID] = v
			}
		}

		gotEdges := map[[2]string]bool{}
		for _, r := range got.Relations {
			if r.Type != RelAffectedBy {
				t.Fatalf("unexpected relation type %q", r.Type)
			}
			e := [2]string{r.From, r.To}
			if gotEdges[e] {
				t.Fatalf("duplicate relation %v", e)
			}
			gotEdges[e] = true
		}
		if len(gotEdges) != len(wantEdges) {
			t.Fatalf("relations: got %d, want %d", len(gotEdges), len(wantEdges))
		}
		for e := range wantEdges {
			if !gotEdges[e] {
				t.Fatalf("missing relation %v", e)
			}
		}

		if len(got.Entities) != len(wantVulns) {
			t.Fatalf("entities: got %d, want %d", len(got.Entities), len(wantVulns))
		}
		seen := map[string]bool{}
		for _, e := range got.Entities {
			id := e.Identity["id"]
			v, ok := wantVulns[id]
			if !ok || seen[id] {
				t.Fatalf("unexpected or duplicate vulnerability %q", id)
			}
			seen[id] = true
			if e.Attributes["cvss"] != v.CVSS.Score || e.Attributes["epss"] != v.EPSS {
				t.Fatalf("%s: cvss/epss %v/%v, want %v/%v", id, e.Attributes["cvss"], e.Attributes["epss"], v.CVSS.Score, v.EPSS)
			}
			wantKEV := "false"
			if v.KnownExploited {
				wantKEV = "true"
			}
			if e.Attributes["kev"] != wantKEV {
				t.Fatalf("%s: kev %v, want %s", id, e.Attributes["kev"], wantKEV)
			}
		}
	})
}

func TestPlanEmptyInputsYieldNoVulnerability(t *testing.T) {
	corpus := planCorpus{{ID: "CVE-2024-0001", Affected: []model.AffectedPackage{{Purl: planNames[0]}}}}
	for name, tc := range map[string]struct {
		pkgs   []Pkg
		corpus planCorpus
	}{
		"no packages": {nil, corpus},
		"no corpus":   {[]Pkg{{ID: "p", Purl: planNames[0] + "@1.0.0"}}, nil},
	} {
		got, err := Plan(tc.pkgs, tc.corpus)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(got.Entities) != 0 || len(got.Relations) != 0 {
			t.Fatalf("%s: got %d entities, %d relations", name, len(got.Entities), len(got.Relations))
		}
	}
}
