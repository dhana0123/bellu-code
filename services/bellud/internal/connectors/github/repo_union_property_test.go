package github

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// Feature: github-app-signin, Property 31: Repository listing is the union across installations
//
// For any set of installations with overlapping repositories, the listing
// returns each full_name exactly once, equal to the union, and Installations
// equals the number of installations.
//
// **Validates: Requirements 5.4**
func TestProperty31RepositoryListingIsUnionAcrossInstallations(t *testing.T) {
	// A small name pool makes overlap between installations likely.
	name := rapid.SampledFrom([]string{"o/a", "o/b", "o/c", "p/a", "p/b", "q/z", "q/y", "r/x"})
	rapid.Check(t, func(t *rapid.T) {
		perInstall := rapid.SliceOfN(rapid.SliceOfN(name, 0, 20), 0, 8).Draw(t, "installations")
		union := map[string]bool{}
		for _, repos := range perInstall {
			for _, n := range repos {
				union[n] = true
			}
		}
		rt := &countingRT{routes: func(r *http.Request) (int, string, http.Header) {
			if r.URL.Path == "/user/installations" {
				items := make([]string, len(perInstall))
				for i := range perInstall {
					items[i] = `{"id":` + strconv.Itoa(i+1) + `}`
				}
				return 200, `{"installations":[` + strings.Join(items, ",") + `]}`, nil
			}
			for i, repos := range perInstall {
				if r.URL.Path == "/user/installations/"+strconv.Itoa(i+1)+"/repositories" {
					return 200, repoJSON(repos...), nil
				}
			}
			return 404, `{}`, nil
		}}
		l, err := NewProvider(ProviderConfig{}).RepoList(context.Background(), deviceCall(rt))
		if err != nil {
			t.Fatalf("RepoList: %v", err)
		}
		if l.Installations != len(perInstall) {
			t.Fatalf("Installations = %d, want %d", l.Installations, len(perInstall))
		}
		got := make([]string, 0, len(l.Repos))
		seen := map[string]bool{}
		for _, r := range l.Repos {
			if seen[r.FullName] {
				t.Fatalf("duplicate full_name %q in %v", r.FullName, l.Repos)
			}
			seen[r.FullName] = true
			got = append(got, r.FullName)
		}
		want := make([]string, 0, len(union))
		for n := range union {
			want = append(want, n)
		}
		sort.Strings(got)
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("listing = %v, want union %v", got, want)
		}
	})
}
