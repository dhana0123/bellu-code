package correlate

import (
	"fmt"
	"sort"
	"testing"

	"pgregory.net/rapid"
)

// Feature: unified-security-graph, Property 3: Relations are planned only
// across connections, by key.
//
// **Validates: Requirements 2.5, 2.6**

// sameKeyEntities draws entities with unique IDs, a few connections, a few
// canonical keys (or none), and names that make repo/resource name matches
// likely.
func sameKeyEntities() *rapid.Generator[[]KeyedEntity] {
	return rapid.Custom(func(t *rapid.T) []KeyedEntity {
		n := rapid.IntRange(0, 12).Draw(t, "n")
		kinds := rapid.SampledFrom([]string{kindRepo, kindResource, "other"})
		conns := rapid.SampledFrom([]string{"c1", "c2", "c3"})
		keys := rapid.SampledFrom([]string{"", "k1", "k2", "k3"})
		names := rapid.SampledFrom([]string{"", "api", "Web", "acme/API", "acme/web", "db"})
		ents := make([]KeyedEntity, n)
		for i := range ents {
			ents[i] = KeyedEntity{
				ID:         fmt.Sprintf("e%02d", i),
				Kind:       kinds.Draw(t, "kind"),
				Connection: conns.Draw(t, "conn"),
				Key:        keys.Draw(t, "key"),
				Name:       names.Draw(t, "name"),
			}
		}
		return ents
	})
}

// sameKeyExpected computes the same_as edges ("from>to") the spec requires:
// for each key whose members span two or more connections, every member
// except the smallest ID points at the smallest ID.
func sameKeyExpected(ents []KeyedEntity) []string {
	byKey := map[string][]KeyedEntity{}
	for _, e := range ents {
		if e.Key != "" {
			byKey[e.Key] = append(byKey[e.Key], e)
		}
	}
	var want []string
	for _, members := range byKey {
		conns := map[string]bool{}
		anchor := members[0].ID
		for _, m := range members {
			conns[m.Connection] = true
			if m.ID < anchor {
				anchor = m.ID
			}
		}
		if len(conns) < 2 {
			continue
		}
		anchorConn := ""
		for _, m := range members {
			if m.ID == anchor {
				anchorConn = m.Connection
			}
		}
		for _, m := range members {
			if m.ID != anchor && m.Connection != anchorConn {
				want = append(want, m.ID+">"+anchor)
			}
		}
	}
	sort.Strings(want)
	return want
}

func TestPlanSameAsAcrossConnectionsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		ents := sameKeyEntities().Draw(t, "ents")
		conn := map[string]string{}
		for _, e := range ents {
			conn[e.ID] = e.Connection
		}

		var got []string
		pairs := map[[2]string]map[string]bool{}
		for _, r := range PlanSameAs(ents) {
			if r.Type != RelSameAs && r.Type != RelLikelySameAs {
				t.Fatalf("unexpected relation type %q", r.Type)
			}
			if conn[r.From] == conn[r.To] {
				t.Fatalf("%s %s>%s joins entities of one connection %q", r.Type, r.From, r.To, conn[r.From])
			}
			p := [2]string{r.From, r.To}
			if r.From > r.To {
				p = [2]string{r.To, r.From}
			}
			if pairs[p] == nil {
				pairs[p] = map[string]bool{}
			}
			pairs[p][r.Type] = true
			if r.Type == RelSameAs {
				got = append(got, r.From+">"+r.To)
			}
		}

		for p, types := range pairs {
			if len(types) > 1 {
				t.Fatalf("pair %v has both same_as and likely_same_as", p)
			}
		}

		sort.Strings(got)
		want := sameKeyExpected(ents)
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("same_as = %v; want %v", got, want)
		}
	})
}
