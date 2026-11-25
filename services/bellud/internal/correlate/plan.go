// Package correlate plans cross-source relations: package-to-vulnerability
// matches from the intel corpus and cross-connection identity links. The plan
// functions in this file are pure; they read only through Lookup.
package correlate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bellu/bellucode/services/bellud/internal/canonical"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
	"github.com/bellu/bellucode/services/bellud/internal/intel/model"
)

// CollectorName is the Batch.Collector value of a correlation plan.
const CollectorName = "correlator:intel"

// Relation and entity kinds written by the correlator.
const (
	KindVulnerability = "vulnerability"
	RelAffectedBy     = "affected_by"
	RelSameAs         = "same_as"
	RelLikelySameAs   = "likely_same_as"
)

// Kinds scanned by PlanSameAs.
const (
	kindRepo     = "github_repo"
	kindResource = "aws_resource"
)

// Lookup is the read-only intel access Plan needs. It has no list-all method,
// so the corpus is never loaded into memory.
type Lookup interface {
	// ByPurl returns the vulnerabilities that list name (a purl without
	// version, such as "pkg:npm/lodash") among their affected packages.
	ByPurl(name string) ([]model.Vuln, error)
}

// Pkg is a package entity as the plan sees it. ID is its Entity_ID and Purl
// is the versioned purl.
type Pkg struct {
	ID, Connection, Scope, Purl string
}

// KeyedEntity is an entity that may carry a canonical key. Name is the
// entity's descriptive name, used only by the repo-name heuristic.
type KeyedEntity struct {
	ID, Kind, Connection, Key, Name string
}

// Plan returns the vulnerabilities that match pkgs and the affected_by
// relations from each matching package to its vulnerabilities. Only matching
// packages produce output. The result is deterministic for a given input.
func Plan(pkgs []Pkg, l Lookup) (batch.Batch, error) {
	out := batch.Batch{Collector: CollectorName}
	sorted := append([]Pkg(nil), pkgs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	byName := map[string][]model.Vuln{}
	vulns := map[string]*vulnAcc{}
	type edge struct{ from, to string }
	seen := map[edge]bool{}

	for _, p := range sorted {
		if p.ID == "" || strings.TrimSpace(p.Purl) == "" {
			continue
		}
		name, version := model.SplitPurl(p.Purl)
		cands, ok := byName[name]
		if !ok {
			var err error
			if cands, err = l.ByPurl(name); err != nil {
				return batch.Batch{}, fmt.Errorf("correlate: lookup %q: %w", name, err)
			}
			byName[name] = cands
		}
		for _, v := range cands {
			id := strings.TrimSpace(v.ID)
			if id == "" {
				continue
			}
			matched, ap := model.MatchPackage(v.Affected, name, version)
			if !matched {
				continue
			}
			acc := vulns[id]
			if acc == nil {
				h, err := identity.Hash(KindVulnerability, map[string]string{"id": id})
				if err != nil {
					return batch.Batch{}, err
				}
				acc = &vulnAcc{v: v, id: id, entityID: string(h), fixed: map[string]bool{}}
				vulns[id] = acc
			}
			for _, f := range ap.FixedIn {
				if f = strings.TrimSpace(f); f != "" {
					acc.fixed[f] = true
				}
			}
			e := edge{p.ID, acc.entityID}
			if !seen[e] {
				seen[e] = true
				out.Relations = append(out.Relations, batch.Relation{Type: RelAffectedBy, From: p.ID, To: acc.entityID})
			}
		}
	}

	ids := make([]string, 0, len(vulns))
	for id := range vulns {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		out.Entities = append(out.Entities, vulns[id].entity())
	}
	return out, nil
}

type vulnAcc struct {
	v        model.Vuln
	id       string
	entityID string
	fixed    map[string]bool
}

func (a *vulnAcc) entity() batch.Entity {
	fixed := make([]string, 0, len(a.fixed))
	for f := range a.fixed {
		fixed = append(fixed, f)
	}
	return VulnEntity(a.v, fixed)
}

// VulnEntity returns the `vulnerability` entity for v with the identity and
// attributes Plan writes, so that another planner (for example the vulnmatch
// scanner) merges with the correlator's entity instead of duplicating it.
// fixed lists the fixed versions of the matched package entries. Blank and
// repeated values are dropped and the rest are sorted.
func VulnEntity(v model.Vuln, fixed []string) batch.Entity {
	id := strings.TrimSpace(v.ID)
	kev := "false"
	if v.KnownExploited {
		kev = "true"
	}
	uniq := map[string]bool{}
	for _, f := range fixed {
		if f = strings.TrimSpace(f); f != "" {
			uniq[f] = true
		}
	}
	fs := make([]string, 0, len(uniq))
	for f := range uniq {
		fs = append(fs, f)
	}
	sort.Strings(fs)
	attrs := map[string]any{
		"name":     id,
		"summary":  v.Summary,
		"cvss":     v.CVSS.Score,
		"epss":     v.EPSS,
		"kev":      kev,
		"severity": string(v.Severity),
		"fixed_in": strings.Join(fs, ","),
	}
	if k, ok := canonical.Key(canonical.KindVuln, id); ok {
		attrs[canonical.AttrCanonicalKey] = k
	}
	return batch.Entity{Type: KindVulnerability, Identity: map[string]string{"id": id}, Attributes: attrs}
}

// VulnEntityID returns the Entity_ID of the vulnerability with the given id.
func VulnEntityID(id string) (string, error) {
	h, err := identity.Hash(KindVulnerability, map[string]string{"id": strings.TrimSpace(id)})
	return string(h), err
}

// PlanSameAs returns the identity relations among ents.
//
// A group of entities sharing a canonical key and spanning at least two
// connections yields a same_as star: every member except the anchor (the
// smallest Entity_ID) points at the anchor. Separately, an aws_resource whose
// lowercase name equals a github_repo's repository name, from a different
// connection and without a shared key, yields likely_same_as from the
// resource to the repo. Relations carry no attributes.
func PlanSameAs(ents []KeyedEntity) []batch.Relation {
	var rels []batch.Relation

	groups := map[string]map[string]string{} // key -> entity ID -> connection
	for _, e := range ents {
		if e.ID == "" || e.Key == "" {
			continue
		}
		if groups[e.Key] == nil {
			groups[e.Key] = map[string]string{}
		}
		groups[e.Key][e.ID] = e.Connection
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		members := groups[k]
		conns := map[string]bool{}
		ids := make([]string, 0, len(members))
		for id, c := range members {
			conns[c] = true
			ids = append(ids, id)
		}
		if len(conns) < 2 {
			continue
		}
		sort.Strings(ids)
		// Never join two entities of one connection (Requirement 2.5).
		for _, id := range ids[1:] {
			if members[id] == members[ids[0]] {
				continue
			}
			rels = append(rels, batch.Relation{Type: RelSameAs, From: id, To: ids[0]})
		}
	}

	return append(rels, likelySameAs(ents)...)
}

func likelySameAs(ents []KeyedEntity) []batch.Relation {
	repos := map[string][]KeyedEntity{} // repo name -> repos
	for _, e := range ents {
		if e.ID == "" || e.Kind != kindRepo {
			continue
		}
		if n := repoName(e.Name); n != "" {
			repos[n] = append(repos[n], e)
		}
	}
	var rels []batch.Relation
	seen := map[[2]string]bool{}
	for _, r := range ents {
		if r.ID == "" || r.Kind != kindResource {
			continue
		}
		n := strings.ToLower(strings.TrimSpace(r.Name))
		for _, repo := range repos[n] {
			if repo.Connection == r.Connection {
				continue
			}
			if repo.Key != "" && repo.Key == r.Key {
				continue
			}
			p := [2]string{r.ID, repo.ID}
			if seen[p] {
				continue
			}
			seen[p] = true
			rels = append(rels, batch.Relation{Type: RelLikelySameAs, From: r.ID, To: repo.ID})
		}
	}
	sort.Slice(rels, func(i, j int) bool {
		if rels[i].From != rels[j].From {
			return rels[i].From < rels[j].From
		}
		return rels[i].To < rels[j].To
	})
	return rels
}

// repoName returns the lowercase repository name: the segment after the last
// slash of a full name such as "acme/Widget".
func repoName(full string) string {
	full = strings.TrimSpace(full)
	if i := strings.LastIndexByte(full, '/'); i >= 0 {
		full = full[i+1:]
	}
	return strings.ToLower(full)
}
