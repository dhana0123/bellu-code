package lens

import (
	"context"
	"sort"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/facade"
)

// NetGraph is the read view NetworkReach walks.
type NetGraph interface {
	Out(id, relType string) []string
	In(id, relType string) []string
	Attr(id, name string) string
}

// Reached is one entity reached through the network chain.
type Reached struct {
	ID   string
	Hops int
	// Via lists the relation types walked from the start.
	Via []string
}

// netStage says which relations may be walked from a node.
type netStage uint8

const (
	stageCompute netStage = iota // a workload: walk to its ENIs
	stageENI                     // an ENI: walk to its groups, subnet, and owner
	stageOwnSG                   // a group the walk is a member of: walk to rules naming it as peer
	stageRule                    // an ingress rule: walk to the group it belongs to
	stagePeerSG                  // a group that allows ingress from the walk: walk to its members
	stageSubnet                  // a subnet: walk to its route table and ACL
	stageContext                 // route table or ACL: terminal
)

type netHop struct {
	rel   string
	in    bool
	next  netStage
	check func(g NetGraph, id string) bool
}

func ingress(g NetGraph, id string) bool { return g.Attr(id, "direction") == "ingress" }

var netHops = map[netStage][]netHop{
	stageCompute: {{rel: "aws_has_eni", next: stageENI}},
	stageENI: {
		{rel: "aws_member_of_sg", next: stageOwnSG},
		{rel: "aws_in_subnet", next: stageSubnet},
		{rel: "aws_has_eni", in: true, next: stageCompute},
	},
	stageOwnSG:  {{rel: "aws_rule_peer", in: true, next: stageRule, check: ingress}},
	stageRule:   {{rel: "aws_rule_of", next: stagePeerSG}},
	stagePeerSG: {{rel: "aws_member_of_sg", in: true, next: stageENI}},
	stageSubnet: {{rel: "aws_associated_subnet", in: true, next: stageContext}},
}

// NetworkReach walks the network chain from a compute entity: its ENIs, their
// security groups, the groups that allow ingress from those groups through a
// rule node, the members of those groups and their owners, and the subnet
// context. The walk is breadth first, bounded by maxDepth hops, and returns
// every reached entity except start in (hops, id) order.
func NetworkReach(g NetGraph, start string, maxDepth int) []Reached {
	type item struct {
		id    string
		stage netStage
		via   []string
	}
	type key struct {
		id    string
		stage netStage
	}
	seen := map[key]bool{{start, stageCompute}: true}
	best := map[string]Reached{}
	frontier := []item{{id: start, stage: stageCompute}}
	for hops := 1; hops <= maxDepth && len(frontier) > 0; hops++ {
		var next []item
		for _, it := range frontier {
			for _, h := range netHops[it.stage] {
				ids := g.Out(it.id, h.rel)
				if h.in {
					ids = g.In(it.id, h.rel)
				}
				sort.Strings(ids)
				for _, id := range ids {
					k := key{id, h.next}
					if seen[k] || (h.check != nil && !h.check(g, id)) {
						continue
					}
					seen[k] = true
					via := append(append([]string(nil), it.via...), h.rel)
					if _, ok := best[id]; !ok && id != start {
						best[id] = Reached{ID: id, Hops: hops, Via: via}
					}
					next = append(next, item{id: id, stage: h.next, via: via})
				}
			}
		}
		frontier = next
	}
	out := make([]Reached, 0, len(best))
	for _, r := range best {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Hops != out[j].Hops {
			return out[i].Hops < out[j].Hops
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// sourceNet is a NetGraph over a Source. It records every edge it reads and
// keeps the first error; after an error it answers nothing.
type sourceNet struct {
	ctx   context.Context
	src   Source
	attrs map[string]map[string]any
	edges []facade.Edge
	err   error
}

func (s *sourceNet) walk(id, rel, dir string) []string {
	if s.err != nil {
		return nil
	}
	var out []string
	var cursor string
	for {
		pg, err := s.src.Neighbors(s.ctx, facade.EntityID(id), facade.NeighborOpts{
			Direction: dir, RelationType: rel, Depth: 1,
			Paging: facade.Paging{PageSize: facade.MaxPageSize, Cursor: cursor},
		})
		if err != nil {
			s.err = err
			return nil
		}
		for _, e := range pg.Items {
			if e.Derived || e.Type != rel {
				continue
			}
			s.edges = append(s.edges, e)
			other := e.To
			if dir == facade.DirIn {
				other = e.From
			}
			out = append(out, string(other))
		}
		if !pg.Truncated || pg.NextCursor == "" {
			return out
		}
		cursor = pg.NextCursor
	}
}

func (s *sourceNet) Out(id, rel string) []string { return s.walk(id, rel, facade.DirOut) }
func (s *sourceNet) In(id, rel string) []string  { return s.walk(id, rel, facade.DirIn) }

func (s *sourceNet) Attr(id, name string) string {
	a, ok := s.attrs[id]
	if !ok && s.err == nil {
		en, err := s.src.Entity(s.ctx, facade.EntityID(id))
		if err != nil {
			s.err = err
			return ""
		}
		a = en.Attributes
		s.attrs[id] = a
	}
	v, _ := a[name].(string)
	return v
}
