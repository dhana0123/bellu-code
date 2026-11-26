package lens

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/facade"
)

// DefaultReachHops is the default hop limit of a reachability query (12.5).
const DefaultReachHops = 10

// ErrReachEntity is wrapped when a reachability endpoint does not exist (12.9).
var ErrReachEntity = errors.New("reachability entity not found")

// ReachOpts configures Reach.
type ReachOpts struct {
	// MaxHops is the hop limit; zero or negative means DefaultReachHops.
	MaxHops int
	// IncludeInferred lets the path use inferred relations.
	IncludeInferred bool
}

// ReachHop is one relation of a reachability path with its evidence.
type ReachHop struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Relation string `json:"relation"`
	Evidence string `json:"evidence,omitempty"`
	Inferred bool   `json:"inferred,omitempty"`
}

// ReachResult is the answer to "can Source reach Target".
type ReachResult struct {
	Source      string     `json:"source"`
	Target      string     `json:"target"`
	Unreachable bool       `json:"unreachable"`
	Inferred    bool       `json:"inferred,omitempty"`
	Path        []ReachHop `json:"path"`
}

// Reach returns the shortest path of confirmed (extracted) relations from
// source to target within the hop limit. Inferred relations are used only when
// opts.IncludeInferred is set, and the path is then flagged inferred when it
// uses one. With no path the result is Unreachable with an empty Path. A
// missing source or target is rejected with ErrReachEntity naming the entity.
func Reach(ctx context.Context, src Source, source, target string, opts ReachOpts) (ReachResult, error) {
	if opts.MaxHops <= 0 {
		opts.MaxHops = DefaultReachHops
	}
	res := ReachResult{Source: source, Target: target, Path: []ReachHop{}}
	for _, id := range []string{source, target} {
		if _, err := src.Entity(ctx, facade.EntityID(id)); err != nil {
			if errors.Is(err, facade.ErrNotFound) {
				return res, fmt.Errorf("%w: %s", ErrReachEntity, id)
			}
			return res, err
		}
	}
	if source == target {
		return res, nil
	}
	prev := map[string]ReachHop{}
	seen := map[string]bool{source: true}
	frontier := []string{source}
	for hops := 1; hops <= opts.MaxHops && len(frontier) > 0; hops++ {
		var next []string
		for _, id := range frontier {
			edges, err := reachEdges(ctx, src, id, opts.IncludeInferred)
			if err != nil {
				return res, err
			}
			for _, e := range edges {
				if seen[e.To] {
					continue
				}
				seen[e.To] = true
				prev[e.To] = e
				if e.To == target {
					for at := target; at != source; at = prev[at].From {
						res.Path = append([]ReachHop{prev[at]}, res.Path...)
					}
					for _, h := range res.Path {
						res.Inferred = res.Inferred || h.Inferred
					}
					return res, nil
				}
				next = append(next, e.To)
			}
		}
		frontier = next
	}
	res.Unreachable = true
	return res, nil
}

// reachEdges lists the usable outgoing relations of id in (to, relation) order.
func reachEdges(ctx context.Context, src Source, id string, inferred bool) ([]ReachHop, error) {
	var out []ReachHop
	var cursor string
	for {
		pg, err := src.Neighbors(ctx, facade.EntityID(id), facade.NeighborOpts{
			Direction: facade.DirOut, Depth: 1,
			Paging: facade.Paging{PageSize: facade.MaxPageSize, Cursor: cursor},
		})
		if err != nil {
			return nil, err
		}
		for _, e := range pg.Items {
			if e.Derived || string(e.From) != id {
				continue
			}
			inf := e.Confidence == ConfInferred
			if e.Confidence != ConfExtracted && !(inf && inferred) {
				continue
			}
			out = append(out, ReachHop{From: id, To: string(e.To), Relation: e.Type, Evidence: e.Evidence, Inferred: inf})
		}
		if !pg.Truncated || pg.NextCursor == "" {
			break
		}
		cursor = pg.NextCursor
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].To != out[j].To {
			return out[i].To < out[j].To
		}
		if out[i].Inferred != out[j].Inferred {
			return !out[i].Inferred
		}
		return out[i].Relation < out[j].Relation
	})
	return out, nil
}
