package cveupdate

import (
	"errors"
	"fmt"
	"sort"
)

// Chain limit bounds (Requirement 19.9).
const (
	DefaultMaxChain = 30
	MinMaxChain     = 1
	MaxMaxChain     = 365
)

// ErrNoLatest is returned when the index names no latest snapshot.
var ErrNoLatest = errors.New("index has no latest snapshot")

// PlanReason says why a full snapshot was chosen.
type PlanReason string

const (
	ReasonNone           PlanReason = ""
	ReasonNothingInstall PlanReason = "nothing installed"
	ReasonMissingDelta   PlanReason = "delta missing from chain"
	ReasonChainTooLong   PlanReason = "delta chain exceeds limit"
	ReasonTooOld         PlanReason = "installed snapshot older than oldest retained delta"
)

// Plan is the set of packs to fetch. When UpToDate is true nothing is fetched.
// Otherwise it holds either Deltas (applied in order) or, when Full is true,
// the latest full Snapshot.
type Plan struct {
	UpToDate bool
	Full     bool
	Reason   PlanReason
	Snapshot Snapshot
	Deltas   []Delta
}

// ChainLimit returns limit, or the default when limit is 0. It rejects values
// outside 1 to 365.
func ChainLimit(limit int) (int, error) {
	if limit == 0 {
		return DefaultMaxChain, nil
	}
	if limit < MinMaxChain || limit > MaxMaxChain {
		return 0, fmt.Errorf("cve.max_delta_chain %d out of range %d to %d", limit, MinMaxChain, MaxMaxChain)
	}
	return limit, nil
}

// PlanUpdate decides how to move from installedID ("" when nothing is
// installed) to idx.Latest. It applies the shortest delta chain, and falls back
// to the latest full snapshot when nothing is installed, no chain exists, the
// chain is longer than maxChain (0 means the default of 30), or the installed
// snapshot is older than the oldest retained delta. The chain search matches
// the Global CVE internal/install findChain: breadth first, ties broken by
// target id. That package is internal to another module, so it is mirrored here.
func PlanUpdate(idx *Index, installedID string, maxChain int) (Plan, error) {
	limit, err := ChainLimit(maxChain)
	if err != nil {
		return Plan{}, err
	}
	latest := idx.Latest
	if latest.ID == "" {
		return Plan{}, ErrNoLatest
	}
	full := func(r PlanReason) Plan { return Plan{Full: true, Reason: r, Snapshot: latest} }

	if installedID == "" {
		return full(ReasonNothingInstall), nil
	}
	if installedID == latest.ID {
		return Plan{UpToDate: true}, nil
	}
	if installedOlderThanDeltas(idx, installedID) {
		return full(ReasonTooOld), nil
	}
	chain, ok := findChain(idx.Deltas, installedID, latest.ID)
	if !ok {
		return full(ReasonMissingDelta), nil
	}
	if len(chain) > limit {
		return full(ReasonChainTooLong), nil
	}
	return Plan{Deltas: chain}, nil
}

// installedOlderThanDeltas reports whether the installed snapshot was built
// before every retained delta's base. Unknown build times never trigger it.
func installedOlderThanDeltas(idx *Index, installedID string) bool {
	created := map[string]Snapshot{}
	for _, s := range idx.Snapshots {
		created[s.ID] = s
	}
	created[idx.Latest.ID] = idx.Latest
	inst, ok := created[installedID]
	if !ok || inst.CreatedAt.IsZero() {
		return false
	}
	found := false
	for _, d := range idx.Deltas {
		if d.Base == installedID {
			return false
		}
		b, ok := created[d.Base]
		if !ok || b.CreatedAt.IsZero() {
			continue
		}
		if b.CreatedAt.After(inst.CreatedAt) {
			found = true
			continue
		}
		return false // some retained delta starts at or before the installed build
	}
	return found
}

// findChain returns the shortest delta path from installedID to target.
func findChain(deltas []Delta, installedID, target string) ([]Delta, bool) {
	next := map[string][]Delta{}
	for _, d := range deltas {
		next[d.Base] = append(next[d.Base], d)
	}
	for k := range next {
		sort.Slice(next[k], func(i, j int) bool { return next[k][i].Target < next[k][j].Target })
	}
	prev := map[string]Delta{}
	seen := map[string]bool{installedID: true}
	queue := []string{installedID}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, d := range next[cur] {
			if seen[d.Target] {
				continue
			}
			seen[d.Target] = true
			prev[d.Target] = d
			if d.Target == target {
				var out []Delta
				for id := target; id != installedID; id = prev[id].Base {
					out = append([]Delta{prev[id]}, out...)
				}
				return out, true
			}
			queue = append(queue, d.Target)
		}
	}
	return nil, false
}
