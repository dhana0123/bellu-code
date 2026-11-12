package query

import (
	"sort"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/graph"
)

// DiffCap bounds each of the added, changed, removed and flapping lists.
const DiffCap = 1000

// StateSet is the read-only view of one as-of state used by DiffStates.
// *graph.Graph implements it.
type StateSet interface {
	Entity(id graph.EntityID) (*graph.EntityState, bool)
	Annotation(id graph.EntityID) (graph.Annotation, bool)
	LiveIDs() []graph.EntityID
}

// Flap is an entity with its number of Change_Events in a window.
type Flap struct {
	ID      graph.EntityID
	Changes int
}

// DiffResult is the comparison of two states. Added, Changed and Removed are
// sorted by ID; Flapping by changes descending, then ID. Each list is capped
// at DiffCap and Truncated is set when any cap was hit.
type DiffResult struct {
	Added, Changed, Removed []graph.EntityID
	Flapping                []Flap
	Truncated               bool
}

// SameState reports whether the entity has the same state in a and b: both
// not live, or both live with equal attributes and annotations.
func SameState(a, b StateSet, id graph.EntityID) bool {
	ea, oka := live(a, id)
	eb, okb := live(b, id)
	if !oka || !okb {
		return oka == okb
	}
	if len(ea.Attrs) != len(eb.Attrs) {
		return false
	}
	for k, v := range ea.Attrs {
		if w, ok := eb.Attrs[k]; !ok || !v.Equal(w) {
			return false
		}
	}
	aa, _ := a.Annotation(id)
	ab, _ := b.Annotation(id)
	if len(aa.Values) != len(ab.Values) {
		return false
	}
	for k, v := range aa.Values {
		if w, ok := ab.Values[k]; !ok || v != w {
			return false
		}
	}
	return true
}

func live(s StateSet, id graph.EntityID) (*graph.EntityState, bool) {
	e, ok := s.Entity(id)
	return e, ok && e.Live
}

// DiffStates compares two states. counts holds the number of entity
// Change_Events per entity inside the window (from, to]. An entity is added
// when live only in to, removed when live only in from, changed when live in
// both with different state, and flapping when it has at least two changes
// and the same state in both (absent in both counts as the same).
func DiffStates(from, to StateSet, counts map[graph.EntityID]int) DiffResult {
	var r DiffResult
	for _, id := range to.LiveIDs() {
		if _, ok := live(from, id); !ok {
			r.Added = append(r.Added, id)
		} else if !SameState(from, to, id) {
			r.Changed = append(r.Changed, id)
		}
	}
	for _, id := range from.LiveIDs() {
		if _, ok := live(to, id); !ok {
			r.Removed = append(r.Removed, id)
		}
	}
	for id, n := range counts {
		if n >= 2 && SameState(from, to, id) {
			r.Flapping = append(r.Flapping, Flap{id, n})
		}
	}
	sort.Strings(r.Added)
	sort.Strings(r.Changed)
	sort.Strings(r.Removed)
	sort.Slice(r.Flapping, func(i, j int) bool {
		a, b := r.Flapping[i], r.Flapping[j]
		if a.Changes != b.Changes {
			return a.Changes > b.Changes
		}
		return a.ID < b.ID
	})
	r.Added, r.Truncated = capList(r.Added, r.Truncated)
	r.Changed, r.Truncated = capList(r.Changed, r.Truncated)
	r.Removed, r.Truncated = capList(r.Removed, r.Truncated)
	r.Flapping, r.Truncated = capList(r.Flapping, r.Truncated)
	return r
}

func capList[T any](l []T, trunc bool) ([]T, bool) {
	if len(l) > DiffCap {
		return l[:DiffCap], true
	}
	return l, trunc
}
