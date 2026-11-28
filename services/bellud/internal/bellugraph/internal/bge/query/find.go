package query

import (
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/codec"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/graph"
)

// Page size bounds.
const (
	DefaultPageSize = 100
	MaxPageSize     = 1000
)

// Reader is the read-only part of the Projection used by the query package.
// *graph.Graph implements it.
type Reader interface {
	Entity(id graph.EntityID) (*graph.EntityState, bool)
	LiveIDs() []graph.EntityID
	LiveIDsOfKind(kind string) []graph.EntityID
	Relation(k graph.RelKey) (*graph.RelState, bool)
	RelationsFrom(id graph.EntityID) []graph.RelKey
	RelationsTo(id graph.EntityID) []graph.RelKey
}

// PageLimit returns the effective page size: 0 means DefaultPageSize; values
// below 0 or above MaxPageSize return an error wrapping errs.Validation.
func PageLimit(size int) (int, error) {
	if size == 0 {
		return DefaultPageSize, nil
	}
	if size < 0 || size > MaxPageSize {
		return 0, fmt.Errorf("%w: page size %d is outside 1 to %d", errs.Validation, size, MaxPageSize)
	}
	return size, nil
}

// QueryHash hashes the normalized query parts for binding a cursor to its query.
func QueryHash(parts ...string) uint64 {
	h := fnv.New64a()
	for _, p := range parts {
		h.Write([]byte(strconv.Itoa(len(p))))
		h.Write([]byte{':'})
		h.Write([]byte(p))
	}
	return h.Sum64()
}

// Find returns, sorted by Entity_ID, the live entities of kind (any kind when
// empty) whose identity and descriptive attributes contain every pair of
// attrs. The result is a read-only copy of the index slice only when no
// attribute filter applies.
func Find(g Reader, kind string, attrs map[string]string) []graph.EntityID {
	var src []graph.EntityID
	if kind == "" {
		src = g.LiveIDs()
	} else {
		src = g.LiveIDsOfKind(kind)
	}
	if len(attrs) == 0 {
		return append([]graph.EntityID(nil), src...)
	}
	out := make([]graph.EntityID, 0)
	for _, id := range src {
		if e, ok := g.Entity(id); ok && MatchAttrs(e, attrs) {
			out = append(out, id)
		}
	}
	return out
}

// MatchAttrs reports whether e carries every key=value pair, looking at
// identity attributes first and then descriptive ones. Values compare by
// their string form; a list attribute matches when any element equals the
// value.
func MatchAttrs(e *graph.EntityState, attrs map[string]string) bool {
	for k, want := range attrs {
		if v, ok := e.Identity[k]; ok {
			if v != want {
				return false
			}
			continue
		}
		v, ok := e.Attrs[k]
		if !ok || !valueMatches(v, want) {
			return false
		}
	}
	return true
}

func valueMatches(v codec.Value, want string) bool {
	switch v.T {
	case codec.TagString:
		return v.S == want
	case codec.TagBool:
		return strconv.FormatBool(v.B) == want
	case codec.TagInt:
		return strconv.FormatInt(v.I, 10) == want
	case codec.TagFloat:
		return strconv.FormatFloat(v.F, 'g', -1, 64) == want
	case codec.TagList:
		for _, s := range v.L {
			if s == want {
				return true
			}
		}
	}
	return false
}

// AfterString returns the index of the first element of the sorted list that
// is greater than key.
func AfterString(sorted []string, key string) int {
	lo, hi := 0, len(sorted)
	for lo < hi {
		m := (lo + hi) / 2
		if sorted[m] > key {
			hi = m
		} else {
			lo = m + 1
		}
	}
	return lo
}

// JoinKey is a helper for building normalized query descriptions.
func JoinKey(parts ...string) string { return strings.Join(parts, "\x00") }
