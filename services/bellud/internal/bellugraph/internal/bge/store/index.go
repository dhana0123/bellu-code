package store

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/cockroachdb/pebble"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/codec"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
)

// IndexEntry is one secondary-index hit: the event's sequence, Valid_Time and
// type.
type IndexEntry struct {
	Seq     uint64
	ValidNS int64
	Type    codec.EventType
}

// EntityEntries returns the x/ent entries of entity id in ascending seq order.
func (v view) EntityEntries(id string) ([]IndexEntry, error) {
	return v.idEntries(prefixEnt, id)
}

// RelationEntries returns the x/rel entries of relations touching entity id
// (as from or to) in ascending seq order. A self-relation appears twice.
func (v view) RelationEntries(id string) ([]IndexEntry, error) {
	return v.idEntries(prefixRel, id)
}

func (v view) idEntries(prefix []byte, id string) ([]IndexEntry, error) {
	lo := append(append(append([]byte(nil), prefix...), id...), 0)
	it, err := v.r.NewIter(&pebble.IterOptions{LowerBound: lo, UpperBound: upperBound(lo)})
	if err != nil {
		return nil, err
	}
	defer it.Close()
	var out []IndexEntry
	for ok := it.First(); ok; ok = it.Next() {
		k, val := it.Key(), it.Value()
		if len(k) != len(lo)+8 || len(val) != 9 {
			return nil, fmt.Errorf("%w: malformed index entry %q", errs.Corrupt, k)
		}
		out = append(out, IndexEntry{
			Seq:     binary.BigEndian.Uint64(k[len(lo):]),
			ValidNS: int64(binary.BigEndian.Uint64(val)),
			Type:    codec.EventType(val[8]),
		})
	}
	return out, it.Error()
}

// ValidRange returns the x/vt entries with fromNS <= valid <= toNS in
// ascending (valid, seq) order.
func (v view) ValidRange(fromNS, toNS int64) ([]IndexEntry, error) {
	opts := &pebble.IterOptions{LowerBound: vtKey(fromNS, 0), UpperBound: upperBound(prefixVT)}
	if toNS != math.MaxInt64 {
		opts.UpperBound = vtKey(toNS+1, 0)
	}
	it, err := v.r.NewIter(opts)
	if err != nil {
		return nil, err
	}
	defer it.Close()
	var out []IndexEntry
	for ok := it.First(); ok; ok = it.Next() {
		k, val := it.Key(), it.Value()
		if len(k) != len(prefixVT)+16 || len(val) != 1 {
			return nil, fmt.Errorf("%w: malformed valid-time entry %q", errs.Corrupt, k)
		}
		out = append(out, IndexEntry{
			Seq:     binary.BigEndian.Uint64(k[len(prefixVT)+8:]),
			ValidNS: int64(binary.BigEndian.Uint64(k[len(prefixVT):]) ^ (1 << 63)),
			Type:    codec.EventType(val[0]),
		})
	}
	return out, it.Error()
}
