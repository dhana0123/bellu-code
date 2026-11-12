package store

import "encoding/binary"

// Keyspace prefixes.
var (
	prefixEvent = []byte("e/")
	prefixEnt   = []byte("x/ent/")
	prefixRel   = []byte("x/rel/")
	prefixVT    = []byte("x/vt/")
	prefixSnap  = []byte("s/")
)

func be64(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }

// eventKey is e/<u64be seq>.
func eventKey(seq uint64) []byte {
	return binary.BigEndian.AppendUint64(append([]byte(nil), prefixEvent...), seq)
}

// idxKey is <prefix><id>\x00<u64be seq>, used for x/ent and x/rel.
func idxKey(prefix []byte, id string, seq uint64) []byte {
	k := append(append(append([]byte(nil), prefix...), id...), 0)
	return binary.BigEndian.AppendUint64(k, seq)
}

// vtKey is x/vt/<valid_ns with the sign bit flipped><u64be seq>.
func vtKey(validNS int64, seq uint64) []byte {
	k := append([]byte(nil), prefixVT...)
	k = binary.BigEndian.AppendUint64(k, uint64(validNS)^(1<<63))
	return binary.BigEndian.AppendUint64(k, seq)
}

// snapPrefix is s/<u64be seq>/.
func snapPrefix(seq uint64) []byte {
	k := binary.BigEndian.AppendUint64(append([]byte(nil), prefixSnap...), seq)
	return append(k, '/')
}

func snapHeaderKey(seq uint64) []byte { return append(snapPrefix(seq), 'h') }

// upperBound returns the smallest key greater than every key with the prefix.
func upperBound(prefix []byte) []byte {
	b := append([]byte(nil), prefix...)
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] != 0xff {
			b[i]++
			return b[:i+1]
		}
	}
	return nil
}
