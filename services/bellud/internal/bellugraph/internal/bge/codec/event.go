package codec

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
)

// EventType is the envelope type code.
type EventType byte

const (
	EntityCreated   EventType = 1
	EntityUpdated   EventType = 2
	EntityRemoved   EventType = 3
	RelationAdded   EventType = 4
	RelationRemoved EventType = 5
	Annotated       EventType = 6
	ScopeDelta      EventType = 7
	RelationUpdated EventType = 8
)

// Update classes for EntityUpdated.
const (
	ClassAttr  byte = 1
	ClassState byte = 2
)

const (
	eventMagic   = 0x45
	eventVersion = 0x01
	// envelope: magic, version, seq, ULID, valid, recorded, type
	envHeaderLen = 1 + 1 + 8 + 16 + 8 + 8 + 1
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// RelRef names a relation by type and endpoints.
type RelRef struct{ Type, From, To string }

// Event is a decoded log event. Only the body fields for Type are used.
type Event struct {
	Seq        uint64
	ULID       [16]byte
	ValidNS    int64
	RecordedNS int64
	Type       EventType
	Collector  string

	// ID is the entity ID for Updated, Removed and Annotated. For Created it
	// is not stored; the caller recomputes it from Kind and Identity.
	ID string

	Kind     string            // Created
	Identity map[string]string // Created
	Attrs    map[string]Value  // Created

	Class byte             // Updated
	Set   map[string]Value // Updated
	Unset []string         // Updated, Annotated

	RelType, From, To string // RelationAdded, RelationRemoved, RelationUpdated

	EdgeAttrs EdgeAttrs // RelationAdded, RelationUpdated

	Actor   string            // Annotated
	AnnoSet map[string]string // Annotated
	AddEnts []string          // ScopeDelta
	DelEnts []string          // ScopeDelta
	AddRels []RelRef          // ScopeDelta
	DelRels []RelRef          // ScopeDelta
}

// EncodeEvent serializes ev into its envelope, ending with a CRC-32C.
func EncodeEvent(ev Event) ([]byte, error) {
	b := make([]byte, 0, 128)
	b = append(b, eventMagic, eventVersion)
	b = appendU64(b, ev.Seq)
	b = append(b, ev.ULID[:]...)
	b = appendU64(b, uint64(ev.ValidNS))
	b = appendU64(b, uint64(ev.RecordedNS))
	b = append(b, byte(ev.Type))
	b = appendStr(b, ev.Collector)
	switch ev.Type {
	case EntityCreated:
		b = appendStr(b, ev.Kind)
		b = AppendMap(b, stringValues(ev.Identity))
		b = AppendMap(b, ev.Attrs)
	case EntityUpdated:
		b = appendStr(b, ev.ID)
		b = append(b, ev.Class)
		b = AppendMap(b, ev.Set)
		b = appendStrList(b, ev.Unset)
	case EntityRemoved:
		b = appendStr(b, ev.ID)
	case RelationAdded, RelationRemoved, RelationUpdated:
		if ev.EdgeAttrs.Has&^edgeHasMask != 0 {
			return nil, fmt.Errorf("%w: edge attribute flags 0x%02x", errs.Validation, ev.EdgeAttrs.Has)
		}
		b = appendStr(appendStr(appendStr(b, ev.RelType), ev.From), ev.To)
		switch ev.Type {
		case RelationAdded:
			b = AppendEdgeAttrs(b, ev.EdgeAttrs)
		case RelationUpdated:
			b = appendEdgeBody(b, ev.EdgeAttrs)
		}
	case Annotated:
		b = appendStr(b, ev.ID)
		b = appendStr(b, ev.Actor)
		b = appendStrMap(b, ev.AnnoSet)
		b = appendStrList(b, ev.Unset)
	case ScopeDelta:
		b = appendStrList(b, ev.AddEnts)
		b = appendStrList(b, ev.DelEnts)
		b = appendRels(b, ev.AddRels)
		b = appendRels(b, ev.DelRels)
	default:
		return nil, fmt.Errorf("%w: unknown event type %d", errs.Validation, ev.Type)
	}
	return appendU32(b, crc32.Checksum(b, castagnoli)), nil
}

// DecodeEvent verifies the CRC and decodes an envelope. Any damage, including
// truncation, trailing bytes or a bad CRC, yields errs.Corrupt.
func DecodeEvent(b []byte) (Event, error) {
	var ev Event
	if len(b) < envHeaderLen+4 {
		return ev, fmt.Errorf("%w: codec: event too short", errs.Corrupt)
	}
	body, sum := b[:len(b)-4], binary.BigEndian.Uint32(b[len(b)-4:])
	if crc32.Checksum(body, castagnoli) != sum {
		return ev, fmt.Errorf("%w: codec: event CRC mismatch", errs.Corrupt)
	}
	r := &reader{b: body}
	if r.u8() != eventMagic || r.u8() != eventVersion {
		return ev, fmt.Errorf("%w: codec: bad event magic or version", errs.Corrupt)
	}
	ev.Seq = r.u64()
	copy(ev.ULID[:], r.take(16))
	ev.ValidNS = int64(r.u64())
	ev.RecordedNS = int64(r.u64())
	ev.Type = EventType(r.u8())
	ev.Collector = r.str()
	switch ev.Type {
	case EntityCreated:
		ev.Kind = r.str()
		ev.Identity = valuesToStrings(r, r.valueMap())
		ev.Attrs = r.valueMap()
	case EntityUpdated:
		ev.ID = r.str()
		ev.Class = r.u8()
		if ev.Class != ClassAttr && ev.Class != ClassState {
			r.fail("bad update class")
		}
		ev.Set = r.valueMap()
		ev.Unset = r.strList()
	case EntityRemoved:
		ev.ID = r.str()
	case RelationAdded, RelationRemoved, RelationUpdated:
		ev.RelType, ev.From, ev.To = r.str(), r.str(), r.str()
		switch ev.Type {
		case RelationAdded:
			ev.EdgeAttrs = r.edgeTrailer(len(body), ev.Seq)
		case RelationUpdated:
			ev.EdgeAttrs = r.edgeBody()
		}
	case Annotated:
		ev.ID = r.str()
		ev.Actor = r.str()
		ev.AnnoSet = r.strMap()
		ev.Unset = r.strList()
	case ScopeDelta:
		ev.AddEnts = r.strList()
		ev.DelEnts = r.strList()
		ev.AddRels = readRels(r)
		ev.DelRels = readRels(r)
	default:
		r.fail("unknown event type")
	}
	if r.err == nil && len(r.b) != 0 {
		r.fail("trailing bytes")
	}
	if r.err != nil {
		return Event{}, r.err
	}
	return ev, nil
}

func valuesToStrings(r *reader, m map[string]Value) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		if v.T != TagString {
			r.fail("identity value not a string")
		}
		out[k] = v.S
	}
	return out
}

func appendRels(b []byte, l []RelRef) []byte {
	b = appendU32(b, uint32(len(l)))
	for _, x := range l {
		b = appendStr(appendStr(appendStr(b, x.Type), x.From), x.To)
	}
	return b
}

func readRels(r *reader) []RelRef {
	n := r.count(12)
	l := make([]RelRef, 0, n)
	for i := 0; i < n && r.err == nil; i++ {
		l = append(l, RelRef{r.str(), r.str(), r.str()})
	}
	return l
}
