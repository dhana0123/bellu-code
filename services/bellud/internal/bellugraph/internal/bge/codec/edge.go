package codec

import (
	"fmt"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
)

const (
	edgeTrailerTag = 0x01
	edgeHasMask    = 0x07 // evidence | confidence | observed_at
)

// EdgeAttrs are the optional attributes of a relation. Has records which
// fields are present, because an empty string differs from an omitted one.
type EdgeAttrs struct {
	Evidence, Confidence, ObservedAt string
	Has                              uint8 // bit0 evidence, bit1 confidence, bit2 observed_at
}

// Zero reports whether no attribute is present.
func (a EdgeAttrs) Zero() bool { return a.Has == 0 }

// Equal compares presence and the values of present fields.
func (a EdgeAttrs) Equal(b EdgeAttrs) bool {
	if a.Has != b.Has {
		return false
	}
	return (a.Has&1 == 0 || a.Evidence == b.Evidence) &&
		(a.Has&2 == 0 || a.Confidence == b.Confidence) &&
		(a.Has&4 == 0 || a.ObservedAt == b.ObservedAt)
}

// AppendEdgeAttrs appends the optional trailer `0x01 | flags | strings`. It
// appends nothing when no attribute is present, so the bytes of a relation
// without attributes stay identical to the legacy encoding.
func AppendEdgeAttrs(b []byte, a EdgeAttrs) []byte {
	if a.Has == 0 {
		return b
	}
	return appendEdgeBody(append(b, edgeTrailerTag), a)
}

// appendEdgeBody appends `flags | present strings`.
func appendEdgeBody(b []byte, a EdgeAttrs) []byte {
	b = append(b, a.Has)
	if a.Has&1 != 0 {
		b = appendStr(b, a.Evidence)
	}
	if a.Has&2 != 0 {
		b = appendStr(b, a.Confidence)
	}
	if a.Has&4 != 0 {
		b = appendStr(b, a.ObservedAt)
	}
	return b
}

// edgeBody reads `flags | present strings`.
func (r *reader) edgeBody() EdgeAttrs {
	var a EdgeAttrs
	a.Has = r.u8()
	if r.err == nil && a.Has&^edgeHasMask != 0 {
		r.fail(fmt.Sprintf("edge attribute flags 0x%02x", a.Has))
	}
	if a.Has&1 != 0 {
		a.Evidence = r.str()
	}
	if a.Has&2 != 0 {
		a.Confidence = r.str()
	}
	if a.Has&4 != 0 {
		a.ObservedAt = r.str()
	}
	if r.err != nil {
		return EdgeAttrs{}
	}
	return a
}

// edgeTrailer reads the optional trailer after the legacy fields and requires
// that nothing follows it. total is the record length, used for the position
// in errors; seq is the record's sequence number.
func (r *reader) edgeTrailer(total int, seq uint64) EdgeAttrs {
	if r.err != nil || len(r.b) == 0 {
		return EdgeAttrs{}
	}
	pos := total - len(r.b)
	if tag := r.u8(); tag != edgeTrailerTag {
		r.err = fmt.Errorf("%w: codec: unknown trailing field set 0x%02x at byte %d of record (seq %d)", errs.Corrupt, tag, pos, seq)
		return EdgeAttrs{}
	}
	a := r.edgeBody()
	if r.err == nil && len(r.b) != 0 {
		r.fail("trailing bytes")
	}
	if r.err != nil {
		return EdgeAttrs{}
	}
	return a
}
