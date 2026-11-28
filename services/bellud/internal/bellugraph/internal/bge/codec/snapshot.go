package codec

import (
	"encoding/binary"
	"fmt"
	"hash"
	"hash/crc32"
	"sort"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
)

const (
	snapMagic   = 'S'
	snapVersion = 1
	// magic, version, seq, maxVT, lastRT, nEnt, nRel (the CRC covers these)
	snapFieldsLen = 1 + 1 + 8 + 8 + 8 + 4 + 4
	// SnapshotHeaderLen is the encoded size of a SnapshotHeader.
	SnapshotHeaderLen = snapFieldsLen + 4
)

// SnapshotHeader is the value at s/<seq>/h, written last in its batch.
type SnapshotHeader struct {
	Seq      uint64
	MaxVTNS  int64
	LastRTNS int64
	NEnt     uint32
	NRel     uint32
	CRC      uint32 // over the header fields, then record bytes in key order
}

func (h SnapshotHeader) fields() []byte {
	b := make([]byte, 0, snapFieldsLen)
	b = append(b, snapMagic, snapVersion)
	b = appendU64(b, h.Seq)
	b = appendU64(b, uint64(h.MaxVTNS))
	b = appendU64(b, uint64(h.LastRTNS))
	b = appendU32(b, h.NEnt)
	return appendU32(b, h.NRel)
}

// NewSnapshotCRC starts the Snapshot checksum with the header fields. Write
// each record value in key order, then store Sum32 in SnapshotHeader.CRC.
func NewSnapshotCRC(h SnapshotHeader) hash.Hash32 {
	c := crc32.New(castagnoli)
	c.Write(h.fields())
	return c
}

// Encode returns the header bytes including h.CRC.
func (h SnapshotHeader) Encode() []byte { return appendU32(h.fields(), h.CRC) }

// DecodeSnapshotHeader parses a header. Record contents are verified by the
// caller by recomputing the CRC with NewSnapshotCRC.
func DecodeSnapshotHeader(b []byte) (SnapshotHeader, error) {
	var h SnapshotHeader
	if len(b) != SnapshotHeaderLen {
		return h, fmt.Errorf("%w: codec: snapshot header length %d", errs.Corrupt, len(b))
	}
	r := &reader{b: b}
	if r.u8() != snapMagic || r.u8() != snapVersion {
		return h, fmt.Errorf("%w: codec: bad snapshot magic or version", errs.Corrupt)
	}
	h.Seq = r.u64()
	h.MaxVTNS = int64(r.u64())
	h.LastRTNS = int64(r.u64())
	h.NEnt = r.u32()
	h.NRel = r.u32()
	h.CRC = binary.BigEndian.Uint32(b[snapFieldsLen:])
	return h, r.err
}

// Annotation is operator-owned data attached to an entity.
type Annotation struct {
	Values      map[string]string
	UpdatedAtNS int64
	By          string
}

// EntityRecord is the value at s/<seq>/e/<id>. The ID lives in the key.
type EntityRecord struct {
	Kind     string
	Identity map[string]string
	Attrs    map[string]Value
	Owner    map[string]string
	Live     bool
	Asserted []string // collectors; encoded sorted
	VTNS     int64
	RTNS     int64
	Seq      uint64
	Ann      *Annotation // nil when absent
}

// Encode serializes the record canonically.
func (e EntityRecord) Encode() []byte {
	b := appendStr(nil, e.Kind)
	b = appendStrMap(b, e.Identity)
	b = AppendMap(b, e.Attrs)
	b = appendStrMap(b, e.Owner)
	if e.Live {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	b = appendStrList(b, sortedCopy(e.Asserted))
	b = appendU64(b, uint64(e.VTNS))
	b = appendU64(b, uint64(e.RTNS))
	b = appendU64(b, e.Seq)
	if e.Ann == nil {
		return append(b, 0)
	}
	b = append(b, 1)
	b = appendStrMap(b, e.Ann.Values)
	b = appendU64(b, uint64(e.Ann.UpdatedAtNS))
	return appendStr(b, e.Ann.By)
}

// DecodeEntityRecord parses an entity record.
func DecodeEntityRecord(b []byte) (EntityRecord, error) {
	r := &reader{b: b}
	var e EntityRecord
	e.Kind = r.str()
	e.Identity = r.strMap()
	e.Attrs = r.valueMap()
	e.Owner = r.strMap()
	switch r.u8() {
	case 0:
	case 1:
		e.Live = true
	default:
		r.fail("bad live flag")
	}
	e.Asserted = r.strList()
	e.VTNS = int64(r.u64())
	e.RTNS = int64(r.u64())
	e.Seq = r.u64()
	switch r.u8() {
	case 0:
	case 1:
		e.Ann = &Annotation{Values: r.strMap(), UpdatedAtNS: int64(r.u64()), By: r.str()}
	default:
		r.fail("bad annotation flag")
	}
	if r.err == nil && len(r.b) != 0 {
		r.fail("trailing bytes")
	}
	if r.err != nil {
		return EntityRecord{}, r.err
	}
	return e, nil
}

// RelationRecord is the value at s/<seq>/r/<type>\x00<from>\x00<to>.
type RelationRecord struct {
	Asserted []string
	VTNS     int64
	RTNS     int64
	Seq      uint64
	Attrs    EdgeAttrs
}

// Encode serializes the record canonically.
func (x RelationRecord) Encode() []byte {
	b := appendStrList(nil, sortedCopy(x.Asserted))
	b = appendU64(b, uint64(x.VTNS))
	b = appendU64(b, uint64(x.RTNS))
	b = appendU64(b, x.Seq)
	return AppendEdgeAttrs(b, x.Attrs)
}

// DecodeRelationRecord parses a relation record.
func DecodeRelationRecord(b []byte) (RelationRecord, error) {
	r := &reader{b: b}
	x := RelationRecord{Asserted: r.strList()}
	x.VTNS = int64(r.u64())
	x.RTNS = int64(r.u64())
	x.Seq = r.u64()
	x.Attrs = r.edgeTrailer(len(b), x.Seq)
	if r.err != nil {
		return RelationRecord{}, r.err
	}
	return x, nil
}

func sortedCopy(s []string) []string {
	out := append([]string{}, s...)
	sort.Strings(out)
	return out
}
