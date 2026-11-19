package codec

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"sort"
	"testing"
)

// This file freezes the pre-feature (no edge attributes) encoders for the
// RelationAdded event and the RelationRecord. The bodies below are verbatim
// copies of EncodeEvent's RelationAdded branch and RelationRecord.Encode as
// they were before edge attributes existed. They never change. Later tests
// compare the live encoders against them to prove that a relation with zero
// attributes encodes to identical bytes (Requirements 7.2, 16.5).
//
// The primitives are copied too, so a change to the live helpers cannot
// silently change the frozen output.

var legacyCastagnoli = crc32.MakeTable(crc32.Castagnoli)

func legacyAppendU32(b []byte, n uint32) []byte { return binary.BigEndian.AppendUint32(b, n) }
func legacyAppendU64(b []byte, n uint64) []byte { return binary.BigEndian.AppendUint64(b, n) }
func legacyAppendStr(b []byte, s string) []byte {
	return append(legacyAppendU32(b, uint32(len(s))), s...)
}

func legacyAppendStrList(b []byte, l []string) []byte {
	b = legacyAppendU32(b, uint32(len(l)))
	for _, s := range l {
		b = legacyAppendStr(b, s)
	}
	return b
}

func legacySortedCopy(s []string) []string {
	out := append([]string{}, s...)
	sort.Strings(out)
	return out
}

// legacyEncodeRelationAddedBody is the RelationAdded body: type, from, to.
func legacyEncodeRelationAddedBody(b []byte, ev Event) []byte {
	return legacyAppendStr(legacyAppendStr(legacyAppendStr(b, ev.RelType), ev.From), ev.To)
}

// legacyEncodeRelationAdded is the full RelationAdded envelope: header, body
// and trailing CRC-32C, exactly as EncodeEvent produced it.
func legacyEncodeRelationAdded(ev Event) []byte {
	b := make([]byte, 0, 128)
	b = append(b, eventMagic, eventVersion)
	b = legacyAppendU64(b, ev.Seq)
	b = append(b, ev.ULID[:]...)
	b = legacyAppendU64(b, uint64(ev.ValidNS))
	b = legacyAppendU64(b, uint64(ev.RecordedNS))
	b = append(b, byte(RelationAdded))
	b = legacyAppendStr(b, ev.Collector)
	b = legacyEncodeRelationAddedBody(b, ev)
	return legacyAppendU32(b, crc32.Checksum(b, legacyCastagnoli))
}

// legacyEncodeRelationRecord is RelationRecord.Encode.
func legacyEncodeRelationRecord(x RelationRecord) []byte {
	b := legacyAppendStrList(nil, legacySortedCopy(x.Asserted))
	b = legacyAppendU64(b, uint64(x.VTNS))
	b = legacyAppendU64(b, uint64(x.RTNS))
	return legacyAppendU64(b, x.Seq)
}

// TestLegacyEncodersMatchCurrent checks the frozen copies against the current
// encoders on the pre-feature tree. Once edge attributes land, a zero-attribute
// relation must still pass this.
func TestLegacyEncodersMatchCurrent(t *testing.T) {
	ev := Event{
		Seq:        7,
		ULID:       [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		ValidNS:    1_700_000_000_000_000_000,
		RecordedNS: 1_700_000_001_000_000_000,
		Type:       RelationAdded,
		Collector:  "aws",
		RelType:    "contains",
		From:       "acct-1",
		To:         "vpc-1",
	}
	got, err := EncodeEvent(ev)
	if err != nil {
		t.Fatal(err)
	}
	if want := legacyEncodeRelationAdded(ev); !bytes.Equal(got, want) {
		t.Fatalf("RelationAdded bytes differ\n got %x\nwant %x", got, want)
	}

	rec := RelationRecord{Asserted: []string{"github", "aws"}, VTNS: 11, RTNS: 12, Seq: 13}
	if got, want := rec.Encode(), legacyEncodeRelationRecord(rec); !bytes.Equal(got, want) {
		t.Fatalf("RelationRecord bytes differ\n got %x\nwant %x", got, want)
	}
	empty := RelationRecord{}
	if got, want := empty.Encode(), legacyEncodeRelationRecord(empty); !bytes.Equal(got, want) {
		t.Fatalf("empty RelationRecord bytes differ\n got %x\nwant %x", got, want)
	}
}
