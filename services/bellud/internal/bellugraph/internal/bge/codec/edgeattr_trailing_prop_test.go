package codec

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
)

// trDamage builds a trailer that a decoder must reject. wantUnknown is set
// when the failure is an unknown tag, whose message names the position.
func trDamage(t *rapid.T) (trailer []byte, wantTag int) {
	a := genEdgeAttrs().Draw(t, "attrs")
	filler := rapid.SliceOfN(rapid.Byte(), 0, 8).Draw(t, "filler")
	switch rapid.IntRange(0, 3).Draw(t, "damage") {
	case 0: // tag other than 0x01
		tag := rapid.SampledFrom([]int{0x00, 0x02, 0x7f, 0x80, 0xff}).Draw(t, "tag")
		return append([]byte{byte(tag)}, filler...), tag
	case 1: // flags with undefined bits
		flags := byte(rapid.IntRange(0x08, 0xff).Draw(t, "flags"))
		return append([]byte{edgeTrailerTag, flags}, filler...), -1
	case 2: // valid section cut inside its tag, flags or strings
		full := appendEdgeBody(append([]byte(nil), edgeTrailerTag), EdgeAttrs{
			Has: a.Has | 1, Evidence: a.Evidence, Confidence: a.Confidence, ObservedAt: a.ObservedAt,
		})
		cut := rapid.IntRange(1, len(full)-1).Draw(t, "cut")
		return full[:len(full)-cut], -1
	default: // valid section followed by extra bytes
		extra := append([]byte{rapid.Byte().Draw(t, "extra")}, filler...)
		return append(appendEdgeBody([]byte{edgeTrailerTag}, a), extra...), -1
	}
}

// Feature: aws-relationship-registry, Property 10: Unknown trailing field sets are decode errors
// Validates: Requirements 7.4
func TestTrUnknownTrailingFieldSetProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		trailer, tag := trDamage(t)
		seq := rapid.Uint64().Draw(t, "seq")
		wantMsg := func(pos int) string {
			if tag < 0 {
				return ""
			}
			return fmt.Sprintf("unknown trailing field set 0x%02x at byte %d of record (seq %d)", tag, pos, seq)
		}

		ev := relEvent(RelationAdded, EdgeAttrs{})
		ev.Seq = seq
		enc, err := EncodeEvent(ev)
		if err != nil {
			t.Fatal(err)
		}
		legacy := enc[:len(enc)-4]
		gotEv, err := DecodeEvent(reseal(append(append([]byte{}, legacy...), trailer...)))
		if !errors.Is(err, errs.Corrupt) {
			t.Fatalf("event: want Corrupt, got %v", err)
		}
		if gotEv.Seq != 0 || gotEv.RelType != "" || !gotEv.EdgeAttrs.Zero() {
			t.Fatalf("event: partial value %+v", gotEv)
		}
		if m := wantMsg(len(legacy)); !strings.Contains(err.Error(), m) {
			t.Fatalf("event: %q does not contain %q", err, m)
		}

		rec := RelationRecord{Asserted: []string{"aws"}, VTNS: 1, RTNS: 2, Seq: seq}.Encode()
		gotRec, err := DecodeRelationRecord(append(append([]byte{}, rec...), trailer...))
		if !errors.Is(err, errs.Corrupt) {
			t.Fatalf("record: want Corrupt, got %v", err)
		}
		if gotRec.Seq != 0 || len(gotRec.Asserted) != 0 || !gotRec.Attrs.Zero() {
			t.Fatalf("record: partial value %+v", gotRec)
		}
		if m := wantMsg(len(rec)); !strings.Contains(err.Error(), m) {
			t.Fatalf("record: %q does not contain %q", err, m)
		}
	})
}
