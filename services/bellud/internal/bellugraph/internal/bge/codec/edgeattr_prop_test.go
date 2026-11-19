package codec

import (
	"bytes"
	"reflect"
	"slices"
	"sort"
	"testing"

	"pgregory.net/rapid"
)

// rtGenAttrs draws 0 to 3 edge attributes. Empty strings are allowed so an
// empty evidence stays distinct from an absent one.
func rtGenAttrs(t *rapid.T) EdgeAttrs {
	a := EdgeAttrs{Has: rapid.Uint8Range(0, 7).Draw(t, "has")}
	str := rapid.StringN(0, 24, -1)
	if a.Has&1 != 0 {
		a.Evidence = str.Draw(t, "evidence")
	}
	if a.Has&2 != 0 {
		a.Confidence = str.Draw(t, "confidence")
	}
	if a.Has&4 != 0 {
		a.ObservedAt = str.Draw(t, "observed_at")
	}
	return a
}

// rtGenRelEvent draws a relation event of the given type. Attributes are
// drawn only when withAttrs is set.
func rtGenRelEvent(t *rapid.T, typ EventType, withAttrs bool) Event {
	str := rapid.StringN(0, 16, -1)
	ev := Event{
		Seq:        rapid.Uint64().Draw(t, "seq"),
		ValidNS:    rapid.Int64().Draw(t, "valid"),
		RecordedNS: rapid.Int64().Draw(t, "recorded"),
		Type:       typ,
		Collector:  str.Draw(t, "collector"),
		RelType:    str.Draw(t, "rel_type"),
		From:       str.Draw(t, "from"),
		To:         str.Draw(t, "to"),
	}
	copy(ev.ULID[:], rapid.SliceOfN(rapid.Byte(), 16, 16).Draw(t, "ulid"))
	if withAttrs {
		ev.EdgeAttrs = rtGenAttrs(t)
	}
	return ev
}

// rtGenRecord draws a relation record with a sorted, unique Asserted list,
// the canonical form that Encode produces and decode returns.
func rtGenRecord(t *rapid.T, withAttrs bool) RelationRecord {
	asserted := rapid.SliceOfNDistinct(rapid.StringN(0, 12, -1), 0, 5, rapid.ID[string]).Draw(t, "asserted")
	sort.Strings(asserted)
	x := RelationRecord{
		Asserted: asserted,
		VTNS:     rapid.Int64().Draw(t, "vt"),
		RTNS:     rapid.Int64().Draw(t, "rt"),
		Seq:      rapid.Uint64().Draw(t, "seq"),
	}
	if withAttrs {
		x.Attrs = rtGenAttrs(t)
	}
	return x
}

func rtRecordsEqual(a, b RelationRecord) bool {
	return slices.Equal(a.Asserted, b.Asserted) && a.VTNS == b.VTNS && a.RTNS == b.RTNS &&
		a.Seq == b.Seq && a.Attrs.Equal(b.Attrs)
}

// Feature: aws-relationship-registry, Property 8: Zero-attribute encoding is byte identical to the legacy format
//
// Validates: Requirements 7.1, 7.2, 7.3, 16.5
func TestZeroAttributeBytesMatchLegacyProperty(t *testing.T) {
	t.Run("RelationAdded", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			ev := rtGenRelEvent(t, RelationAdded, false)
			legacy := legacyEncodeRelationAdded(ev)
			got, err := EncodeEvent(ev)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, legacy) {
				t.Fatalf("bytes differ\n got %x\nwant %x", got, legacy)
			}
			dec, err := DecodeEvent(legacy)
			if err != nil {
				t.Fatalf("decode legacy: %v", err)
			}
			if !dec.EdgeAttrs.Zero() || !reflect.DeepEqual(dec, ev) {
				t.Fatalf("decoded legacy bytes\n got %+v\nwant %+v", dec, ev)
			}
		})
	})
	t.Run("RelationRecord", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			x := rtGenRecord(t, false)
			legacy := legacyEncodeRelationRecord(x)
			if got := x.Encode(); !bytes.Equal(got, legacy) {
				t.Fatalf("bytes differ\n got %x\nwant %x", got, legacy)
			}
			dec, err := DecodeRelationRecord(legacy)
			if err != nil {
				t.Fatalf("decode legacy: %v", err)
			}
			if !dec.Attrs.Zero() || !rtRecordsEqual(dec, x) {
				t.Fatalf("decoded legacy bytes\n got %+v\nwant %+v", dec, x)
			}
		})
	})
}

// Feature: aws-relationship-registry, Property 9: Codec round trip with attributes
//
// Validates: Requirements 7.1, 7.3, 7.5
func TestCodecRoundTripWithAttributesProperty(t *testing.T) {
	t.Run("RelationAdded and RelationUpdated", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			typ := rapid.SampledFrom([]EventType{RelationAdded, RelationUpdated}).Draw(t, "type")
			ev := rtGenRelEvent(t, typ, true)
			b, err := EncodeEvent(ev)
			if err != nil {
				t.Fatal(err)
			}
			got, err := DecodeEvent(b)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !reflect.DeepEqual(got, ev) {
				t.Fatalf("round trip\n got %+v\nwant %+v", got, ev)
			}
		})
	})
	t.Run("RelationRecord", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			x := rtGenRecord(t, true)
			got, err := DecodeRelationRecord(x.Encode())
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !rtRecordsEqual(got, x) {
				t.Fatalf("round trip\n got %+v\nwant %+v", got, x)
			}
		})
	})
}
