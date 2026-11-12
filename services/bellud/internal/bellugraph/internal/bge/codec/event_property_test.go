package codec

import (
	"reflect"
	"testing"

	"pgregory.net/rapid"
)

func genStr() *rapid.Generator[string] { return rapid.StringN(0, 12, 40) }

func genValue() *rapid.Generator[Value] {
	return rapid.OneOf(
		rapid.Map(genStr(), func(s string) Value { return Value{T: TagString, S: s} }),
		rapid.Map(rapid.Bool(), func(b bool) Value { return Value{T: TagBool, B: b} }),
		rapid.Map(rapid.Int64(), func(i int64) Value { return Value{T: TagInt, I: i} }),
		rapid.Map(rapid.Float64(), func(f float64) Value {
			if f == 0 {
				f = 0
			}
			return Value{T: TagFloat, F: f}
		}),
		rapid.Map(rapid.SliceOfN(genStr(), 0, 4), func(l []string) Value {
			return Value{T: TagList, L: append([]string{}, l...)}
		}),
	)
}

func genValueMap() *rapid.Generator[map[string]Value] {
	return rapid.MapOfN(genStr(), genValue(), 0, 4)
}

func genStrMap() *rapid.Generator[map[string]string] {
	return rapid.MapOfN(genStr(), genStr(), 0, 4)
}

func genStrList() *rapid.Generator[[]string] {
	return rapid.Map(rapid.SliceOfN(genStr(), 0, 4), func(l []string) []string { return append([]string{}, l...) })
}

func genRels() *rapid.Generator[[]RelRef] {
	return rapid.Map(rapid.SliceOfN(rapid.Custom(func(t *rapid.T) RelRef {
		return RelRef{genStr().Draw(t, "t"), genStr().Draw(t, "f"), genStr().Draw(t, "to")}
	}), 0, 3), func(l []RelRef) []RelRef { return append([]RelRef{}, l...) })
}

// genEvent draws a valid Event with only the body fields for its type set.
func genEvent() *rapid.Generator[Event] {
	return rapid.Custom(func(t *rapid.T) Event {
		e := Event{
			Seq:        rapid.Uint64().Draw(t, "seq"),
			ValidNS:    rapid.Int64().Draw(t, "valid"),
			RecordedNS: rapid.Int64().Draw(t, "rec"),
			Type:       EventType(rapid.IntRange(1, 7).Draw(t, "type")),
			Collector:  genStr().Draw(t, "col"),
		}
		copy(e.ULID[:], rapid.SliceOfN(rapid.Byte(), 16, 16).Draw(t, "ulid"))
		switch e.Type {
		case EntityCreated:
			e.Kind = genStr().Draw(t, "kind")
			e.Identity = genStrMap().Draw(t, "identity")
			e.Attrs = genValueMap().Draw(t, "attrs")
		case EntityUpdated:
			e.ID = genStr().Draw(t, "id")
			e.Class = byte(rapid.IntRange(1, 2).Draw(t, "class"))
			e.Set = genValueMap().Draw(t, "set")
			e.Unset = genStrList().Draw(t, "unset")
		case EntityRemoved:
			e.ID = genStr().Draw(t, "id")
		case RelationAdded, RelationRemoved:
			e.RelType, e.From, e.To = genStr().Draw(t, "rt"), genStr().Draw(t, "from"), genStr().Draw(t, "to")
		case Annotated:
			e.ID = genStr().Draw(t, "id")
			e.Actor = genStr().Draw(t, "actor")
			e.AnnoSet = genStrMap().Draw(t, "anno")
			e.Unset = genStrList().Draw(t, "unset")
		case ScopeDelta:
			e.AddEnts = genStrList().Draw(t, "ae")
			e.DelEnts = genStrList().Draw(t, "de")
			e.AddRels = genRels().Draw(t, "ar")
			e.DelRels = genRels().Draw(t, "dr")
		}
		return e
	})
}

// Feature: bellu-graph-native, Property 1: Event codec round trip and corruption detection
// Validates: Requirements 3.2, 18.6
func TestPropertyEventCodecRoundTripAndCorruption(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		e := genEvent().Draw(t, "event")
		b, err := EncodeEvent(e)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		got, err := DecodeEvent(b)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !reflect.DeepEqual(got, e) {
			t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, e)
		}

		// Any single-byte change must be detected.
		i := rapid.IntRange(0, len(b)-1).Draw(t, "index")
		delta := byte(rapid.IntRange(1, 255).Draw(t, "delta"))
		bad := append([]byte{}, b...)
		bad[i] ^= delta
		if _, err := DecodeEvent(bad); err == nil {
			t.Fatalf("corruption at byte %d (xor %#x) not detected", i, delta)
		}
	})
}
