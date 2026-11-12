package codec

import (
	"errors"
	"math"
	"reflect"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
)

func TestFromAny(t *testing.T) {
	for _, tc := range []struct {
		in   any
		want Value
	}{
		{"x", Value{T: TagString, S: "x"}},
		{true, Value{T: TagBool, B: true}},
		{uint8(7), Value{T: TagInt, I: 7}},
		{int32(-3), Value{T: TagInt, I: -3}},
		{float32(1.5), Value{T: TagFloat, F: 1.5}},
		{[]any{"a", "b"}, Value{T: TagList, L: []string{"a", "b"}}},
	} {
		got, err := FromAny("a", tc.in)
		if err != nil || !got.Equal(tc.want) {
			t.Errorf("FromAny(%v) = %v, %v", tc.in, got, err)
		}
	}
	for _, bad := range []any{math.NaN(), math.Inf(1), math.Inf(-1), uint64(math.MaxInt64) + 1, []any{"a", 1}, nil, map[string]any{}} {
		if _, err := FromAny("a", bad); !errors.Is(err, errs.Validation) {
			t.Errorf("FromAny(%v) err = %v, want Validation", bad, err)
		}
	}
	v, _ := FromAny("a", math.Copysign(0, -1))
	if math.Signbit(v.F) {
		t.Error("-0 not normalized")
	}
}

func TestMapRoundTripAndOrder(t *testing.T) {
	m := map[string]Value{
		"b": {T: TagList, L: []string{"x", ""}},
		"a": {T: TagInt, I: -9},
		"c": {T: TagFloat, F: 2.25},
		"d": {T: TagBool, B: true},
		"e": {T: TagString, S: "héllo"},
	}
	enc := EncodeMap(m)
	if string(enc) != string(EncodeMap(m)) {
		t.Fatal("not deterministic")
	}
	got, err := DecodeMap(enc)
	if err != nil || !reflect.DeepEqual(got, m) {
		t.Fatalf("round trip: %v %v", got, err)
	}
	if _, err := DecodeMap(append(enc, 0)); err == nil {
		t.Error("trailing byte accepted")
	}
}

func TestEventRoundTripAllTypes(t *testing.T) {
	base := Event{Seq: 9, ULID: [16]byte{1, 2, 3}, ValidNS: -5, RecordedNS: 77, Collector: "col"}
	evs := []Event{
		{Type: EntityCreated, Kind: "host", Identity: map[string]string{"hostname": "w"}, Attrs: map[string]Value{"n": {T: TagInt, I: 1}}},
		{Type: EntityUpdated, ID: "host:1", Class: ClassState, Set: map[string]Value{"state": {T: TagString, S: "up"}}, Unset: []string{"z"}},
		{Type: EntityRemoved, ID: "host:1"},
		{Type: RelationAdded, RelType: "runs_on", From: "a", To: "b"},
		{Type: RelationRemoved, RelType: "runs_on", From: "a", To: "b"},
		{Type: Annotated, ID: "host:1", Actor: "op", AnnoSet: map[string]string{"k": "v"}, Unset: []string{"u"}},
		{Type: ScopeDelta, AddEnts: []string{"a"}, DelEnts: []string{"b"}, AddRels: []RelRef{{"t", "f", "x"}}, DelRels: []RelRef{}},
	}
	for _, e := range evs {
		e.Seq, e.ULID, e.ValidNS, e.RecordedNS, e.Collector = base.Seq, base.ULID, base.ValidNS, base.RecordedNS, base.Collector
		b, err := EncodeEvent(e)
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeEvent(b)
		if err != nil {
			t.Fatalf("type %d: %v", e.Type, err)
		}
		norm(&e)
		norm(&got)
		if !reflect.DeepEqual(e, got) {
			t.Errorf("type %d:\n got %+v\nwant %+v", e.Type, got, e)
		}
		for i := range b { // any single-bit flip is detected
			c := append([]byte{}, b...)
			c[i] ^= 0x10
			if _, err := DecodeEvent(c); !errors.Is(err, errs.Corrupt) {
				t.Fatalf("type %d: flip at %d undetected", e.Type, i)
			}
		}
		if _, err := DecodeEvent(b[:len(b)-1]); err == nil {
			t.Error("truncation undetected")
		}
	}
}

// norm makes nil and empty collections equal for comparison.
func norm(e *Event) {
	if len(e.Unset) == 0 {
		e.Unset = nil
	}
	if len(e.DelRels) == 0 {
		e.DelRels = nil
	}
	if len(e.AddRels) == 0 {
		e.AddRels = nil
	}
	if len(e.AddEnts) == 0 {
		e.AddEnts = nil
	}
	if len(e.DelEnts) == 0 {
		e.DelEnts = nil
	}
	if len(e.Set) == 0 {
		e.Set = nil
	}
}

func TestSnapshot(t *testing.T) {
	er := EntityRecord{Kind: "host", Identity: map[string]string{"hostname": "w"}, Attrs: map[string]Value{"a": {T: TagBool, B: true}},
		Owner: map[string]string{"a": "c"}, Live: true, Asserted: []string{"c", "b"}, VTNS: 1, RTNS: 2, Seq: 3,
		Ann: &Annotation{Values: map[string]string{"k": "v"}, UpdatedAtNS: 4, By: "op"}}
	eb := er.Encode()
	got, err := DecodeEntityRecord(eb)
	er.Asserted = []string{"b", "c"}
	if err != nil || !reflect.DeepEqual(got, er) {
		t.Fatalf("entity record: %+v %v", got, err)
	}
	rr := RelationRecord{Asserted: []string{"c"}, VTNS: 1, RTNS: 2, Seq: 3}
	rb := rr.Encode()
	if g, err := DecodeRelationRecord(rb); err != nil || !reflect.DeepEqual(g, rr) {
		t.Fatalf("relation record: %+v %v", g, err)
	}
	h := SnapshotHeader{Seq: 3, MaxVTNS: 5, LastRTNS: 6, NEnt: 1, NRel: 1}
	c := NewSnapshotCRC(h)
	c.Write(eb)
	c.Write(rb)
	h.CRC = c.Sum32()
	hg, err := DecodeSnapshotHeader(h.Encode())
	if err != nil || hg != h {
		t.Fatalf("header: %+v %v", hg, err)
	}
	if _, err := DecodeSnapshotHeader(h.Encode()[1:]); err == nil {
		t.Error("short header accepted")
	}
	if _, err := DecodeEntityRecord(eb[:len(eb)-1]); err == nil {
		t.Error("truncated record accepted")
	}
}
