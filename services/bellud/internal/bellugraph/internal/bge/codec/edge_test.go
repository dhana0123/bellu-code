package codec

import (
	"bytes"
	"errors"
	"hash/crc32"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
)

func genEdgeAttrs() *rapid.Generator[EdgeAttrs] {
	return rapid.Custom(func(t *rapid.T) EdgeAttrs {
		a := EdgeAttrs{Has: rapid.Uint8Range(0, 7).Draw(t, "has")}
		if a.Has&1 != 0 {
			a.Evidence = genStr().Draw(t, "evidence")
		}
		if a.Has&2 != 0 {
			a.Confidence = genStr().Draw(t, "confidence")
		}
		if a.Has&4 != 0 {
			a.ObservedAt = genStr().Draw(t, "observed")
		}
		return a
	})
}

// reseal rebuilds an event's CRC after its body was edited.
func reseal(body []byte) []byte {
	return appendU32(body, crc32.Checksum(body, castagnoli))
}

func relEvent(typ EventType, a EdgeAttrs) Event {
	return Event{Seq: 9, Type: typ, Collector: "aws", RelType: "t", From: "a", To: "b", EdgeAttrs: a}
}

// Validates: Requirements 7.1, 7.3
func TestEdgeAttrsRoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := genEdgeAttrs().Draw(t, "attrs")
		for _, typ := range []EventType{RelationAdded, RelationUpdated} {
			b, err := EncodeEvent(relEvent(typ, a))
			if err != nil {
				t.Fatal(err)
			}
			got, err := DecodeEvent(b)
			if err != nil || !got.EdgeAttrs.Equal(a) {
				t.Fatalf("type %d: got %+v, %v want %+v", typ, got.EdgeAttrs, err, a)
			}
		}
		rec := RelationRecord{Asserted: []string{"aws"}, VTNS: 1, RTNS: 2, Seq: 3, Attrs: a}
		got, err := DecodeRelationRecord(rec.Encode())
		if err != nil || !got.Attrs.Equal(a) || got.Seq != 3 {
			t.Fatalf("record: got %+v, %v", got, err)
		}
	})
}

// Validates: Requirements 7.2
func TestEdgeAttrsZeroKeepsLegacyBytes(t *testing.T) {
	rec := RelationRecord{Asserted: []string{"aws"}, VTNS: 1, RTNS: 2, Seq: 3}
	legacy := appendU64(appendU64(appendU64(appendStrList(nil, []string{"aws"}), 1), 2), 3)
	if !bytes.Equal(rec.Encode(), legacy) {
		t.Fatal("zero attrs changed record bytes")
	}
	b, _ := EncodeEvent(relEvent(RelationAdded, EdgeAttrs{}))
	body := b[:len(b)-4]
	if !bytes.HasSuffix(body, appendStr(appendStr(appendStr(nil, "t"), "a"), "b")) {
		t.Fatal("zero attrs appended bytes to RelationAdded")
	}
	if b[1] != eventVersion || snapVersion != 1 {
		t.Fatal("version changed")
	}
}

func TestEdgeAttrsEmptyDiffersFromAbsent(t *testing.T) {
	if (EdgeAttrs{Has: 1}).Equal(EdgeAttrs{}) || !(EdgeAttrs{}).Zero() || (EdgeAttrs{Has: 1}).Zero() {
		t.Fatal("presence not tracked")
	}
	if !(EdgeAttrs{Has: 1, Evidence: "x", Confidence: "ignored"}).Equal(EdgeAttrs{Has: 1, Evidence: "x"}) {
		t.Fatal("absent fields must be ignored")
	}
}

// Validates: Requirements 7.4, 7.5
func TestEdgeTrailerRejectsDamage(t *testing.T) {
	good, _ := EncodeEvent(relEvent(RelationAdded, EdgeAttrs{Has: 1, Evidence: "ev"}))
	body := good[:len(good)-4]
	legacy, _ := EncodeEvent(relEvent(RelationAdded, EdgeAttrs{}))
	legacyBody := legacy[:len(legacy)-4]

	cases := map[string][]byte{
		"unknown tag":     append(append([]byte{}, legacyBody...), 0x02, 0x00),
		"undefined flags": append(append([]byte{}, legacyBody...), 0x01, 0x08),
		"truncated str":   body[:len(body)-1],
		"bytes after":     append(append([]byte{}, body...), 0x00),
		"missing flags":   append(append([]byte{}, legacyBody...), 0x01),
	}
	for name, c := range cases {
		got, err := DecodeEvent(reseal(c))
		if !errors.Is(err, errs.Corrupt) || !got.EdgeAttrs.Zero() || got.RelType != "" {
			t.Errorf("%s: got %+v, %v", name, got, err)
		}
	}

	_, err := DecodeEvent(reseal(cases["unknown tag"]))
	want := "unknown trailing field set 0x02 at byte " // position is the tag offset
	if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "of record (seq 9)") {
		t.Errorf("event message: %v", err)
	}

	rec := RelationRecord{Asserted: []string{"aws"}, Seq: 5}.Encode()
	for name, c := range map[string][]byte{
		"unknown tag":     append(append([]byte{}, rec...), 0x7f),
		"undefined flags": append(append([]byte{}, rec...), 0x01, 0xff),
		"truncated str":   append(append([]byte{}, rec...), 0x01, 0x01, 0, 0, 0, 9, 'x'),
		"bytes after":     append(RelationRecord{Asserted: []string{"aws"}, Seq: 5, Attrs: EdgeAttrs{Has: 2}}.Encode(), 0),
	} {
		got, err := DecodeRelationRecord(c)
		if !errors.Is(err, errs.Corrupt) || got.Seq != 0 || len(got.Asserted) != 0 {
			t.Errorf("record %s: got %+v, %v", name, got, err)
		}
	}
	_, err = DecodeRelationRecord(append(append([]byte{}, rec...), 0x7f))
	if err == nil || !strings.Contains(err.Error(), "unknown trailing field set 0x7f at byte 35 of record (seq 5)") {
		t.Errorf("record message: %v", err)
	}
}

func TestEncodeRejectsUndefinedEdgeFlags(t *testing.T) {
	if _, err := EncodeEvent(relEvent(RelationUpdated, EdgeAttrs{Has: 8})); !errors.Is(err, errs.Validation) {
		t.Fatalf("got %v", err)
	}
}
