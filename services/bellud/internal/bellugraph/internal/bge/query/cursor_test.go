package query

import (
	"bytes"
	"errors"
	"testing"
	"testing/quick"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
)

func TestCursorRoundTrip(t *testing.T) {
	for _, key := range [][]byte{{}, {0}, []byte("entity-1"), {0xff, 0x00, 0x7f}} {
		got, err := DecodeCursor("find", 42, EncodeCursor("find", 42, key))
		if err != nil || !bytes.Equal(got, key) {
			t.Fatalf("key %x: got %x, %v", key, got, err)
		}
	}
}

func TestCursorRejects(t *testing.T) {
	c := EncodeCursor("find", 1, []byte("k"))
	for name, tc := range map[string]struct {
		kind string
		q    uint64
		s    string
	}{
		"kind":    {"history", 1, c},
		"query":   {"find", 2, c},
		"empty":   {"find", 1, ""},
		"garbage": {"find", 1, "!!not base64!!"},
		"notjson": {"find", 1, "aGVsbG8"},
		"trunc":   {"find", 1, c[:len(c)-3]},
	} {
		if _, err := DecodeCursor(tc.kind, tc.q, tc.s); !errors.Is(err, errs.Validation) {
			t.Errorf("%s: err = %v, want Validation", name, err)
		}
	}
}

// Property 27: cursor integrity.
func TestCursorProperty(t *testing.T) {
	round := func(kind string, q uint64, key []byte) bool {
		got, err := DecodeCursor(kind, q, EncodeCursor(kind, q, key))
		return err == nil && bytes.Equal(got, key)
	}
	if err := quick.Check(round, nil); err != nil {
		t.Fatal(err)
	}
	mismatch := func(kind string, q uint64, key []byte) bool {
		c := EncodeCursor(kind, q, key)
		_, e1 := DecodeCursor(kind+"x", q, c)
		_, e2 := DecodeCursor(kind, q+1, c)
		return errors.Is(e1, errs.Validation) && errors.Is(e2, errs.Validation)
	}
	if err := quick.Check(mismatch, nil); err != nil {
		t.Fatal(err)
	}
	random := func(s string) bool {
		_, err := DecodeCursor("find", 1, s)
		return errors.Is(err, errs.Validation)
	}
	if err := quick.Check(random, nil); err != nil {
		t.Fatal(err)
	}
}
