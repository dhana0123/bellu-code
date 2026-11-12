package codec

import (
	"bytes"
	"math"
	"testing"

	"pgregory.net/rapid"
)

type unsupportedStruct struct{ X int }

// genAny draws a Go value from supported and unsupported types and reports
// whether FromAny is expected to accept it.
func genAny() *rapid.Generator[struct {
	V  any
	OK bool
}] {
	type pair = struct {
		V  any
		OK bool
	}
	ok := func(g *rapid.Generator[any]) *rapid.Generator[pair] {
		return rapid.Map(g, func(v any) pair { return pair{v, true} })
	}
	bad := func(g *rapid.Generator[any]) *rapid.Generator[pair] {
		return rapid.Map(g, func(v any) pair { return pair{v, false} })
	}
	return rapid.OneOf(
		ok(rapid.Map(genStr(), func(v string) any { return v })),
		ok(rapid.Map(rapid.Bool(), func(v bool) any { return v })),
		ok(rapid.Map(rapid.Int(), func(v int) any { return v })),
		ok(rapid.Map(rapid.Int8(), func(v int8) any { return v })),
		ok(rapid.Map(rapid.Int16(), func(v int16) any { return v })),
		ok(rapid.Map(rapid.Int32(), func(v int32) any { return v })),
		ok(rapid.Map(rapid.Int64(), func(v int64) any { return v })),
		ok(rapid.Map(rapid.Uint8(), func(v uint8) any { return v })),
		ok(rapid.Map(rapid.Uint16(), func(v uint16) any { return v })),
		ok(rapid.Map(rapid.Uint32(), func(v uint32) any { return v })),
		ok(rapid.Map(rapid.Uint64Range(0, math.MaxInt64), func(v uint64) any { return v })),
		ok(rapid.Map(rapid.Float64(), func(v float64) any { return v })),
		ok(rapid.Map(rapid.Float32(), func(v float32) any { return v })),
		ok(rapid.Map(rapid.SliceOfN(genStr(), 0, 4), func(v []string) any { return v })),
		ok(rapid.Map(rapid.SliceOfN(genStr(), 0, 4), func(v []string) any {
			l := make([]any, len(v))
			for i, s := range v {
				l[i] = s
			}
			return l
		})),
		bad(rapid.Map(rapid.Uint64Range(math.MaxInt64+1, math.MaxUint64), func(v uint64) any { return v })),
		bad(rapid.SampledFrom([]any{math.NaN(), math.Inf(1), math.Inf(-1), float32(math.Inf(1)), nil})),
		bad(rapid.Map(rapid.Int(), func(v int) any { return []any{"a", v} })),
		bad(rapid.Map(rapid.Int(), func(v int) any { return []int{v} })),
		bad(rapid.Map(rapid.Int(), func(v int) any { return unsupportedStruct{v} })),
		bad(rapid.Map(genStr(), func(v string) any { return map[string]any{v: 1} })),
		bad(rapid.Map(rapid.Float64(), func(v float64) any { return &v })),
	)
}

// Feature: bellu-graph-native, Property 2: Attribute values round trip
// Validates: Requirements 5.12
func TestPropertyAttributeValuesRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		p := genAny().Draw(t, "value")
		v, err := FromAny("k", p.V)
		if (err == nil) != p.OK {
			t.Fatalf("FromAny(%#v) err = %v, want success=%v", p.V, err, p.OK)
		}
		if err != nil {
			return
		}
		got, err := DecodeMap(EncodeMap(map[string]Value{"k": v}))
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !got["k"].Equal(v) {
			t.Fatalf("round trip: got %#v want %#v", got["k"], v)
		}
	})
}

// Feature: bellu-graph-native, Property 2: Attribute values round trip (canonical bytes across map orders)
// Validates: Requirements 5.12
func TestPropertyCanonicalBytesIndependentOfMapOrder(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		src := genValueMap().Draw(t, "map")
		keys := make([]string, 0, len(src))
		for k := range src {
			keys = append(keys, k)
		}
		perm := rapid.Permutation(keys).Draw(t, "order")
		m2 := make(map[string]Value, len(src))
		for _, k := range perm {
			m2[k] = src[k]
		}
		if !bytes.Equal(EncodeMap(src), EncodeMap(m2)) {
			t.Fatal("canonical bytes differ across insertion orders")
		}
	})
}
