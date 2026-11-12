// Package codec implements the Bellu Graph Engine's value model, canonical
// map encoding, event envelope and Snapshot records.
package codec

import (
	"encoding/binary"
	"fmt"
	"math"
	"sort"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
)

// Tag identifies the type of a Value.
type Tag byte

const (
	TagString Tag = 0x01
	TagBool   Tag = 0x02
	TagInt    Tag = 0x03
	TagFloat  Tag = 0x04
	TagList   Tag = 0x05
)

// Value is a typed attribute value. Only the field selected by T is meaningful.
type Value struct {
	T Tag
	S string
	B bool
	I int64
	F float64
	L []string
}

// FromAny converts a caller value to a Value. name is used in error messages.
func FromAny(name string, v any) (Value, error) {
	switch x := v.(type) {
	case string:
		return Value{T: TagString, S: x}, nil
	case bool:
		return Value{T: TagBool, B: x}, nil
	case int:
		return Value{T: TagInt, I: int64(x)}, nil
	case int8:
		return Value{T: TagInt, I: int64(x)}, nil
	case int16:
		return Value{T: TagInt, I: int64(x)}, nil
	case int32:
		return Value{T: TagInt, I: int64(x)}, nil
	case int64:
		return Value{T: TagInt, I: x}, nil
	case uint:
		return fromUint(name, uint64(x))
	case uint8:
		return Value{T: TagInt, I: int64(x)}, nil
	case uint16:
		return Value{T: TagInt, I: int64(x)}, nil
	case uint32:
		return Value{T: TagInt, I: int64(x)}, nil
	case uint64:
		return fromUint(name, x)
	case uintptr:
		return fromUint(name, uint64(x))
	case float32:
		return fromFloat(name, float64(x))
	case float64:
		return fromFloat(name, x)
	case []string:
		return Value{T: TagList, L: append([]string{}, x...)}, nil
	case []any:
		l := make([]string, len(x))
		for i, e := range x {
			s, ok := e.(string)
			if !ok {
				return Value{}, fmt.Errorf("%w: attribute %q: list element %d is %T, want string", errs.Validation, name, i, e)
			}
			l[i] = s
		}
		return Value{T: TagList, L: l}, nil
	}
	return Value{}, fmt.Errorf("%w: attribute %q: unsupported value type %T", errs.Validation, name, v)
}

func fromUint(name string, u uint64) (Value, error) {
	if u > math.MaxInt64 {
		return Value{}, fmt.Errorf("%w: attribute %q: integer %d exceeds int64", errs.Validation, name, u)
	}
	return Value{T: TagInt, I: int64(u)}, nil
}

func fromFloat(name string, f float64) (Value, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return Value{}, fmt.Errorf("%w: attribute %q: non-finite float", errs.Validation, name)
	}
	if f == 0 {
		f = 0 // normalizes -0 to +0
	}
	return Value{T: TagFloat, F: f}, nil
}

// ToAny converts a Value back to string, bool, int64, float64 or []string.
func (v Value) ToAny() any {
	switch v.T {
	case TagString:
		return v.S
	case TagBool:
		return v.B
	case TagInt:
		return v.I
	case TagFloat:
		return v.F
	case TagList:
		return append([]string{}, v.L...)
	}
	return nil
}

// Equal reports whether two Values have the same type and content.
func (v Value) Equal(o Value) bool {
	if v.T != o.T {
		return false
	}
	switch v.T {
	case TagString:
		return v.S == o.S
	case TagBool:
		return v.B == o.B
	case TagInt:
		return v.I == o.I
	case TagFloat:
		return math.Float64bits(v.F) == math.Float64bits(o.F)
	case TagList:
		if len(v.L) != len(o.L) {
			return false
		}
		for i := range v.L {
			if v.L[i] != o.L[i] {
				return false
			}
		}
		return true
	}
	return false
}

// --- primitive encoding ---

func appendU32(b []byte, n uint32) []byte { return binary.BigEndian.AppendUint32(b, n) }
func appendU64(b []byte, n uint64) []byte { return binary.BigEndian.AppendUint64(b, n) }
func appendStr(b []byte, s string) []byte { return append(appendU32(b, uint32(len(s))), s...) }

// AppendValue appends enc(v) = tag || payload.
func AppendValue(b []byte, v Value) []byte {
	b = append(b, byte(v.T))
	switch v.T {
	case TagString:
		b = appendStr(b, v.S)
	case TagBool:
		if v.B {
			b = append(b, 1)
		} else {
			b = append(b, 0)
		}
	case TagInt:
		b = appendU64(b, uint64(v.I))
	case TagFloat:
		f := v.F
		if f == 0 {
			f = 0
		}
		b = appendU64(b, math.Float64bits(f))
	case TagList:
		b = appendU32(b, uint32(len(v.L)))
		for _, e := range v.L {
			b = appendStr(b, e)
		}
	}
	return b
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys) // bytewise order for Go strings
	return keys
}

// AppendMap appends the canonical map encoding of m.
func AppendMap(b []byte, m map[string]Value) []byte {
	b = appendU32(b, uint32(len(m)))
	for _, k := range sortedKeys(m) {
		b = appendStr(b, k)
		b = AppendValue(b, m[k])
	}
	return b
}

// EncodeMap returns the canonical map encoding of m.
func EncodeMap(m map[string]Value) []byte { return AppendMap(nil, m) }

// DecodeMap decodes a canonical map encoding that spans all of b.
func DecodeMap(b []byte) (map[string]Value, error) {
	r := &reader{b: b}
	m := r.valueMap()
	if r.err == nil && len(r.b) != 0 {
		r.fail("trailing bytes")
	}
	if r.err != nil {
		return nil, r.err
	}
	return m, nil
}

// --- reader ---

type reader struct {
	b   []byte
	err error
}

func (r *reader) fail(msg string) {
	if r.err == nil {
		r.err = fmt.Errorf("%w: codec: %s", errs.Corrupt, msg)
	}
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.b) {
		r.fail("truncated")
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) u8() byte {
	if b := r.take(1); b != nil {
		return b[0]
	}
	return 0
}

func (r *reader) u32() uint32 {
	if b := r.take(4); b != nil {
		return binary.BigEndian.Uint32(b)
	}
	return 0
}

func (r *reader) u64() uint64 {
	if b := r.take(8); b != nil {
		return binary.BigEndian.Uint64(b)
	}
	return 0
}

func (r *reader) str() string {
	n := r.u32()
	if uint64(n) > uint64(len(r.b)) {
		r.fail("string length exceeds input")
		return ""
	}
	return string(r.take(int(n)))
}

// count reads an element count and checks it against the remaining input,
// given the minimum encoded size of one element.
func (r *reader) count(minElem int) int {
	n := r.u32()
	if r.err == nil && uint64(n)*uint64(minElem) > uint64(len(r.b)) {
		r.fail("count exceeds input")
		return 0
	}
	return int(n)
}

func (r *reader) value() Value {
	t := Tag(r.u8())
	v := Value{T: t}
	switch t {
	case TagString:
		v.S = r.str()
	case TagBool:
		switch r.u8() {
		case 0:
		case 1:
			v.B = true
		default:
			r.fail("bool byte not 0 or 1")
		}
	case TagInt:
		v.I = int64(r.u64())
	case TagFloat:
		v.F = math.Float64frombits(r.u64())
		if math.IsNaN(v.F) || math.IsInf(v.F, 0) {
			r.fail("non-finite float")
		}
	case TagList:
		n := r.count(4)
		v.L = make([]string, 0, n)
		for i := 0; i < n && r.err == nil; i++ {
			v.L = append(v.L, r.str())
		}
	default:
		r.fail(fmt.Sprintf("unknown value tag 0x%02x", byte(t)))
	}
	return v
}

func (r *reader) valueMap() map[string]Value {
	n := r.count(5)
	m := make(map[string]Value, n)
	prev := ""
	for i := 0; i < n && r.err == nil; i++ {
		k := r.str()
		if i > 0 && k <= prev {
			r.fail("map keys not strictly sorted")
		}
		prev = k
		m[k] = r.value()
	}
	return m
}

func appendStrList(b []byte, l []string) []byte {
	b = appendU32(b, uint32(len(l)))
	for _, s := range l {
		b = appendStr(b, s)
	}
	return b
}

func (r *reader) strList() []string {
	n := r.count(4)
	l := make([]string, 0, n)
	for i := 0; i < n && r.err == nil; i++ {
		l = append(l, r.str())
	}
	return l
}

func appendStrMap(b []byte, m map[string]string) []byte {
	b = appendU32(b, uint32(len(m)))
	for _, k := range sortedKeys(m) {
		b = appendStr(appendStr(b, k), m[k])
	}
	return b
}

func (r *reader) strMap() map[string]string {
	n := r.count(8)
	m := make(map[string]string, n)
	prev := ""
	for i := 0; i < n && r.err == nil; i++ {
		k := r.str()
		if i > 0 && k <= prev {
			r.fail("map keys not strictly sorted")
		}
		prev = k
		m[k] = r.str()
	}
	return m
}

func stringValues(m map[string]string) map[string]Value {
	out := make(map[string]Value, len(m))
	for k, v := range m {
		out[k] = Value{T: TagString, S: v}
	}
	return out
}
