package facade

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/model"
)

// attrKVs converts collector attributes to engine key-values, sorted by key.
// Keys in skip are dropped (identity attributes are carried separately).
func attrKVs(attrs map[string]any) ([]model.KeyValue, error) {
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]model.KeyValue, 0, len(keys))
	for _, k := range keys {
		if k == "" {
			return nil, fmt.Errorf("%w: empty attribute key", ErrValidation)
		}
		v, err := toValue(attrs[k])
		if err != nil {
			return nil, fmt.Errorf("%w: attribute %q: %v", ErrValidation, k, err)
		}
		out = append(out, model.KeyValue{Key: k, Value: v})
	}
	return out, nil
}

func toValue(x any) (model.Value, error) {
	switch v := x.(type) {
	case string:
		return model.StringValue(v), nil
	case bool:
		return model.BoolValue(v), nil
	case int:
		return model.IntValue(int64(v)), nil
	case int8:
		return model.IntValue(int64(v)), nil
	case int16:
		return model.IntValue(int64(v)), nil
	case int32:
		return model.IntValue(int64(v)), nil
	case int64:
		return model.IntValue(v), nil
	case uint8:
		return model.IntValue(int64(v)), nil
	case uint16:
		return model.IntValue(int64(v)), nil
	case uint32:
		return model.IntValue(int64(v)), nil
	case uint:
		if uint64(v) > 1<<63-1 {
			return model.Value{}, fmt.Errorf("integer %d overflows int64", v)
		}
		return model.IntValue(int64(v)), nil
	case uint64:
		if v > 1<<63-1 {
			return model.Value{}, fmt.Errorf("integer %d overflows int64", v)
		}
		return model.IntValue(int64(v)), nil
	case float32:
		return model.DoubleValue(float64(v)), nil
	case float64:
		return model.DoubleValue(v), nil
	case []string:
		out := make([]model.Value, len(v))
		for i, s := range v {
			out[i] = model.StringValue(s)
		}
		return model.ArrayValue(out), nil
	case []any:
		out := make([]model.Value, len(v))
		for i, e := range v {
			ev, err := toValue(e)
			if err != nil {
				return model.Value{}, err
			}
			out[i] = ev
		}
		return model.ArrayValue(out), nil
	case map[string]string:
		m := make(map[string]any, len(v))
		for k, s := range v {
			m[k] = s
		}
		return toValue(m)
	case map[string]any:
		kvs, err := attrKVs(v)
		if err != nil {
			return model.Value{}, err
		}
		return model.KvlistValue(kvs), nil
	case nil:
		return model.Value{}, fmt.Errorf("nil value")
	}
	// Any other shape (structs, typed slices, time.Time) goes through its JSON
	// form; the result only contains the types handled above.
	b, err := json.Marshal(x)
	if err != nil {
		return model.Value{}, err
	}
	var norm any
	if err := json.Unmarshal(b, &norm); err != nil {
		return model.Value{}, err
	}
	if _, again := norm.(float64); again {
		// json numbers are float64; keep integral ones integral.
		if f := norm.(float64); f == float64(int64(f)) {
			return model.IntValue(int64(f)), nil
		}
	}
	return toValue(norm)
}

// valueAny renders a Value as a JSON-ready Go value.
func valueAny(v model.Value) any {
	switch v.Kind() {
	case model.KindString:
		return v.Str()
	case model.KindInt:
		return v.Int()
	case model.KindDouble:
		return v.Double()
	case model.KindBool:
		return v.Bool()
	case model.KindArray:
		out := make([]any, len(v.Array()))
		for i, e := range v.Array() {
			out[i] = valueAny(e)
		}
		return out
	case model.KindKvlist:
		return kvMap(v.Kvlist())
	}
	return nil
}

func kvMap(kvs []model.KeyValue) map[string]any {
	out := make(map[string]any, len(kvs))
	for _, kv := range kvs {
		out[kv.Key] = valueAny(kv.Value)
	}
	return out
}

// normalize validates paging and returns the effective page size.
func (p Paging) normalize() (int, error) {
	switch {
	case p.PageSize == 0:
		return DefaultPageSize, nil
	case p.PageSize < 1 || p.PageSize > MaxPageSize:
		return 0, fmt.Errorf("%w: page size %d is outside the allowed range 1 to %d", ErrValidation, p.PageSize, MaxPageSize)
	}
	return p.PageSize, nil
}

// offset decodes an offset cursor.
func (p Paging) offset() (int, error) {
	if p.Cursor == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(p.Cursor)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%w: invalid cursor %q", ErrValidation, p.Cursor)
	}
	return n, nil
}

// paginate slices items by an offset cursor.
func paginate[T any](items []T, p Paging) (Page[T], error) {
	limit, err := p.normalize()
	if err != nil {
		return Page[T]{}, err
	}
	off, err := p.offset()
	if err != nil {
		return Page[T]{}, err
	}
	pg := Page[T]{Items: []T{}, Total: len(items), Limit: limit}
	if off >= len(items) {
		return pg, nil
	}
	end := min(off+limit, len(items))
	pg.Items = items[off:end]
	if end < len(items) {
		pg.Truncated = true
		pg.NextCursor = strconv.Itoa(end)
	}
	return pg, nil
}
