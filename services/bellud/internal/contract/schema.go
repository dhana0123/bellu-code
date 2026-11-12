package contract

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"
)

//go:embed schemas.json
var schemasJSON []byte

// Schemas is the per-operation response schema set generated from packages/protocol
// (script/gen-contract-schemas.ts).
type Schemas struct {
	Operations map[string]struct {
		Responses map[string]map[string]any `json:"responses"` // status -> content type -> schema
	} `json:"operations"`
	Components map[string]any `json:"components"`
}

var (
	embeddedOnce sync.Once
	embedded     *Schemas
	embeddedErr  error
)

// Embedded returns the build-time embedded schemas.
func Embedded() (*Schemas, error) {
	embeddedOnce.Do(func() {
		var s Schemas
		if err := json.Unmarshal(schemasJSON, &s); err != nil {
			embeddedErr = err
			return
		}
		embedded = &s
	})
	return embedded, embeddedErr
}

// Response returns the schema declared for operation op, status and media type.
func (s *Schemas) Response(op string, status int, mediaType string) (any, bool) {
	o, ok := s.Operations[op]
	if !ok {
		return nil, false
	}
	c, ok := o.Responses[fmt.Sprint(status)]
	if !ok {
		return nil, false
	}
	sc, ok := c[mediaType]
	return sc, ok
}

// Validate checks value (decoded JSON) against schema and returns error messages with JSON-pointer paths.
// With placeholders true, strings of the form "<NAME>" (as recorded in fixtures) match any schema.
func (s *Schemas) Validate(schema, value any, placeholders bool) []string {
	v := &validator{s: s, ph: placeholders}
	v.check(schema, value, "")
	return v.errs
}

type validator struct {
	s     *Schemas
	ph    bool
	errs  []string
	depth int
}

var placeholderRe = regexp.MustCompile(`^<[A-Za-z0-9_:.\-]+>$`)

func (v *validator) fail(path, format string, args ...any) {
	if path == "" {
		path = "/"
	}
	v.errs = append(v.errs, path+": "+fmt.Sprintf(format, args...))
}

// sub validates in an isolated error scope and reports whether it passed.
func (v *validator) sub(schema, value any, path string) ([]string, bool) {
	c := &validator{s: v.s, ph: v.ph, depth: v.depth}
	c.check(schema, value, path)
	return c.errs, len(c.errs) == 0
}

func typeOf(x any) string {
	switch t := x.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case float64:
		if t == math.Trunc(t) {
			return "integer"
		}
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return fmt.Sprintf("%T", x)
}

func typeMatches(want, got string) bool {
	return want == got || (want == "number" && got == "integer")
}

func (v *validator) check(schema, value any, path string) {
	v.depth++
	defer func() { v.depth-- }()
	if v.depth > 64 {
		v.fail(path, "schema nesting too deep")
		return
	}
	switch sc := schema.(type) {
	case bool:
		if !sc {
			v.fail(path, "schema forbids any value")
		}
		return
	case map[string]any:
		v.checkObj(sc, value, path)
	case nil:
	default:
		v.fail(path, "unsupported schema %T", schema)
	}
}

func (v *validator) checkObj(sc map[string]any, value any, path string) {
	if ref, ok := sc["$ref"].(string); ok {
		const prefix = "#/components/schemas/"
		name := strings.TrimPrefix(ref, prefix)
		target, found := v.s.Components[name]
		if !strings.HasPrefix(ref, prefix) || !found {
			v.fail(path, "unresolved $ref %s", ref)
			return
		}
		v.check(target, value, path)
		return
	}
	if str, ok := value.(string); ok && v.ph && placeholderRe.MatchString(str) {
		return
	}
	if value == nil {
		if n, _ := sc["nullable"].(bool); n {
			return
		}
	}
	if types, ok := sc["type"]; ok {
		var list []string
		switch t := types.(type) {
		case string:
			list = []string{t}
		case []any:
			for _, e := range t {
				if s, ok := e.(string); ok {
					list = append(list, s)
				}
			}
		}
		got := typeOf(value)
		match := false
		for _, w := range list {
			if typeMatches(w, got) {
				match = true
			}
		}
		if len(list) > 0 && !match {
			v.fail(path, "expected type %s, got %s", strings.Join(list, "|"), got)
			return
		}
	}
	if c, ok := sc["const"]; ok && !jsonEqual(c, value) {
		v.fail(path, "expected const %v, got %v", c, value)
	}
	if en, ok := sc["enum"].([]any); ok {
		found := false
		for _, e := range en {
			if jsonEqual(e, value) {
				found = true
			}
		}
		if !found {
			v.fail(path, "value %v not in enum", value)
		}
	}
	if all, ok := sc["allOf"].([]any); ok {
		for _, s := range all {
			v.check(s, value, path)
		}
	}
	if any_, ok := sc["anyOf"].([]any); ok {
		v.union(any_, value, path, "anyOf")
	}
	if one, ok := sc["oneOf"].([]any); ok {
		v.union(one, value, path, "oneOf")
	}
	switch val := value.(type) {
	case float64:
		if m, ok := sc["minimum"].(float64); ok && val < m {
			v.fail(path, "%v below minimum %v", val, m)
		}
		if m, ok := sc["maximum"].(float64); ok && val > m {
			v.fail(path, "%v above maximum %v", val, m)
		}
	case string:
		if cs, ok := sc["contentSchema"]; ok {
			var inner any
			if err := json.Unmarshal([]byte(val), &inner); err != nil {
				v.fail(path, "content is not valid JSON: %v", err)
			} else {
				v.check(cs, inner, path+"(content)")
			}
		}
	case []any:
		if items, ok := sc["items"]; ok {
			for i, e := range val {
				v.check(items, e, fmt.Sprintf("%s/%d", path, i))
			}
		}
	case map[string]any:
		props, _ := sc["properties"].(map[string]any)
		if req, ok := sc["required"].([]any); ok {
			for _, r := range req {
				if k, ok := r.(string); ok {
					if _, present := val[k]; !present {
						v.fail(path, "missing required property %q", k)
					}
				}
			}
		}
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			p := path + "/" + k
			if ps, ok := props[k]; ok {
				v.check(ps, val[k], p)
				continue
			}
			switch ap := sc["additionalProperties"].(type) {
			case bool:
				if !ap {
					v.fail(path, "unexpected property %q", k)
				}
			case map[string]any:
				v.check(ap, val[k], p)
			}
		}
	}
}

func (v *validator) union(list []any, value any, path, kw string) {
	n := 0
	var first []string
	for _, s := range list {
		errs, ok := v.sub(s, value, path)
		if ok {
			n++
		} else if first == nil {
			first = errs
		}
	}
	if n == 0 {
		msg := "no " + kw + " branch matched"
		if len(first) > 0 {
			msg += " (first branch: " + first[0] + ")"
		}
		v.fail(path, "%s", msg)
	}
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
