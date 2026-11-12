package redact

import (
	"reflect"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

// Feature: go-server-bellu-graph, Property 5: Scrub idempotence
// **Validates: Requirements 15.2, 15.3, 15.4, 15.5**

var (
	genKeys    = []string{"name", "note", "data", "environment", "variables", "configuration", "api_key", "Password", "x-token", "items", "meta", "labels"}
	genSecrets = []string{
		"AKIAABCDEFGHIJKLMNOP",
		"ghp_" + strings.Repeat("a", 36),
		"Bearer abcdefghijklmnopqrstuvwxyz",
	}
)

func genString() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		s := rapid.StringMatching(`[a-z ]{0,8}`).Draw(t, "plain")
		if rapid.Bool().Draw(t, "secret") {
			s += " " + rapid.SampledFrom(genSecrets).Draw(t, "which") + " " + s
		}
		return s
	})
}

func genValue(depth int) *rapid.Generator[any] {
	return rapid.Custom(func(t *rapid.T) any {
		max := 7
		if depth <= 0 {
			max = 3
		}
		switch rapid.IntRange(0, max).Draw(t, "kind") {
		case 0:
			return genString().Draw(t, "s")
		case 1:
			return rapid.IntRange(-5, 5).Draw(t, "i")
		case 2:
			return rapid.Bool().Draw(t, "b")
		case 3:
			return rapid.SliceOfN(genString(), 0, 3).Draw(t, "ss")
		case 4:
			return rapid.SliceOfN(genValue(depth-1), 0, 3).Draw(t, "sa")
		case 5:
			return rapid.MapOfN(rapid.SampledFrom(genKeys), genString(), 0, 3).Draw(t, "ms")
		default:
			return genMap(depth-1).Draw(t, "m")
		}
	})
}

func genMap(depth int) *rapid.Generator[map[string]any] {
	return rapid.MapOfN(rapid.SampledFrom(genKeys), genValue(depth), 0, 4)
}

func genBatch() *rapid.Generator[batch.Batch] {
	ident := rapid.MapOfN(rapid.SampledFrom([]string{"name", "ns", "id"}), genString(), 1, 3)
	ent := rapid.Custom(func(t *rapid.T) batch.Entity {
		return batch.Entity{
			Type:       rapid.SampledFrom([]string{"repo", "pod", "host"}).Draw(t, "type"),
			Identity:   ident.Draw(t, "ident"),
			Attributes: genMap(3).Draw(t, "attrs"),
		}
	})
	rel := rapid.Custom(func(t *rapid.T) batch.Relation {
		return batch.Relation{
			Type:       "has",
			From:       rapid.StringMatching(`[a-z]{1,6}`).Draw(t, "from"),
			To:         rapid.StringMatching(`[a-z]{1,6}`).Draw(t, "to"),
			Attributes: genMap(2).Draw(t, "rattrs"),
		}
	})
	return rapid.Custom(func(t *rapid.T) batch.Batch {
		return batch.Batch{
			Collector: "git",
			Entities:  rapid.SliceOfN(ent, 0, 4).Draw(t, "entities"),
			Relations: rapid.SliceOfN(rel, 0, 4).Draw(t, "relations"),
		}
	})
}

func deepCopy(v any) any {
	switch x := v.(type) {
	case []string:
		return append(make([]string, 0, len(x)), x...)
	case []any:
		o := make([]any, len(x))
		for i, e := range x {
			o[i] = deepCopy(e)
		}
		return o
	case map[string]any:
		return copyMap(x)
	case map[string]string:
		o := make(map[string]string, len(x))
		for k, s := range x {
			o[k] = s
		}
		return o
	}
	return v
}

func copyMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	o := make(map[string]any, len(m))
	for k, v := range m {
		o[k] = deepCopy(v)
	}
	return o
}

func copyBatch(b batch.Batch) batch.Batch {
	o := batch.Batch{Collector: b.Collector}
	if b.Entities != nil {
		o.Entities = []batch.Entity{}
	}
	if b.Relations != nil {
		o.Relations = []batch.Relation{}
	}
	for _, e := range b.Entities {
		o.Entities = append(o.Entities, batch.Entity{Type: e.Type, Identity: cloneIdentity(e.Identity), Attributes: copyMap(e.Attributes)})
	}
	for _, r := range b.Relations {
		o.Relations = append(o.Relations, batch.Relation{Type: r.Type, From: r.From, To: r.To, Attributes: copyMap(r.Attributes)})
	}
	return o
}

// sameShape reports whether a and b have the same field names and container sizes.
func sameShape(a, b any) bool {
	// A key/path rule replaces the whole value with a marker; the field name stays.
	if s, ok := b.(string); ok && isMarker(s) {
		return true
	}
	switch x := a.(type) {
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			w, ok := y[k]
			if !ok || !sameShape(v, w) {
				return false
			}
		}
		return true
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !sameShape(x[i], y[i]) {
				return false
			}
		}
		return true
	case []string:
		y, ok := b.([]string)
		return ok && len(x) == len(y)
	case map[string]string:
		y, ok := b.(map[string]string)
		if !ok || len(x) != len(y) {
			return false
		}
		for k := range x {
			if _, ok := y[k]; !ok {
				return false
			}
		}
		return true
	}
	// Leaf: a sensitive leaf may become a marker string; others keep their type.
	if _, isStr := b.(string); isStr {
		return true
	}
	return reflect.TypeOf(a) == reflect.TypeOf(b)
}

func TestPropertyScrubIdempotence(t *testing.T) {
	g := New()
	rapid.Check(t, func(t *rapid.T) {
		in := genBatch().Draw(t, "batch")
		before := copyBatch(in)

		once := g.Scrub(in)
		if !reflect.DeepEqual(in, before) {
			t.Fatalf("input mutated\n%#v\n%#v", in, before)
		}
		twice := g.Scrub(once)
		if !reflect.DeepEqual(once, twice) {
			t.Fatalf("not idempotent:\nonce:  %#v\ntwice: %#v", once, twice)
		}
		if once.Collector != in.Collector || len(once.Entities) != len(in.Entities) || len(once.Relations) != len(in.Relations) {
			t.Fatalf("collector or counts changed")
		}
		for i, e := range in.Entities {
			o := once.Entities[i]
			if o.Type != e.Type || !reflect.DeepEqual(o.Identity, e.Identity) {
				t.Fatalf("entity %d identity changed", i)
			}
			if !sameShape(e.Attributes, o.Attributes) {
				t.Fatalf("entity %d field names changed", i)
			}
		}
		for i, r := range in.Relations {
			o := once.Relations[i]
			if o.Type != r.Type || o.From != r.From || o.To != r.To {
				t.Fatalf("relation %d ids changed", i)
			}
			if !sameShape(r.Attributes, o.Attributes) {
				t.Fatalf("relation %d field names changed", i)
			}
		}
	})
}
