package facade

import (
	"errors"
	"testing"

	"pgregory.net/rapid"
)

// Feature: go-server-bellu-graph, Property 9: Identity hash determinism
// **Validates: Requirements 13.1, 13.2, 13.3, 13.4**

func ihKind() *rapid.Generator[string] {
	return rapid.SampledFrom(Kinds())
}

func ihValue() *rapid.Generator[string] {
	return rapid.StringN(1, 12, -1)
}

// ihIdentity draws a non-empty value for every identity attribute of kind.
func ihIdentity(t *rapid.T, kind string) map[string]string {
	keys, _ := IdentityAttributes(kind)
	m := make(map[string]string, len(keys))
	for _, k := range keys {
		m[k] = ihValue().Draw(t, "val_"+k)
	}
	return m
}

// ihShuffledCopy rebuilds m inserting entries in a random order, merging extra.
func ihShuffledCopy(t *rapid.T, m, extra map[string]string) map[string]string {
	type kv struct{ k, v string }
	var all []kv
	for k, v := range m {
		all = append(all, kv{k, v})
	}
	for k, v := range extra {
		all = append(all, kv{k, v})
	}
	out := make(map[string]string, len(all))
	for len(all) > 0 {
		i := rapid.IntRange(0, len(all)-1).Draw(t, "pick")
		out[all[i].k] = all[i].v
		all = append(all[:i], all[i+1:]...)
	}
	return out
}

func TestIdentityHashOrderAndExtraAttrsInvariant(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		kind := ihKind().Draw(t, "kind")
		id := ihIdentity(t, kind)
		extra := map[string]string{}
		for _, k := range rapid.SliceOfN(rapid.StringN(1, 8, -1), 0, 5).Draw(t, "extraKeys") {
			if _, isID := id[k]; !isID {
				extra["x_"+k] = ihValue().Draw(t, "extraVal")
			}
		}
		want, err := Hash(kind, id)
		if err != nil {
			t.Fatalf("Hash: %v", err)
		}
		got, err := Hash(kind, ihShuffledCopy(t, id, extra))
		if err != nil {
			t.Fatalf("Hash with extras: %v", err)
		}
		if got != want {
			t.Fatalf("hash changed: %q vs %q", got, want)
		}
	})
}

func TestIdentityHashDistinguishes(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		kind := ihKind().Draw(t, "kind")
		a := ihIdentity(t, kind)
		keys, _ := IdentityAttributes(kind)

		// Differing identity value => different ID.
		k := rapid.SampledFrom(keys).Draw(t, "key")
		b := ihShuffledCopy(t, a, nil)
		b[k] = ihValue().Draw(t, "other")
		ha, _ := Hash(kind, a)
		hb, _ := Hash(kind, b)
		if (a[k] == b[k]) != (ha == hb) {
			t.Fatalf("a[%s]=%q b[%s]=%q but hashes %q / %q", k, a[k], k, b[k], ha, hb)
		}

		// Different kind with the same attribute values => different ID.
		other := ihKind().Draw(t, "otherKind")
		if other == kind {
			return
		}
		oa := ihIdentity(t, other)
		for kk, v := range a {
			if _, ok := oa[kk]; ok {
				oa[kk] = v
			}
		}
		ho, err := Hash(other, oa)
		if err != nil {
			t.Fatalf("Hash(other): %v", err)
		}
		if ho == ha {
			t.Fatalf("kinds %q and %q collide: %q", kind, other, ho)
		}
	})
}

func TestIdentityHashMissingOrEmptyIsValidation(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		kind := ihKind().Draw(t, "kind")
		attrs := ihIdentity(t, kind)
		keys, _ := IdentityAttributes(kind)
		k := rapid.SampledFrom(keys).Draw(t, "key")
		if rapid.Bool().Draw(t, "empty") {
			attrs[k] = ""
		} else {
			delete(attrs, k)
		}
		if _, err := Hash(kind, attrs); !errors.Is(err, ErrValidation) {
			t.Fatalf("want ErrValidation, got %v", err)
		}
	})
}

func TestIdentityHashUnknownKind(t *testing.T) {
	if _, err := Hash("no_such_kind", map[string]string{"id": "x"}); !errors.Is(err, ErrValidation) {
		t.Fatalf("want ErrValidation, got %v", err)
	}
}

// TestIdentityHashGolden pins IDs so they stay stable across platforms and releases.
func TestIdentityHashGolden(t *testing.T) {
	cases := []struct {
		kind  string
		attrs map[string]string
		want  EntityID
	}{
		{"host", map[string]string{"hostname": "web-1"}, "host:8aabbfeea7ae96362d5205b88e9c1610"},
		{"container", map[string]string{"id": "abc123"}, "container:fcb78a1aa1ec323b638aba0da3bcf9c3"},
		{"listening_port", map[string]string{"host": "web-1", "protocol": "tcp", "address": "0.0.0.0", "port": "443"}, "listening_port:eb90dff5ff9089d9609472e3044b7bae"},
	}
	for _, c := range cases {
		got, err := Hash(c.kind, c.attrs)
		if err != nil {
			t.Fatalf("%s: %v", c.kind, err)
		}
		if got != c.want {
			t.Errorf("%s: got %q want %q", c.kind, got, c.want)
		}
	}
}
