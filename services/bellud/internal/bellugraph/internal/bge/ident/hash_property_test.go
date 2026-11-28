package ident

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
)

func drawKind(t *rapid.T) (string, []string) {
	kind := rapid.SampledFrom(Kinds()).Draw(t, "kind")
	keys, ok := IdentityAttributes(kind)
	if !ok || len(keys) == 0 {
		t.Fatalf("registered kind %q has no identity attributes", kind)
	}
	return kind, keys
}

func drawIdentity(t *rapid.T, keys []string) map[string]string {
	id := make(map[string]string, len(keys))
	for _, k := range keys {
		id[k] = rapid.StringN(1, 24, -1).Draw(t, "id."+k)
	}
	return id
}

// Feature: aws-relationship-registry, Property 5: Entity_ID depends only on kind and identity attributes
//
// **Validates: Requirements 3.4, 3.7, 3.8**
func TestPropertyEntityIDStability(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		kind, keys := drawKind(t)
		id := drawIdentity(t, keys)
		want, err := Hash(kind, id)
		if err != nil {
			t.Fatalf("Hash(%s, %v): %v", kind, id, err)
		}

		// Adding or changing non-identity attributes leaves the hash unchanged.
		withExtra := make(map[string]string, len(id))
		for k, v := range id {
			withExtra[k] = v
		}
		extras := rapid.SliceOfN(rapid.StringMatching(`[a-z_]{1,10}`), 0, 6).Draw(t, "extraNames")
		for _, n := range extras {
			if slices.Contains(keys, n) {
				continue
			}
			withExtra[n] = rapid.String().Draw(t, "extra."+n)
		}
		got, err := Hash(kind, withExtra)
		if err != nil || got != want {
			t.Fatalf("extras changed hash: got %q, %v want %q", got, err, want)
		}

		// Hash is deterministic and prefixed by the kind.
		again, _ := Hash(kind, id)
		if again != want || !strings.HasPrefix(want, kind+":") {
			t.Fatalf("unstable or unprefixed id %q / %q", want, again)
		}

		// Changing one identity attribute value changes the hash.
		k := rapid.SampledFrom(keys).Draw(t, "changed")
		changed := make(map[string]string, len(id))
		for kk, v := range id {
			changed[kk] = v
		}
		changed[k] = id[k] + "x"
		if other, err := Hash(kind, changed); err != nil || other == want {
			t.Fatalf("changing %q kept hash: %q, %v", k, other, err)
		}

		// A missing or empty identity attribute is a validation error naming it.
		bad := rapid.SampledFrom(keys).Draw(t, "bad")
		broken := make(map[string]string, len(id))
		for kk, v := range withExtra {
			broken[kk] = v
		}
		if rapid.Bool().Draw(t, "empty") {
			broken[bad] = ""
		} else {
			delete(broken, bad)
		}
		out, err := Hash(kind, broken)
		if !errors.Is(err, errs.Validation) || out != "" || !strings.Contains(err.Error(), bad) {
			t.Fatalf("missing %q: got %q, %v", bad, out, err)
		}

		// An unregistered kind is a validation error naming the kind.
		unknown := "zz_" + rapid.StringMatching(`[a-z]{1,8}`).Draw(t, "unknown")
		out, err = Hash(unknown, withExtra)
		if !errors.Is(err, errs.Validation) || out != "" || !strings.Contains(err.Error(), unknown) {
			t.Fatalf("unknown kind %q: got %q, %v", unknown, out, err)
		}
	})
}
