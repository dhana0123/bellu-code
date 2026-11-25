package findings

import (
	"regexp"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

var idPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Feature: bellu-wiz-security-platform, Property 1: For any rule id, asset entity id and discriminator string, computing the Finding id twice from the same three values SHALL produce the same id, and the id SHALL be a function of exactly those three inputs.
// **Validates: Requirements 3.3**
func TestPropertyFindingIDDeterminism(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		rule := rapid.String().Draw(t, "rule")
		asset := rapid.String().Draw(t, "asset")
		disc := rapid.String().Draw(t, "disc")

		first := ID(rule, asset, disc)
		if second := ID(rule, asset, disc); first != second {
			t.Fatalf("same inputs gave different ids: %q vs %q", first, second)
		}
		if !idPattern.MatchString(first) {
			t.Fatalf("id is not 32 lowercase hex characters: %q", first)
		}

		// Changing any one of the three inputs changes the id.
		other := rapid.String().Draw(t, "other")
		if other != rule && ID(other, asset, disc) == first {
			t.Fatalf("rule id change did not change id: %q -> %q", rule, other)
		}
		if other != asset && ID(rule, other, disc) == first {
			t.Fatalf("asset id change did not change id: %q -> %q", asset, other)
		}
		if other != disc && ID(rule, asset, other) == first {
			t.Fatalf("discriminator change did not change id: %q -> %q", disc, other)
		}
	})
}

// Feature: bellu-wiz-security-platform, Property 1: For any rule id, asset entity id and discriminator string, computing the Finding id twice from the same three values SHALL produce the same id, and the id SHALL be a function of exactly those three inputs.
// **Validates: Requirements 3.3**
func TestPropertyFindingIDBoundaries(t *testing.T) {
	// The 0x00 separator is the field boundary, so the strings that are
	// split must not contain it.
	text := rapid.StringMatching(`[^\x00]{2,30}`)
	rapid.Check(t, func(t *rapid.T) {
		runes := []rune(text.Draw(t, "text"))
		i := rapid.IntRange(0, len(runes)).Draw(t, "i")
		j := rapid.IntRange(0, len(runes)).Draw(t, "j")
		if i == j {
			t.Skip()
		}
		// Same concatenated text, boundary between rule and asset moved.
		a := ID(string(runes[:i]), string(runes[i:]), "d")
		b := ID(string(runes[:j]), string(runes[j:]), "d")
		if a == b {
			t.Fatalf("boundary collision at %d and %d for %q", i, j, string(runes))
		}
		// Same for the boundary between asset and discriminator.
		c := ID("r", string(runes[:i]), string(runes[i:]))
		d := ID("r", string(runes[:j]), string(runes[j:]))
		if c == d {
			t.Fatalf("boundary collision at %d and %d for %q", i, j, strings.ToValidUTF8(string(runes), ""))
		}
	})
}
