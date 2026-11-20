package lens

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/facade"
)

// Feature: aws-relationship-registry, Property 21: Evidence is cut on a character boundary
//
// **Validates: Requirements 14.7**
func TestPropertyEvidenceCut(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		unit := rapid.SampledFrom([]string{"a", "é", "€", "😀"}).Draw(t, "unit")
		s := strings.Repeat(unit, rapid.IntRange(0, 300).Draw(t, "n")) + rapid.String().Draw(t, "tail")
		if !utf8.ValidString(s) {
			return
		}
		b := &builder{edges: map[SliceEdge]struct{}{}}
		b.addEdge(facade.Edge{From: "a", To: "b", Type: "depends_on", Evidence: s})
		var got string
		for e := range b.edges {
			got = e.Evidence
		}
		if len(s) <= MaxEvidence {
			if got != s {
				t.Fatalf("short evidence changed: %q -> %q", s, got)
			}
			return
		}
		if len(got) > MaxEvidence || !utf8.ValidString(got) || !strings.HasPrefix(s, got) {
			t.Fatalf("bad cut: %d bytes, valid=%v", len(got), utf8.ValidString(got))
		}
		// Longest: the next character would exceed the limit.
		_, size := utf8.DecodeRuneInString(s[len(got):])
		if len(got)+size <= MaxEvidence {
			t.Fatalf("cut at %d is not the longest prefix", len(got))
		}
	})
	_ = context.Background
}
