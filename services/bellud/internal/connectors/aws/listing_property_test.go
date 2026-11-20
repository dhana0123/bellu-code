package aws

import (
	"context"
	"testing"

	"pgregory.net/rapid"
)

// Feature: aws-relationship-registry, Property 14: Caps set truncation flags exactly when exceeded
//
// Listing half: Truncated is true if and only if more items existed than the cap.
//
// **Validates: Requirements 11.7**
func TestPropertyListingTruncatedExactlyWhenExceeded(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		pages := rapid.SliceOfN(rapid.IntRange(0, 4000), 0, 8).Draw(t, "pages")
		total, i := 0, 0
		for _, n := range pages {
			total += n
		}
		l, err := listAll(context.Background(), func() bool { return i < len(pages) }, func(context.Context) ([]int, error) {
			out := make([]int, pages[i])
			i++
			return out, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if l.Truncated != (total > maxItems) {
			t.Fatalf("total %d: truncated=%v", total, l.Truncated)
		}
		if len(l.Items) != min(total, maxItems) {
			t.Fatalf("total %d: kept %d", total, len(l.Items))
		}
	})
}
