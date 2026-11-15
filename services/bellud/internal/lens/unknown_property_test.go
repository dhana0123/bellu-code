package lens

import (
	"context"
	"errors"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// Feature: unified-security-graph, Property 16: Unknown lens ids are rejected
// by name.
//
// **Validates: Requirements 7.7, 7.8**

func TestUnknownLensRejectedByNameProperty(t *testing.T) {
	known := map[string]bool{}
	for _, d := range Catalog() {
		known[d.ID] = true
	}
	svc := NewService()
	eng := NewEngine(nil)
	rapid.Check(t, func(t *rapid.T) {
		id := rapid.StringMatching(`[A-Za-z0-9_./ -]{1,24}`).
			Filter(func(s string) bool { return !known[s] }).Draw(t, "id")
		for name, slice := range map[string]func() error{
			"service": func() error { _, err := svc.Slice(context.Background(), id, Params{}); return err },
			"engine":  func() error { _, err := eng.Slice(context.Background(), id, Params{}); return err },
		} {
			err := slice()
			var unknown ErrUnknownLens
			if !errors.As(err, &unknown) {
				t.Fatalf("%s: Slice(%q) err = %v, want ErrUnknownLens", name, id, err)
			}
			if unknown.ID != id || !strings.Contains(err.Error(), id) {
				t.Fatalf("%s: error %q does not name %q", name, err, id)
			}
		}
	})
}

func TestEmptyLensIDSelectsDefault(t *testing.T) {
	// An unbound service passes lens resolution for the default lens and
	// then reports ErrUnavailable, so the empty id was not rejected as unknown.
	_, err := NewService().Slice(context.Background(), "", Params{})
	var unknown ErrUnknownLens
	if errors.As(err, &unknown) {
		t.Fatalf("empty id rejected as unknown: %v", err)
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	if _, ok := lookup(DefaultLens); !ok || DefaultLens != "code-to-cloud" {
		t.Fatalf("default lens %q not in catalog", DefaultLens)
	}
}
