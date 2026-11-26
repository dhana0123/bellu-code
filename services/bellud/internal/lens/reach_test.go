package lens

import (
	"context"
	"errors"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/facade"
)

func reachFixture() *memSource {
	m := &memSource{}
	for _, id := range []string{"a", "b", "c", "d", "x"} {
		m.entity(id, "aws_resource", nil)
	}
	add := func(from, to, conf string) {
		m.rels = append(m.rels, facade.Edge{Type: "r", From: facade.EntityID(from), To: facade.EntityID(to), Confidence: conf, Evidence: "ev:" + from + to})
	}
	add("a", "b", ConfExtracted)
	add("b", "c", ConfExtracted)
	add("a", "d", ConfInferred)
	add("d", "c", ConfExtracted)
	add("c", "x", ConfExtracted)
	return m
}

func TestReach(t *testing.T) {
	ctx, m := context.Background(), reachFixture()
	r, err := Reach(ctx, m, "a", "c", ReachOpts{})
	if err != nil || r.Unreachable || len(r.Path) != 2 || r.Inferred || r.Path[0].Evidence == "" {
		t.Fatalf("confirmed path: %+v %v", r, err)
	}
	r, _ = Reach(ctx, m, "a", "x", ReachOpts{MaxHops: 2})
	if !r.Unreachable || len(r.Path) != 0 {
		t.Fatalf("hop limit: %+v", r)
	}
	r, _ = Reach(ctx, m, "x", "a", ReachOpts{})
	if !r.Unreachable {
		t.Fatalf("directed: %+v", r)
	}
	// a->d is inferred: with include_inferred, a->d is one hop and flagged.
	r, _ = Reach(ctx, m, "a", "d", ReachOpts{IncludeInferred: true})
	if r.Unreachable || !r.Inferred {
		t.Fatalf("inferred: %+v", r)
	}
	r, _ = Reach(ctx, m, "a", "d", ReachOpts{})
	if !r.Unreachable {
		t.Fatalf("inferred excluded by default: %+v", r)
	}
	if _, err = Reach(ctx, m, "a", "nope", ReachOpts{}); !errors.Is(err, ErrReachEntity) {
		t.Fatalf("missing target: %v", err)
	}
}
