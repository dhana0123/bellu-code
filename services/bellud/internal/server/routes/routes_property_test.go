package routes

import (
	"testing"

	"pgregory.net/rapid"
)

// Feature: go-server-bellu-graph, Property 11: Route table total and disjoint
// **Validates: Requirements 1.3, 1.4, 1.7, 1.12, 2.1, 2.2, 2.3, 2.4**
func TestProperty11RouteTableTotalAndDisjoint(t *testing.T) {
	infos := loadOperations(t)
	ops := Operations(infos)
	base := MustLoadEmbedded()
	orig := base.Routes()

	// Totality and disjointness of the embedded table (NewTable rejects overlaps).
	if err := Validate(orig, ops); err != nil {
		t.Fatal(err)
	}

	methods := []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
	segGen := rapid.SampledFrom([]string{"api", "session", "x", "_param_", "event", "global", "a/b", ".", "..", ""})

	rapid.Check(t, func(rt *rapid.T) {
		// Fisher-Yates permutation driven by rapid.
		perm := append([]Route(nil), orig...)
		for i := len(perm) - 1; i > 0; i-- {
			j := rapid.IntRange(0, i).Draw(rt, "swap")
			perm[i], perm[j] = perm[j], perm[i]
		}
		pt, err := NewTable(perm)
		if err != nil {
			rt.Fatalf("permuted table rejected: %v", err)
		}
		if err := Validate(perm, ops); err != nil {
			rt.Fatalf("permuted table not total: %v", err)
		}

		// Every operation resolves to exactly the same route in both tables.
		op := ops[rapid.IntRange(0, len(ops)-1).Draw(rt, "op")]
		p := examplePath(op.Path)
		r1, ok1 := base.Lookup(op.Method, p)
		r2, ok2 := pt.Lookup(op.Method, p)
		if !ok1 || !ok2 || r1 != r2 {
			rt.Fatalf("%s %s: %+v/%v vs permuted %+v/%v", op.Method, p, r1, ok1, r2, ok2)
		}

		// Arbitrary requests resolve identically regardless of order.
		method := rapid.SampledFrom(methods).Draw(rt, "method")
		segs := rapid.SliceOfN(segGen, 0, 5).Draw(rt, "segs")
		path := ""
		for _, s := range segs {
			path += "/" + s
		}
		a, aok := base.Lookup(method, path)
		b, bok := pt.Lookup(method, path)
		if aok != bok || a != b {
			rt.Fatalf("%s %q: %+v/%v vs permuted %+v/%v", method, path, a, aok, b, bok)
		}
	})
}
