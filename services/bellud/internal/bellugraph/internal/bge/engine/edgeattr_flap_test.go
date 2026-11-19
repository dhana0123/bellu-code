package engine

import (
	"context"
	"reflect"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

// An attribute-only change on an existing relation records a relation update
// and adds no entity change, so the digest's flap list is unchanged (Req 6.11).
func TestAttributeOnlyChangeAddsNoFlap(t *testing.T) {
	ctx := context.Background()
	c, err := Open(t.TempDir(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(ctx) })
	a, _ := ident.Hash("host", map[string]string{"hostname": "a"})
	b, _ := ident.Hash("host", map[string]string{"hostname": "b"})
	mk := func(attrs map[string]any) batch.Batch {
		return batch.Batch{Collector: "c", Entities: []batch.Entity{
			{Type: "host", Identity: map[string]string{"hostname": "a"}},
			{Type: "host", Identity: map[string]string{"hostname": "b"}},
		}, Relations: []batch.Relation{{Type: "depends_on", From: a, To: b, Attributes: attrs}}}
	}
	if _, err := c.Apply(ctx, mk(nil), ModeFull); err != nil {
		t.Fatal(err)
	}
	before, err := c.Digest(ctx, TimeRange{}, ChangeFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Apply(ctx, mk(map[string]any{"evidence": "e1", "confidence": "inferred"}), ModeFull); err != nil {
		t.Fatal(err)
	}
	after, err := c.Digest(ctx, TimeRange{}, ChangeFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if after.Total != before.Total+1 || after.BySubject["relation"] != before.BySubject["relation"]+1 {
		t.Fatalf("want one more relation change: before %+v after %+v", before, after)
	}
	if !reflect.DeepEqual(after.Top, before.Top) || !reflect.DeepEqual(after.ByEntityKind, before.ByEntityKind) {
		t.Fatalf("flaps changed: before %+v after %+v", before, after)
	}
}
