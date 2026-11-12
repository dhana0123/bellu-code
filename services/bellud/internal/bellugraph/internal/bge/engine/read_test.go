package engine

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/query"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

// readFixture applies three batches: hosts h0..h4 at t0 (os=linux, h4 os=bsd),
// relation h0->h1 and h1->h2 at t1, and removal of h4 plus an update of h0 at t2.
func readFixture(t *testing.T) (*Core, time.Time) {
	t.Helper()
	t0 := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	c := openTest(t, t.TempDir(), &fakeClock{t: t0.Add(time.Hour)})
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	ctx := context.Background()
	b := hostBatch("h0", "h1", "h2", "h3", "h4")
	b.Entities[4].Attributes = map[string]any{"os": "bsd"}
	b.ObservedAt = t0
	apply(t, c, b, ModeFull)
	apply(t, c, batch.Batch{Collector: "rel", ObservedAt: t0.Add(time.Minute), Relations: []batch.Relation{
		{Type: "depends_on", From: hostID(t, "h0"), To: hostID(t, "h1")},
		{Type: "depends_on", From: hostID(t, "h1"), To: hostID(t, "h2")},
	}}, ModePartial)
	b2 := hostBatch("h0", "h1", "h2", "h3")
	b2.Entities[0].Attributes = map[string]any{"os": "linux", "rack": "r1"}
	b2.ObservedAt = t0.Add(2 * time.Minute)
	apply(t, c, b2, ModeFull)
	_ = ctx
	return c, t0
}

func apply(t *testing.T, c *Core, b batch.Batch, m Mode) {
	t.Helper()
	if _, err := c.Apply(context.Background(), b, m); err != nil {
		t.Fatal(err)
	}
}

func TestEntityAndFind(t *testing.T) {
	c, _ := readFixture(t)
	ctx := context.Background()
	e, err := c.Entity(ctx, hostID(t, "h0"), nil)
	if err != nil || e.Kind != "host" || e.Label != "h0" || e.Attributes["rack"] != "r1" || e.Attributes["hostname"] != "h0" {
		t.Fatalf("Entity = %+v, %v", e, err)
	}
	for _, id := range []string{hostID(t, "h4"), "host:nope"} {
		if _, err := c.Entity(ctx, id, nil); !errors.Is(err, errs.NotFound) {
			t.Fatalf("Entity(%s) err = %v, want NotFound", id, err)
		}
	}
	now := time.Now()
	if _, err := c.Entity(ctx, hostID(t, "h0"), &now); err != nil {
		t.Fatalf("as-of err = %v", err)
	}

	pg, err := c.Find(ctx, FindQuery{Kind: "host", Attributes: map[string]string{"os": "linux"}}, nil)
	if err != nil || pg.Total != 4 || len(pg.Items) != 4 || pg.Truncated || pg.Limit != DefaultPageSize {
		t.Fatalf("Find = %+v, %v", pg, err)
	}
	for i := 1; i < len(pg.Items); i++ {
		if pg.Items[i-1].ID >= pg.Items[i].ID {
			t.Fatal("not sorted by ID")
		}
	}
	// AND over identity and descriptive attributes.
	pg, _ = c.Find(ctx, FindQuery{Attributes: map[string]string{"os": "linux", "hostname": "h0"}}, nil)
	if pg.Total != 1 || pg.Items[0].ID != hostID(t, "h0") {
		t.Fatalf("AND find = %+v", pg)
	}
}

func TestFindPaging(t *testing.T) {
	c, _ := readFixture(t)
	ctx := context.Background()
	var got []string
	cursor := ""
	for {
		pg, err := c.Find(ctx, FindQuery{Paging: Paging{PageSize: 3, Cursor: cursor}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if pg.Total != 4 {
			t.Fatalf("Total = %d", pg.Total)
		}
		for _, it := range pg.Items {
			got = append(got, it.ID)
		}
		if !pg.Truncated {
			break
		}
		cursor = pg.NextCursor
	}
	if len(got) != 4 {
		t.Fatalf("got %d items", len(got))
	}
	for _, p := range []Paging{{PageSize: -1}, {PageSize: 1001}, {Cursor: "garbage"}} {
		if _, err := c.Find(ctx, FindQuery{Paging: p}, nil); !errors.Is(err, errs.Validation) {
			t.Fatalf("Find(%+v) err = %v", p, err)
		}
	}
	// A cursor from another query is rejected.
	pg, _ := c.Find(ctx, FindQuery{Paging: Paging{PageSize: 1}}, nil)
	if _, err := c.Find(ctx, FindQuery{Kind: "host", Paging: Paging{Cursor: pg.NextCursor}}, nil); !errors.Is(err, errs.Validation) {
		t.Fatalf("foreign cursor err = %v", err)
	}
}

func TestNeighbors(t *testing.T) {
	c, _ := readFixture(t)
	ctx := context.Background()
	h := func(n string) string { return hostID(t, n) }
	pg, err := c.Neighbors(ctx, h("h0"), NeighborOpts{Depth: 2}, nil)
	if err != nil || pg.Total != 2 {
		t.Fatalf("Neighbors = %+v, %v", pg, err)
	}
	if e := pg.Items[0]; e.Hops != 1 || e.From != h("h0") || e.To != h("h1") || e.Direction != DirOut {
		t.Fatalf("first = %+v", e)
	}
	if e := pg.Items[1]; e.Hops != 2 || e.From != h("h1") || e.To != h("h2") {
		t.Fatalf("second = %+v", e)
	}
	pg, _ = c.Neighbors(ctx, h("h1"), NeighborOpts{Direction: DirIn}, nil)
	if pg.Total != 1 || pg.Items[0].Direction != DirIn {
		t.Fatalf("in = %+v", pg)
	}
	pg, _ = c.Neighbors(ctx, h("h0"), NeighborOpts{Depth: 3, Paging: Paging{PageSize: 1}}, nil)
	if !pg.Truncated || pg.Total != 2 {
		t.Fatalf("paged = %+v", pg)
	}
	pg2, err := c.Neighbors(ctx, h("h0"), NeighborOpts{Depth: 3, Paging: Paging{PageSize: 1, Cursor: pg.NextCursor}}, nil)
	if err != nil || len(pg2.Items) != 1 || pg2.Truncated || pg2.Items[0].Hops != 2 {
		t.Fatalf("page 2 = %+v, %v", pg2, err)
	}
	if _, err := c.Neighbors(ctx, "host:nope", NeighborOpts{}, nil); !errors.Is(err, errs.NotFound) {
		t.Fatalf("unknown err = %v", err)
	}
	for _, o := range []NeighborOpts{{Depth: 11}, {Depth: -1}, {Direction: "up"}} {
		if _, err := c.Neighbors(ctx, h("h0"), o, nil); !errors.Is(err, errs.Validation) {
			t.Fatalf("%+v err = %v", o, err)
		}
	}
	// Derived hook.
	derived := func(id EntityID) []query.Edge {
		if id == h("h3") {
			return []query.Edge{{Type: "resolves_to", From: h("h3"), To: h("h0")}}
		}
		return nil
	}
	pg, _ = c.Neighbors(ctx, h("h3"), NeighborOpts{Derived: derived}, nil)
	if pg.Total != 1 || !pg.Items[0].Derived {
		t.Fatalf("derived = %+v", pg)
	}
	pg, _ = c.Neighbors(ctx, h("h3"), NeighborOpts{}, nil)
	if pg.Total != 0 {
		t.Fatalf("nil derived = %+v", pg)
	}
}

func TestHistoryChangesDigest(t *testing.T) {
	c, t0 := readFixture(t)
	ctx := context.Background()
	h0 := hostID(t, "h0")

	hist, err := c.History(ctx, h0, TimeRange{}, Paging{})
	if err != nil {
		t.Fatal(err)
	}
	// created, relation added, updated.
	if hist.Total != 3 {
		t.Fatalf("history = %+v", hist)
	}
	for i := 1; i < len(hist.Items); i++ {
		if hist.Items[i].ObservedAt.Before(hist.Items[i-1].ObservedAt) {
			t.Fatal("history not oldest first")
		}
	}
	if hist.Items[1].Subject != SubjectRelation || hist.Items[2].Kind != ChangeChanged {
		t.Fatalf("history items = %+v", hist.Items)
	}
	ranged, _ := c.History(ctx, h0, TimeRange{From: t0.Add(time.Minute), To: t0.Add(time.Minute)}, Paging{})
	if ranged.Total != 1 {
		t.Fatalf("ranged = %+v", ranged)
	}
	if _, err := c.History(ctx, "host:nope", TimeRange{}, Paging{}); !errors.Is(err, errs.NotFound) {
		t.Fatalf("err = %v", err)
	}
	// A removed entity keeps its history.
	h4, err := c.History(ctx, hostID(t, "h4"), TimeRange{}, Paging{})
	if err != nil || h4.Total != 2 {
		t.Fatalf("h4 history = %+v, %v", h4, err)
	}

	all, err := c.Changes(ctx, TimeRange{}, ChangeFilter{}, OrderAsc)
	if err != nil {
		t.Fatal(err)
	}
	if all.Total != 5+2+1+1 { // 5 created, 2 relations, h4 removed, h0 updated
		t.Fatalf("total = %d", all.Total)
	}
	desc, _ := c.Changes(ctx, TimeRange{}, ChangeFilter{}, OrderDesc)
	for i := range all.Items {
		if all.Items[i].Seq != desc.Items[len(desc.Items)-1-i].Seq {
			t.Fatal("desc is not the reverse of asc")
		}
	}
	rel, _ := c.Changes(ctx, TimeRange{}, ChangeFilter{Subject: SubjectRelation}, OrderAsc)
	rem, _ := c.Changes(ctx, TimeRange{}, ChangeFilter{Kind: ChangeRemoved}, OrderAsc)
	ek, _ := c.Changes(ctx, TimeRange{}, ChangeFilter{EntityKind: "host"}, OrderAsc)
	ent, _ := c.Changes(ctx, TimeRange{}, ChangeFilter{Entity: hostID(t, "h1")}, OrderAsc)
	if rel.Total != 2 || rem.Total != 1 || ek.Total != 7 || ent.Total != 3 {
		t.Fatalf("filters: rel=%d rem=%d ek=%d ent=%d", rel.Total, rem.Total, ek.Total, ent.Total)
	}
	// Paging in both orders walks the full set.
	for _, order := range []Order{OrderAsc, OrderDesc} {
		var n int
		cursor := ""
		for {
			pg, err := c.Changes(ctx, TimeRange{}, ChangeFilter{Paging: Paging{PageSize: 2, Cursor: cursor}}, order)
			if err != nil {
				t.Fatal(err)
			}
			n += len(pg.Items)
			if !pg.Truncated {
				break
			}
			cursor = pg.NextCursor
		}
		if n != all.Total {
			t.Fatalf("order %d walked %d of %d", order, n, all.Total)
		}
	}
	if _, err := c.Changes(ctx, TimeRange{}, ChangeFilter{Paging: Paging{Cursor: "x"}}, OrderAsc); !errors.Is(err, errs.Validation) {
		t.Fatalf("cursor err = %v", err)
	}

	d, err := c.Digest(ctx, TimeRange{}, ChangeFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if d.Total != all.Total || d.ByKind["added"] != 7 || d.ByKind["removed"] != 1 || d.ByKind["changed"] != 1 ||
		d.BySubject["relation"] != 2 || d.ByEntityKind["host"] != 7 {
		t.Fatalf("digest = %+v", d)
	}
	if len(d.Top) != 5 || d.Top[0].Changes != 2 || d.Top[1].Changes != 2 || d.Top[2].Changes != 1 || d.Top[0].ID > d.Top[1].ID {
		t.Fatalf("top = %+v", d.Top)
	}
	_ = fmt.Sprint
}
