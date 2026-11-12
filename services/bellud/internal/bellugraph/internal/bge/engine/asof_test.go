package engine

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/graph"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/store"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

// naiveAt folds, from empty, every logged event with Valid_Time <= at.
func naiveAt(t *testing.T, c *Core, at time.Time) *graph.Graph {
	t.Helper()
	g := graph.New()
	it, err := c.st.Events(1, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	for it.Next() {
		ev, err := it.Event()
		if err != nil {
			t.Fatal(err)
		}
		if ev.ValidNS <= at.UnixNano() {
			g.Fold(ev)
		}
	}
	return g
}

func TestStateAtEqualsNaiveFold(t *testing.T) {
	c, t0 := readFixture(t)
	ctx := context.Background()
	// Out-of-order Valid_Time, with a Snapshot in the middle of the log.
	if err := c.writeSnapshot(); err != nil {
		t.Fatal(err)
	}
	late := hostBatch("h9")
	late.ObservedAt = t0.Add(30 * time.Second)
	apply(t, c, late, ModePartial)
	upd := hostBatch("h1")
	upd.Entities[0].Attributes = map[string]any{"os": "plan9"}
	upd.ObservedAt = t0.Add(3 * time.Minute)
	apply(t, c, upd, ModePartial)
	if err := c.writeSnapshot(); err != nil {
		t.Fatal(err)
	}
	for _, d := range []time.Duration{-time.Second, 0, 30 * time.Second, time.Minute, 2 * time.Minute, 150 * time.Second, 5 * time.Minute} {
		at := t0.Add(d)
		got, err := c.StateAt(ctx, at)
		if err != nil {
			t.Fatal(err)
		}
		want := naiveAt(t, c, at)
		want.LastSeq, got.LastSeq = 0, 0
		if !got.Equal(want) {
			t.Fatalf("StateAt(%v) differs from naive fold", d)
		}
	}
}

func TestEntityAsOf(t *testing.T) {
	c, t0 := readFixture(t)
	ctx := context.Background()
	h0, h4 := hostID(t, "h0"), hostID(t, "h4")
	at := t0.Add(time.Minute)
	v, err := c.Entity(ctx, h0, &at)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := v.Attributes["rack"]; ok || !v.ObservedAt.Equal(t0) {
		t.Fatalf("h0 at 1m = %+v", v)
	}
	if err := c.writeSnapshot(); err != nil { // reads then start from the Snapshot record
		t.Fatal(err)
	}
	at2 := t0.Add(2 * time.Minute)
	if v, err = c.Entity(ctx, h0, &at2); err != nil || v.Attributes["rack"] != "r1" || !v.ObservedAt.Equal(at2) {
		t.Fatalf("h0 at 2m = %+v, %v", v, err)
	}
	if _, err = c.Entity(ctx, h4, &at); err != nil {
		t.Fatalf("h4 at 1m: %v", err)
	}
	for _, tc := range []struct {
		id string
		at time.Time
	}{{h4, at2}, {h0, t0.Add(-time.Second)}, {"nope", at2}} {
		if _, err := c.Entity(ctx, tc.id, &tc.at); !errors.Is(err, errs.NotFound) {
			t.Fatalf("Entity(%s, %v) = %v, want NotFound", tc.id, tc.at, err)
		}
	}
}

func TestFindAndNeighborsAsOf(t *testing.T) {
	c, t0 := readFixture(t)
	ctx := context.Background()
	at := t0.Add(30 * time.Second)
	pg, err := c.Find(ctx, FindQuery{Kind: "host"}, &at)
	if err != nil || pg.Total != 5 {
		t.Fatalf("find at 30s: %+v %v", pg, err)
	}
	now, err := c.Find(ctx, FindQuery{Kind: "host"}, nil)
	if err != nil || now.Total != 4 {
		t.Fatalf("find now: %+v %v", now, err)
	}
	h1 := hostID(t, "h1")
	if n, err := c.Neighbors(ctx, h1, NeighborOpts{}, &at); err != nil || n.Total != 0 {
		t.Fatalf("neighbors at 30s: %+v %v", n, err)
	}
	at = t0.Add(time.Minute)
	if n, err := c.Neighbors(ctx, h1, NeighborOpts{}, &at); err != nil || n.Total != 2 {
		t.Fatalf("neighbors at 1m: %+v %v", n, err)
	}
}

func TestDiffAndFlapping(t *testing.T) {
	c, t0 := readFixture(t)
	ctx := context.Background()
	d, err := c.Diff(ctx, t0.Add(30*time.Second), t0.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Added) != 0 || len(d.Changed) != 1 || d.Changed[0].ID != hostID(t, "h0") ||
		len(d.Removed) != 1 || d.Removed[0] != hostID(t, "h4") || d.Truncated {
		t.Fatalf("diff = %+v", d)
	}
	// h7 is created, removed and created again inside the window; h8 is
	// created and removed: neither is added or removed, h7 ends live and so
	// is added, h8 only flaps.
	one := func(names ...string) batch.Batch { b := hostBatch(names...); return b }
	for i, names := range [][]string{{"h7", "h8"}, {"h7"}, {"h7", "h8"}} {
		b := one(names...)
		if i == 1 {
			b = one("h7")
		}
		b.Collector = "flap"
		b.ObservedAt = t0.Add(time.Duration(10+i) * time.Minute)
		apply(t, c, b, ModeFull)
	}
	d, err = c.Diff(ctx, t0.Add(9*time.Minute), t0.Add(13*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	h7, h8 := hostID(t, "h7"), hostID(t, "h8")
	if len(d.Added) != 2 || len(d.Flapping) != 0 {
		t.Fatalf("diff = %+v", d)
	}
	_ = h7
	// Window after creation: h8 removed at +11, recreated at +12 => 2 changes, equal ends.
	d, err = c.Diff(ctx, t0.Add(10*time.Minute+30*time.Second), t0.Add(13*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Flapping) != 1 || d.Flapping[0].ID != h8 || d.Flapping[0].Changes != 2 {
		t.Fatalf("flapping = %+v (diff %+v)", d.Flapping, d)
	}
	if _, err := c.Diff(ctx, t0.Add(time.Hour), t0); !errors.Is(err, errs.Validation) {
		t.Fatalf("to before from: %v", err)
	}
}

func TestAsOfBeforeHorizon(t *testing.T) {
	c, t0 := readFixture(t)
	ctx := context.Background()
	snap := toStoreSnapshot(c.g.Export())
	if _, err := c.st.WriteSnapshot(snap, &store.Base{Seq: snap.Header.Seq, HorizonNS: snap.Header.MaxVTNS}); err != nil {
		t.Fatal(err)
	}
	before := t0.Add(time.Minute)
	for _, err := range []error{
		func() error { _, err := c.Entity(ctx, hostID(t, "h0"), &before); return err }(),
		func() error { _, err := c.StateAt(ctx, before); return err }(),
		func() error { _, err := c.Diff(ctx, before, t0.Add(time.Hour)); return err }(),
	} {
		if !errors.Is(err, errs.Validation) || !strings.Contains(err.Error(), "retention horizon 2025-01-01T00:02:00Z") {
			t.Fatalf("err = %v", err)
		}
	}
	at := t0.Add(2 * time.Minute)
	if v, err := c.Entity(ctx, hostID(t, "h0"), &at); err != nil || v.Attributes["rack"] != "r1" {
		t.Fatalf("at horizon: %+v %v", v, err)
	}
}
