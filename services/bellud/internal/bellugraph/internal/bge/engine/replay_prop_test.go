package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/cockroachdb/pebble"
	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/graph"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/internal/gen"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/internal/gen/model"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/store"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

// fullReplay folds the whole Event_Log into an empty Projection.
func fullReplay(t *rapid.T, c *Core, last uint64) *graph.Graph {
	t.Helper()
	g := graph.New()
	evs, _ := logEvents(t, c, 1, last)
	if uint64(len(evs)) != last {
		t.Fatalf("log holds %d events, want %d", len(evs), last)
	}
	for _, ev := range evs {
		g.Fold(ev)
	}
	return g
}

// dropSnapshots deletes every Snapshot of a closed store.
func dropSnapshots(t *rapid.T, dir string) {
	t.Helper()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	hs, err := st.ListSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	var seqs []uint64
	for _, h := range hs {
		seqs = append(seqs, h.Seq)
	}
	if err := st.DeleteSnapshots(seqs...); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
}

// corruptNewestSnapshot adds a record with an undecodable value to the newest
// Snapshot of a closed store, so its validation fails.
func corruptNewestSnapshot(t *rapid.T, dir string) {
	t.Helper()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	hs, err := st.ListSnapshots()
	st.Close()
	if err != nil || len(hs) == 0 {
		t.Fatalf("snapshots: %v (%d)", err, len(hs))
	}
	newest := hs[0].Seq
	for _, h := range hs {
		if h.Seq > newest {
			newest = h.Seq
		}
	}
	db, err := pebble.Open(store.Path(dir), &pebble.Options{})
	if err != nil {
		t.Fatal(err)
	}
	key := append(binary.BigEndian.AppendUint64([]byte("s/"), newest), "/e/zzz-corrupt"...)
	if err := db.Set(key, []byte{0xff, 0x01, 0x02}, pebble.Sync); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

func reopen(t *rapid.T, dir string, clock func() time.Time) *Core {
	t.Helper()
	c, err := Open(dir, Options{Clock: clock, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	return c
}

// Feature: bellu-graph-native, Property 8: Replay equality
// Validates: Requirements 3.8, 3.9, 13.2
func TestPropReplayEquality(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		f := buildSnapFixture(t)
		c := f.c
		dir := c.dir
		live := c.g
		last := live.LastSeq

		// The full replay from empty equals the live Projection.
		if !live.Equal(fullReplay(t, c, last)) {
			t.Fatal("live Projection differs from the full replay")
		}
		// Every valid Snapshot plus the log tail equals the live Projection.
		v := c.st.NewView()
		hs, err := v.ListSnapshots()
		if err != nil {
			v.Close()
			t.Fatal(err)
		}
		for _, h := range hs {
			s, err := v.LoadSnapshot(h.Seq)
			if err != nil {
				v.Close()
				t.Fatalf("LoadSnapshot(%d): %v", h.Seq, err)
			}
			g, err := graph.Import(fromStoreSnapshot(s))
			if err == nil {
				err = foldTail(v, g, last)
			}
			if err != nil {
				v.Close()
				t.Fatalf("snapshot %d + tail: %v", h.Seq, err)
			}
			if !live.Equal(g) {
				v.Close()
				t.Fatalf("snapshot %d + tail differs from the live Projection", h.Seq)
			}
		}
		v.Close()

		// Close and reopen: with the final snapshot, without any snapshot, or
		// with a corrupt newest snapshot.
		if err := c.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		variant := rapid.SampledFrom([]string{"snapshots", "none", "corrupt-newest"}).Draw(t, "variant")
		switch {
		case variant == "none":
			dropSnapshots(t, dir)
		case variant == "corrupt-newest" && last > 0:
			corruptNewestSnapshot(t, dir)
		}
		c2 := reopen(t, dir, (&stepClock{t: gen.Epoch}).now)
		defer c2.Close(context.Background())
		if !live.Equal(c2.g) {
			t.Fatalf("reopened Projection (%s) differs from the live one", variant)
		}
		if c2.g.LastSeq != last {
			t.Fatalf("reopened LastSeq %d, want %d", c2.g.LastSeq, last)
		}
	})
}

// Feature: bellu-graph-native, Property 8: Replay equality (concurrent writers)
// Validates: Requirements 3.8, 3.9, 13.2
func TestPropReplayEqualityConcurrent(t *testing.T) {
	type op struct {
		annotate bool
		names    []string
	}
	rapid.Check(t, func(t *rapid.T) {
		clk := &stepClock{t: gen.Epoch}
		c := propEngine(t, clk.now)
		dir := c.dir
		pool := []string{"n0", "n1", "n2", "n3", "n4"}
		workers := rapid.IntRange(2, 5).Draw(t, "workers")
		plans := make([][]op, workers)
		total := 0
		for w := range plans {
			plans[w] = rapid.SliceOfN(rapid.Custom(func(t *rapid.T) op {
				return op{
					annotate: rapid.IntRange(0, 3).Draw(t, "annotate") == 0,
					names:    rapid.SliceOfNDistinct(rapid.SampledFrom(pool), 1, 4, func(s string) string { return s }).Draw(t, "names"),
				}
			}), 1, 6).Draw(t, "ops")
			total += len(plans[w])
		}
		var wg sync.WaitGroup
		errc := make(chan error, total)
		for w := range plans {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i, o := range plans[w] {
					if o.annotate {
						id, err := ident.Hash("host", map[string]string{"hostname": o.names[0]})
						if err != nil {
							errc <- err
							return
						}
						// NotFound is fine: the host may not exist yet.
						_, _ = c.Annotate(context.Background(), id, map[string]string{"w": fmt.Sprintf("%d-%d", w, i)}, nil, "op")
						continue
					}
					b := batch.Batch{Collector: fmt.Sprintf("col%d", w)}
					for _, n := range o.names {
						b.Entities = append(b.Entities, batch.Entity{
							Type: "host", Identity: map[string]string{"hostname": n}, Attributes: map[string]any{"w": int64(w*100 + i)},
						})
					}
					if _, err := c.Apply(context.Background(), b, ModeFull); err != nil {
						errc <- err
						return
					}
				}
			}()
		}
		wg.Wait()
		close(errc)
		for err := range errc {
			t.Fatalf("concurrent write: %v", err)
		}

		live := c.g
		last := live.LastSeq
		// Serialized writes: contiguous sequences and strictly increasing ULIDs.
		evs, _ := logEvents(t, c, 1, last)
		for i, ev := range evs {
			if ev.Seq != uint64(i+1) {
				t.Fatalf("event %d has sequence %d", i, ev.Seq)
			}
			if i > 0 && bytes.Compare(evs[i-1].ULID[:], ev.ULID[:]) >= 0 {
				t.Fatalf("ULID of event %d does not increase", ev.Seq)
			}
		}
		if !live.Equal(fullReplay(t, c, last)) {
			t.Fatal("live Projection differs from the full replay")
		}
		if err := c.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		c2 := reopen(t, dir, clk.now)
		defer c2.Close(context.Background())
		if !live.Equal(c2.g) {
			t.Fatal("reopened Projection differs from the live one")
		}
	})
}

// rpCheckRelAttrs fails unless every live relation of g carries the edge
// attributes the model holds for it, and the sets of relations are equal.
func rpCheckRelAttrs(t *rapid.T, label string, g *graph.Graph, ms *model.State) {
	t.Helper()
	keys := g.AllRelations()
	if len(keys) != len(ms.Rels) {
		t.Fatalf("%s: %d relations, model %d", label, len(keys), len(ms.Rels))
	}
	for _, k := range keys {
		r, ok := g.Relation(k)
		mr := ms.Rels[model.RelKey{Type: k.Type, From: k.From, To: k.To}]
		if !ok || mr == nil {
			t.Fatalf("%s: relation %v missing (graph %v, model %v)", label, k, ok, mr != nil)
		}
		if !r.Attrs.Equal(mr.Attrs) {
			t.Fatalf("%s: relation %v attrs %+v, model %+v", label, k, r.Attrs, mr.Attrs)
		}
	}
}

// Feature: aws-relationship-registry, Property 11: Replay, snapshot restore, and as-of reads preserve attributes
// Validates: Requirements 7.6, 7.7, 7.8
func TestPropRelationAttrsSurviveReplayAndRestore(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		f := buildSnapFixture(t)
		c := f.c
		live := c.g
		last := live.LastSeq
		rpCheckRelAttrs(t, "live", live, f.m.Current())

		// Full replay from an empty Projection.
		full := fullReplay(t, c, last)
		if !live.Equal(full) {
			t.Fatal("full replay differs from the live Projection")
		}
		rpCheckRelAttrs(t, "full replay", full, f.m.Current())

		// Each Snapshot plus the rest of the log.
		v := c.st.NewView()
		hs, err := v.ListSnapshots()
		if err != nil {
			v.Close()
			t.Fatal(err)
		}
		for _, h := range hs {
			s, err := v.LoadSnapshot(h.Seq)
			if err != nil {
				v.Close()
				t.Fatalf("LoadSnapshot(%d): %v", h.Seq, err)
			}
			g, err := graph.Import(fromStoreSnapshot(s))
			if err == nil {
				err = foldTail(v, g, last)
			}
			if err != nil {
				v.Close()
				t.Fatalf("snapshot %d + tail: %v", h.Seq, err)
			}
			if !live.Equal(g) {
				v.Close()
				t.Fatalf("snapshot %d + tail differs from the live Projection", h.Seq)
			}
			rpCheckRelAttrs(t, fmt.Sprintf("snapshot %d + tail", h.Seq), g, f.m.Current())
		}
		v.Close()

		// Reopen, restoring from the newest Snapshot.
		dir := c.dir
		if err := c.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		c2 := reopen(t, dir, (&stepClock{t: gen.Epoch}).now)
		defer c2.Close(context.Background())
		rpCheckRelAttrs(t, "reopened", c2.g, f.m.Current())
	})
}
