package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
)

func waitFor(t *testing.T, what string, f func() bool) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func snapSeqs(t *testing.T, c *Core) []uint64 {
	t.Helper()
	hs, err := c.st.ListSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	var out []uint64
	for _, h := range hs {
		out = append(out, h.Seq)
	}
	return out
}

func TestSnapshotTimerOnlyWhenLogAdvanced(t *testing.T) {
	clk := &fakeClock{t: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)}
	c, err := Open(t.TempDir(), Options{Clock: clk.now, SnapshotInterval: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(context.Background())
	time.Sleep(100 * time.Millisecond)
	if n := len(snapSeqs(t, c)); n != 0 {
		t.Fatalf("snapshots on an empty log: %d", n)
	}
	if _, err := c.Apply(context.Background(), hostBatch("a"), ModeFull); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "timed snapshot", func() bool { s := snapSeqs(t, c); return len(s) == 1 && s[0] == 1 })
}

func TestSnapshotEveryNEventsAndKeep(t *testing.T) {
	clk := &fakeClock{t: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)}
	c, err := Open(t.TempDir(), Options{Clock: clk.now, SnapshotInterval: time.Hour, SnapshotEvery: 1, SnapshotKeep: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(context.Background())
	for i := 1; i <= 5; i++ {
		names := []string{}
		for j := 0; j < i; j++ {
			names = append(names, string(rune('a'+j)))
		}
		if _, err := c.Apply(context.Background(), hostBatch(names...), ModeFull); err != nil {
			t.Fatal(err)
		}
		want := c.g.LastSeq
		waitFor(t, "kicked snapshot", func() bool {
			c.snapMu.Lock()
			defer c.snapMu.Unlock()
			return c.lastSnapSeq == want
		})
	}
	if s := snapSeqs(t, c); len(s) != 2 {
		t.Fatalf("kept %v, want 2 newest", s)
	}
}

func TestRetentionKeepsAsOfExact(t *testing.T) {
	start := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	clk := &fakeClock{t: start}
	c, err := Open(t.TempDir(), Options{Clock: clk.now, SnapshotInterval: time.Hour, Retention: 10 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(context.Background())
	ctx := context.Background()
	var names []string
	for i := 0; i < 6; i++ {
		names = append(names, string(rune('a'+i)))
		clk.t = start.Add(time.Duration(i) * time.Hour)
		if _, err := c.Apply(ctx, hostBatch(names...), ModeFull); err != nil {
			t.Fatal(err)
		}
		if i == 2 {
			if err := c.writeSnapshot(); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Events 1..6 recorded at hours 0..5. Cutoff = hour 13 - 10h = hour 3: b = 3.
	probe := []time.Time{start.Add(3 * time.Hour), start.Add(4*time.Hour + 30*time.Minute), start.Add(5 * time.Hour), start.Add(9 * time.Hour)}
	before := map[time.Time]int{}
	for _, at := range probe {
		g, err := c.StateAt(ctx, at)
		if err != nil {
			t.Fatal(err)
		}
		before[at] = g.LiveCount()
	}
	clk.t = start.Add(13 * time.Hour)
	n, err := c.runRetention(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("deleted %d events, want 3", n)
	}
	v := c.st.NewView()
	base, ok, _ := v.Base()
	v.Close()
	if !ok || base.Seq != 3 {
		t.Fatalf("base = %+v ok=%v", base, ok)
	}
	if s := snapSeqs(t, c); len(s) != 1 || s[0] != 3 {
		t.Fatalf("snapshots %v, want [3]", s)
	}
	for _, at := range probe {
		g, err := c.StateAt(ctx, at)
		if err != nil {
			t.Fatalf("StateAt(%v): %v", at, err)
		}
		if g.LiveCount() != before[at] {
			t.Fatalf("StateAt(%v) = %d live, was %d", at, g.LiveCount(), before[at])
		}
	}
	_, err = c.StateAt(ctx, start.Add(-time.Hour))
	if !errors.Is(err, errs.Validation) {
		t.Fatalf("before horizon: %v", err)
	}
	// Second run is a no-op.
	if n, err := c.runRetention(ctx); err != nil || n != 0 {
		t.Fatalf("second run = %d, %v", n, err)
	}
}
