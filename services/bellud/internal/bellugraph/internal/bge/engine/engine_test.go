package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

type fakeClock struct{ t time.Time }

func (f *fakeClock) now() time.Time { return f.t }

func openTest(t *testing.T, dir string, clk *fakeClock) *Core {
	t.Helper()
	c, err := Open(dir, Options{Clock: clk.now})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return c
}

func hostID(t *testing.T, name string) string {
	t.Helper()
	id, err := ident.Hash("host", map[string]string{"hostname": name})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func hostBatch(names ...string) batch.Batch {
	b := batch.Batch{Collector: "test"}
	for _, n := range names {
		b.Entities = append(b.Entities, batch.Entity{
			Type: "host", Identity: map[string]string{"hostname": n}, Attributes: map[string]any{"os": "linux"},
		})
	}
	return b
}

func TestApplyReopenEqual(t *testing.T) {
	dir := t.TempDir()
	clk := &fakeClock{t: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)}
	c := openTest(t, dir, clk)
	if c.State() != StateReady {
		t.Fatalf("state = %s", c.State())
	}

	rc, err := c.Apply(context.Background(), hostBatch("a", "b"), ModeFull)
	if err != nil {
		t.Fatal(err)
	}
	if rc.ID == "" || rc.Entities != 2 {
		t.Fatalf("receipt = %+v", rc)
	}
	// Clock moves backwards: Recorded_Time must not.
	clk.t = clk.t.Add(-time.Hour)
	rc2, err := c.Apply(context.Background(), hostBatch("a", "b", "c"), ModeFull)
	if err != nil {
		t.Fatal(err)
	}
	if rc2.RecordedAt.Before(rc.RecordedAt) {
		t.Fatalf("recorded time went back: %v < %v", rc2.RecordedAt, rc.RecordedAt)
	}
	if c.g.LastSeq != 3 {
		t.Fatalf("LastSeq = %d, want 3", c.g.LastSeq)
	}
	// Re-applying is a no-op that still yields a fresh receipt ID.
	rc3, err := c.Apply(context.Background(), hostBatch("a", "b", "c"), ModeFull)
	if err != nil {
		t.Fatal(err)
	}
	if rc3.ID == "" || rc3.ID == rc2.ID || c.g.LastSeq != 3 {
		t.Fatalf("no-op receipt %q (prev %q), LastSeq %d", rc3.ID, rc2.ID, c.g.LastSeq)
	}
	want := c.g.Clone()
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.State() != StateClosed {
		t.Fatalf("state = %s", c.State())
	}

	c2 := openTest(t, dir, clk)
	defer c2.Close(context.Background())
	if !c2.g.Equal(want) {
		t.Fatal("projection after reopen differs")
	}
	if c2.lastSnapSeq != 3 {
		t.Fatalf("expected the final snapshot at 3, got %d", c2.lastSnapSeq)
	}
}

func TestApplyRejectsInvalid(t *testing.T) {
	c := openTest(t, t.TempDir(), &fakeClock{t: time.Now()})
	defer c.Close(context.Background())
	_, err := c.Apply(context.Background(), batch.Batch{Entities: hostBatch("a").Entities}, ModeFull)
	if !errors.Is(err, errs.Validation) {
		t.Fatalf("err = %v, want validation", err)
	}
	if c.g.LastSeq != 0 {
		t.Fatal("rejected batch appended events")
	}
}

func TestAnnotate(t *testing.T) {
	dir := t.TempDir()
	clk := &fakeClock{t: time.Now()}
	c := openTest(t, dir, clk)
	ctx := context.Background()
	if _, err := c.Apply(ctx, hostBatch("a"), ModeFull); err != nil {
		t.Fatal(err)
	}
	id := hostID(t, "a")

	if _, err := c.Annotate(ctx, hostID(t, "zzz"), map[string]string{"k": "v"}, nil, "me"); !errors.Is(err, errs.NotFound) {
		t.Fatalf("unknown entity: %v", err)
	}
	if _, err := c.Annotate(ctx, id, map[string]string{"Bad Key": "v"}, nil, "me"); !errors.Is(err, errs.Validation) {
		t.Fatalf("bad key: %v", err)
	}
	an, err := c.Annotate(ctx, id, map[string]string{"owner": "ops"}, nil, "me")
	if err != nil || an.Values["owner"] != "ops" || an.By != "me" {
		t.Fatalf("annotate = %+v, %v", an, err)
	}
	// A Batch that drops the entity from the collector's scope must not remove annotations
	// of other live entities, and annotations survive attribute updates.
	b := hostBatch("a")
	b.Entities[0].Attributes = map[string]any{"os": "bsd"}
	if _, err := c.Apply(ctx, b, ModeFull); err != nil {
		t.Fatal(err)
	}
	got, ok, err := c.Annotations.Get(id)
	if err != nil || !ok || got.Values["owner"] != "ops" {
		t.Fatalf("Get = %+v %v %v", got, ok, err)
	}
	if n, _ := c.Annotations.Count(); n != 1 {
		t.Fatalf("Count = %d", n)
	}
	seq := c.g.LastSeq
	if _, err := c.Annotate(ctx, id, map[string]string{"owner": "ops"}, nil, "me"); err != nil || c.g.LastSeq != seq {
		t.Fatalf("unchanged annotate appended (%v)", err)
	}
	if err := c.Close(ctx); err != nil {
		t.Fatal(err)
	}

	c2 := openTest(t, dir, clk)
	defer c2.Close(ctx)
	got, ok, _ = c2.Annotations.Get(id)
	if !ok || got.Values["owner"] != "ops" {
		t.Fatalf("annotation lost on reopen: %+v", got)
	}
	an, err = c2.Annotate(ctx, id, nil, []string{"owner"}, "me")
	if err != nil || len(an.Values) != 0 {
		t.Fatalf("unset = %+v %v", an, err)
	}
	if n, _ := c2.Annotations.Count(); n != 0 {
		t.Fatalf("Count after unset = %d", n)
	}
}

func TestCloseIdempotentAndUnavailable(t *testing.T) {
	c := openTest(t, t.TempDir(), &fakeClock{t: time.Now()})
	ctx := context.Background()
	if err := c.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(ctx); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := c.Apply(ctx, hostBatch("a"), ModeFull); !errors.Is(err, errs.Unavailable) {
		t.Fatalf("Apply after Close: %v", err)
	}
	if _, err := c.Annotate(ctx, "x", nil, nil, ""); !errors.Is(err, errs.Unavailable) {
		t.Fatalf("Annotate after Close: %v", err)
	}
}

func TestOpenLocked(t *testing.T) {
	dir := t.TempDir()
	c := openTest(t, dir, &fakeClock{t: time.Now()})
	defer c.Close(context.Background())
	if _, err := Open(dir, Options{}); !errors.Is(err, errs.Locked) {
		t.Fatalf("second Open: %v, want ErrLocked", err)
	}
}

func TestULIDsIncrease(t *testing.T) {
	var g ulidGen
	t0 := time.Now()
	prev := g.next(t0)
	for i := 0; i < 1000; i++ {
		ts := t0
		if i%7 == 0 {
			ts = t0.Add(-time.Minute)
		}
		n := g.next(ts)
		if n.Compare(prev) <= 0 {
			t.Fatalf("ULID %d not increasing", i)
		}
		prev = n
	}
}
