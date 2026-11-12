package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
)

func recv(t *testing.T, ch <-chan ChangeView) ChangeView {
	t.Helper()
	select {
	case cv, ok := <-ch:
		if !ok {
			t.Fatal("channel closed")
		}
		return cv
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
	return ChangeView{}
}

func TestSubscribeReplayThenLive(t *testing.T) {
	clk := &fakeClock{t: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)}
	c := openTest(t, t.TempDir(), clk)
	defer c.Close(context.Background())
	ctx := context.Background()
	if _, err := c.Apply(ctx, hostBatch("a", "b"), ModeFull); err != nil {
		t.Fatal(err)
	}
	from := uint64(1)
	sub, err := c.Subscribe(ctx, SubscribeOpts{From: &from})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Apply(ctx, hostBatch("a", "b", "c"), ModeFull); err != nil {
		t.Fatal(err)
	}
	for _, want := range []uint64{2, 3} {
		cv := recv(t, sub.C())
		if cv.Seq != want || cv.Kind != ChangeAdded || cv.EntityKind != "host" {
			t.Fatalf("got %+v want seq %d", cv, want)
		}
	}
	if _, err := c.Annotate(ctx, hostID(t, "a"), map[string]string{"k": "v"}, nil, "me"); err != nil {
		t.Fatal(err)
	}
	if cv := recv(t, sub.C()); cv.Seq != 4 || cv.Kind != ChangeChanged || cv.EntityKind != "host" {
		t.Fatalf("annotate change %+v", cv)
	}
	// Live-only with a filter that excludes everything so far.
	sub2, err := c.Subscribe(ctx, SubscribeOpts{Filter: ChangeFilter{Kind: ChangeRemoved}})
	if err != nil {
		t.Fatal(err)
	}
	if len(sub2.C()) != 0 {
		t.Fatal("unexpected delivery")
	}
	if _, err := c.Subscribe(ctx, SubscribeOpts{From: ptr(uint64(99))}); !errors.Is(err, errs.Validation) {
		t.Fatalf("beyond-last err = %v", err)
	}
	c.Close(ctx)
	if _, ok := <-sub.C(); ok {
		t.Fatal("subscriber not closed by Close")
	}
}

func ptr[T any](v T) *T { return &v }
