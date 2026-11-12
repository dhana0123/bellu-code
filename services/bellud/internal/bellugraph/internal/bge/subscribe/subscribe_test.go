package subscribe

import (
	"errors"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
)

func meta(m Meta) Meta { return m }

func TestOverflowClosesOnlySlowSub(t *testing.T) {
	over := 0
	h := NewHub(meta, nil, func() { over++ })
	slow := h.Subscribe(Filter{}, 2)
	fast := h.Subscribe(Filter{Kind: "added"}, 8)
	for i := uint64(1); i <= 3; i++ {
		h.Publish([]Meta{{Seq: i, Kind: "added", Subject: "entity", Entity: "e"}})
	}
	var got []uint64
	for m := range slow.C() {
		got = append(got, m.Seq)
	}
	var oe *OverflowError
	if !errors.Is(slow.Err(), errs.Overflow) || !errors.As(slow.Err(), &oe) || oe.LastSeq != 2 {
		t.Fatalf("err = %v", slow.Err())
	}
	if len(got) != 2 || over != 1 || h.Len() != 1 {
		t.Fatalf("got %v over %d len %d", got, over, h.Len())
	}
	if len(fast.C()) != 3 {
		t.Fatalf("fast has %d", len(fast.C()))
	}
}

func TestFilterMatch(t *testing.T) {
	rel := Meta{Subject: "relation", Kind: "added", From: "a", To: "b"}
	if !(Filter{Entity: "b"}).Match(rel) || (Filter{Entity: "c"}).Match(rel) || (Filter{EntityKind: "host"}).Match(rel) {
		t.Fatal("relation matching wrong")
	}
	ent := Meta{Subject: "entity", Kind: "changed", EntityKind: "host", Entity: "a"}
	if !(Filter{EntityKind: "host", Kind: "changed"}).Match(ent) || (Filter{Kind: "added"}).Match(ent) {
		t.Fatal("entity matching wrong")
	}
}

func TestReplayThenLiveNoGap(t *testing.T) {
	h := NewHub(meta, nil, nil)
	s := h.SubscribeReplay(Filter{}, 8)
	h.Publish([]Meta{{Seq: 4}}) // live during replay
	s.StartReplay(func(emit func(Meta) bool) error {
		emit(Meta{Seq: 2})
		emit(Meta{Seq: 3})
		return nil
	})
	for _, want := range []uint64{2, 3, 4} {
		if m := <-s.C(); m.Seq != want {
			t.Fatalf("got %d want %d", m.Seq, want)
		}
	}
	h.Publish([]Meta{{Seq: 5}})
	if m := <-s.C(); m.Seq != 5 {
		t.Fatalf("live got %d", m.Seq)
	}
	s.Close()
	if _, ok := <-s.C(); ok || s.Err() != nil {
		t.Fatal("close should end cleanly")
	}
}
