//go:build linux

package main

import (
	"errors"
	"strconv"
	"testing"
)

func TestLimiterDropsLowestPriorityFirst(t *testing.T) {
	l := NewLimiter(100)
	for i := 0; i < 60; i++ {
		l.Offer(Event{Type: TypeNetConnect})
	}
	for i := 0; i < 30; i++ {
		l.Offer(Event{Type: TypeProcessExec})
	}
	for i := 0; i < 20; i++ {
		l.Offer(Event{Type: TypeContainerEscape})
	}
	kept := l.Flush()
	if len(kept) != 100 {
		t.Fatalf("kept %d", len(kept))
	}
	d := l.TakeDrops()
	if d[TypeNetConnect] != 10 || len(d) != 1 {
		t.Fatalf("drops %v", d)
	}
	if len(l.TakeDrops()) != 0 {
		t.Fatal("drops not reset")
	}
}

func TestLimiterDropCountsExact(t *testing.T) {
	l := NewLimiter(100)
	types := []string{TypeNetConnect, TypeProcessExec, TypeFileWriteSensitive, TypeShellInContainer, TypePrivChange, TypeContainerEscape}
	for i := 0; i < 300; i++ {
		l.Offer(Event{ID: strconv.Itoa(i), Type: types[i%6]})
	}
	kept := l.Flush()
	var total uint64
	for _, n := range l.TakeDrops() {
		total += n
	}
	if len(kept) != 100 || total != 200 {
		t.Fatalf("kept %d dropped %d", len(kept), total)
	}
	for _, e := range kept {
		if e.Type == TypeNetConnect || e.Type == TypeProcessExec {
			t.Fatalf("low priority survived: %s", e.Type)
		}
	}
}

func TestClampRate(t *testing.T) {
	for in, want := range map[int]int{0: 2000, 5: 100, 1e6: 50000, 500: 500} {
		if got := clampRate(in); got != want {
			t.Fatalf("%d: %d", in, got)
		}
	}
}

func TestReconnectBufferDropsOldestAndKeepsOrder(t *testing.T) {
	b := NewReconnectBuffer(3)
	for i := 0; i < 5; i++ {
		b.Push(Event{ID: strconv.Itoa(i)})
	}
	if b.Dropped() != 2 {
		t.Fatalf("dropped %d", b.Dropped())
	}
	var got []string
	if err := b.Drain(func(e Event) error { got = append(got, e.ID); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0] != "2" || got[2] != "4" {
		t.Fatalf("got %v", got)
	}
}

func TestSenderBuffersWhileDownThenFlushesInOrder(t *testing.T) {
	down := true
	var got []string
	s := NewSender(func(e Event) error {
		if down {
			return errors.New("down")
		}
		got = append(got, e.ID)
		return nil
	}, NewReconnectBuffer(10))
	s.Send(Event{ID: "a"})
	s.Send(Event{ID: "b"})
	down = false
	s.Send(Event{ID: "c"})
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("got %v", got)
	}
}
