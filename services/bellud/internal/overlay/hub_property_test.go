package overlay

import (
	"context"
	"reflect"
	"testing"
	"time"

	"pgregory.net/rapid"
)

func genEvent() *rapid.Generator[Event] {
	return rapid.Custom(func(t *rapid.T) Event {
		return Event{
			Seq:         rapid.Uint64().Draw(t, "seq"),
			Entity:      rapid.StringMatching(`[a-z0-9]{1,12}`).Draw(t, "entity"),
			Action:      rapid.SampledFrom([]string{ActionFocusNode, ActionWalkPath, ActionProposedChange}).Draw(t, "action"),
			Path:        rapid.SliceOfN(rapid.StringMatching(`[a-z0-9]{1,8}`), 0, 4).Draw(t, "path"),
			Explanation: rapid.String().Draw(t, "expl"),
		}
	})
}

// Feature: unified-security-graph, Property 21: Overlay events round trip and keep order
// **Validates: Requirements 9.1, 9.2**
func TestEventRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		e := genEvent().Draw(t, "event")
		if len(e.Path) == 0 {
			e.Path = nil
		}
		b, err := Encode(e)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decode(b)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, e) {
			t.Fatalf("got %+v want %+v", got, e)
		}
	})
}

func TestDecodeRejects(t *testing.T) {
	for _, in := range []string{
		`{"seq":1,"entity":"a","action":"delete","explanation":"x"}`,
		`{"seq":1,"entity":"a","action":"focus_node","explanation":"x","extra":1}`,
		`{"seq":1,"action":"focus_node","explanation":"x"}`,
		`{"seq":1,"entity":"a","action":"focus_node","explanation":"x"} {}`,
	} {
		if _, err := Decode([]byte(in)); err == nil {
			t.Errorf("expected error for %s", in)
		}
	}
}

// **Validates: Requirements 9.2**
func TestHubKeepsOrder(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		evs := rapid.SliceOfN(genEvent(), 0, SubscriberBuffer).Draw(t, "events")
		h := NewHub()
		ch, cancel := h.Subscribe()
		defer cancel()
		for _, e := range evs {
			h.Publish(e)
		}
		for i, want := range evs {
			select {
			case got := <-ch:
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("event %d: got %+v want %+v", i, got, want)
				}
			default:
				t.Fatalf("missing event %d", i)
			}
		}
	})
}

func TestHubOverflowClosesSubscriber(t *testing.T) {
	h := NewHub()
	slow, cancelSlow := h.Subscribe()
	defer cancelSlow()
	fast, cancelFast := h.Subscribe()
	defer cancelFast()
	for i := 0; i < SubscriberBuffer+1; i++ {
		h.Publish(Event{Seq: uint64(i), Entity: "a", Action: ActionFocusNode})
		if i < SubscriberBuffer {
			<-fast
		}
	}
	n := 0
	for range slow {
		n++
	}
	if n != SubscriberBuffer {
		t.Fatalf("slow got %d events, want %d then close", n, SubscriberBuffer)
	}
	if ev := <-fast; ev.Seq != SubscriberBuffer {
		t.Fatalf("fast subscriber lost event: %+v", ev)
	}
	cancelSlow() // idempotent
}

func TestHubNoHistory(t *testing.T) {
	h := NewHub()
	h.Publish(Event{Entity: "a", Action: ActionFocusNode})
	ch, cancel := h.Subscribe()
	defer cancel()
	select {
	case e := <-ch:
		t.Fatalf("late subscriber saw %+v", e)
	default:
	}
}

func TestReplay(t *testing.T) {
	steps := []Event{
		{Entity: "a", Action: ActionFocusNode, Explanation: "x"},
		{Entity: "b", Action: ActionWalkPath, Path: []string{"a", "b"}, Explanation: "y"},
	}
	ch, err := ReplayEvery(context.Background(), DemoScript, steps, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	var got []Event
	for e := range ch {
		got = append(got, e)
	}
	if len(got) != 2 || got[0].Seq != 1 || got[1].Seq != 2 || got[1].Entity != "b" {
		t.Fatalf("got %+v", got)
	}
	if _, err := Replay(context.Background(), "other", steps); err == nil {
		t.Fatal("unknown script accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	ch, _ = ReplayEvery(ctx, DemoScript, steps, time.Hour)
	cancel()
	if _, ok := <-ch; ok {
		t.Fatal("expected closed channel after cancel")
	}
}
