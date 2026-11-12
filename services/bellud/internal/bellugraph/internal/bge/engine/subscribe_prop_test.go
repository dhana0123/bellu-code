package engine

import (
	"context"
	"sort"
	"sync/atomic"
	"time"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/internal/gen"
	"testing"
)

// Feature: bellu-graph-native, Property 25: Subscriptions deliver exactly the committed changes
// Validates: Requirements 14.1, 14.2, 14.3
func TestPropSubscriptionsDeliverCommittedChanges(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		steps := gen.Options{ForeignEndpoints: true}.Schedule(2, 12).Draw(t, "schedule")
		clk := &stepClock{t: gen.Epoch}
		c := propEngine(t, clk.now)
		ctx := context.Background()
		split := rapid.IntRange(0, len(steps)).Draw(t, "split")
		// Steps stamp the shared clock, so apply them from one goroutine only.
		run := func(ss []gen.Step) {
			for _, s := range ss {
				clk.t = s.Now
				_, _ = c.Apply(ctx, s.Batch, engineMode(s.Mode))
			}
		}
		run(steps[:split])
		last := c.g.LastSeq

		flt := ChangeFilter{
			Kind:       rapid.SampledFrom([]ChangeKind{"", ChangeAdded, ChangeChanged, ChangeRemoved}).Draw(t, "kind"),
			Subject:    rapid.SampledFrom([]ChangeSubject{"", SubjectEntity, SubjectRelation}).Draw(t, "subject"),
			EntityKind: rapid.SampledFrom(append([]string{""}, gen.DefaultUniverse().Kinds...)).Draw(t, "entityKind"),
		}
		var from uint64
		opts := SubscribeOpts{Filter: flt}
		if rapid.Bool().Draw(t, "resume") {
			from = uint64(rapid.Int64Range(0, int64(last)).Draw(t, "from"))
			opts.From = &from
		} else {
			from = last // live only: nothing before the subscription
		}
		sub, err := c.Subscribe(ctx, opts)
		if err != nil {
			t.Fatalf("Subscribe: %v", err)
		}
		defer sub.Close()

		var n atomic.Int64
		got := make(chan []ChangeView, 1)
		go func() {
			var out []ChangeView
			for cv := range sub.C() {
				out = append(out, cv)
				n.Add(1)
			}
			got <- out
		}()
		run(steps[split:])

		// Expected: stored Change_Events with seq > from matching the filter.
		qf := flt
		qf.PageSize = 1000
		page, err := c.Changes(ctx, TimeRange{}, qf, OrderAsc)
		if err != nil {
			t.Fatal(err)
		}
		if page.Truncated || page.NextCursor != "" {
			t.Fatalf("expected changes span more than one page")
		}
		var want []ChangeView
		for _, cv := range page.Items {
			if cv.Seq > from {
				want = append(want, cv)
			}
		}
		sort.Slice(want, func(i, j int) bool { return want[i].Seq < want[j].Seq })

		// Wait until the expected events arrived, then end the Sub and compare.
		deadline := time.Now().Add(5 * time.Second)
		for n.Load() < int64(len(want)) && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		time.Sleep(5 * time.Millisecond)
		sub.Close()
		var have []ChangeView
		select {
		case have = <-got:
		case <-time.After(5 * time.Second):
			t.Fatal("subscriber did not finish")
		}
		if sub.Err() != nil {
			t.Fatalf("Sub ended with %v", sub.Err())
		}
		if len(have) != len(want) {
			t.Fatalf("delivered %d events, want %d (from=%d)", len(have), len(want), from)
		}
		for i := range want {
			if have[i].Seq != want[i].Seq || have[i].Kind != want[i].Kind || have[i].Subject != want[i].Subject ||
				have[i].Entity != want[i].Entity || have[i].From != want[i].From || have[i].To != want[i].To {
				t.Fatalf("event %d: got %+v, want %+v", i, have[i], want[i])
			}
			if i > 0 && have[i].Seq <= have[i-1].Seq {
				t.Fatalf("seq not strictly increasing at %d: %d after %d", i, have[i].Seq, have[i-1].Seq)
			}
		}
	})
}
