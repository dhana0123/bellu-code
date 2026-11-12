package engine

import (
	"bytes"
	"context"
	"testing"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/internal/gen"
)

// Feature: bellu-graph-native, Property 4: Log ordering
// Validates: Requirements 3.1, 3.2, 4.2, 4.3
func TestPropLogOrdering(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		steps := gen.Options{}.Schedule(1, 10).Draw(t, "schedule")
		clk := gen.Clocks(1, 12).Draw(t, "clock")
		c := propEngine(t, clk.Now)
		seen := map[uint64][]byte{}
		for i, s := range steps {
			if _, err := c.Apply(context.Background(), s.Batch, engineMode(s.Mode)); err != nil {
				t.Fatalf("step %d: valid batch rejected: %v", i, err)
			}
			evs, raws := logEvents(t, c, 1, 0)
			if uint64(len(evs)) != c.g.LastSeq {
				t.Fatalf("log has %d events, LastSeq %d", len(evs), c.g.LastSeq)
			}
			for j, ev := range evs {
				if ev.Seq != uint64(j+1) {
					t.Fatalf("event %d has Log_Sequence %d", j, ev.Seq)
				}
				if j > 0 {
					if bytes.Compare(evs[j-1].ULID[:], ev.ULID[:]) >= 0 {
						t.Fatalf("ULID not increasing at seq %d", ev.Seq)
					}
					if ev.RecordedNS < evs[j-1].RecordedNS {
						t.Fatalf("Recorded_Time decreased at seq %d", ev.Seq)
					}
				}
				if old, ok := seen[ev.Seq]; ok && !bytes.Equal(old, raws[j]) {
					t.Fatalf("event %d changed after later batches", ev.Seq)
				}
				seen[ev.Seq] = raws[j]
			}
		}
	})
}
