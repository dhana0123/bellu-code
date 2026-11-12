package engine

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"time"

	"testing"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/graph"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/internal/gen"
)

// Feature: bellu-graph-native, Property 10: Retention preserves as-of at or after the horizon
// Validates: Requirements 13.4, 13.5, 13.6
func TestPropRetentionPreservesAsOf(t *testing.T) {
	const window = time.Hour
	rapid.Check(t, func(t *rapid.T) {
		dir, err := os.MkdirTemp("", "bge-ret-")
		if err != nil {
			t.Fatal(err)
		}
		clk := &stepClock{t: gen.Epoch}
		c, err := Open(dir, Options{
			Clock: clk.now, Retention: window, SnapshotInterval: time.Hour,
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		})
		if err != nil {
			os.RemoveAll(dir)
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = c.Close(context.Background())
			os.RemoveAll(dir)
		})
		ctx := context.Background()

		steps := gen.Options{ForeignEndpoints: true}.Schedule(2, 14).Draw(t, "schedule")
		for _, s := range steps {
			clk.t = s.Now
			_, _ = c.Apply(ctx, s.Batch, engineMode(s.Mode)) // rejected Batches are skipped
			if rapid.IntRange(0, 3).Draw(t, "snapshot") == 0 {
				if err := c.writeSnapshot(); err != nil {
					t.Fatal(err)
				}
			}
		}
		last := c.g.LastSeq
		if last == 0 {
			t.Skip("no events")
		}

		// The retention cut: the clock is set so the cutoff falls at, between
		// or beyond the Recorded_Times of the log.
		evs, _ := logEvents(t, c, 1, last)
		pick := rapid.SampledFrom(evs).Draw(t, "cutEvent")
		cut := time.Unix(0, pick.RecordedNS).UTC().Add(time.Duration(rapid.IntRange(-1, 1).Draw(t, "cutOff")) * time.Second)

		// Instants to probe, as-of states before retention.
		instants := []time.Time{gen.Epoch.Add(-time.Hour), gen.Epoch.Add(10 * time.Hour)}
		for i := 0; i < 6; i++ {
			instants = append(instants, drawInstant(t, nil, "at"))
		}
		before := make([]*graph.Graph, len(instants))
		for i, at := range instants {
			if before[i], err = c.StateAt(ctx, at); err != nil {
				t.Fatalf("StateAt(%v) before retention: %v", at, err)
			}
		}

		clk.t = cut.Add(window)
		if _, err := c.runRetention(ctx); err != nil {
			t.Fatalf("runRetention: %v", err)
		}

		v := c.st.NewView()
		base, hasBase, err := v.Base()
		v.Close()
		if err != nil {
			t.Fatal(err)
		}
		if hasBase {
			instants = append(instants, time.Unix(0, base.HorizonNS).UTC(), time.Unix(0, base.HorizonNS).UTC().Add(-time.Nanosecond))
			g0, err := c.StateAt(ctx, time.Unix(0, base.HorizonNS).UTC())
			if err != nil {
				t.Fatalf("StateAt(horizon): %v", err)
			}
			before = append(before, g0, nil) // the horizon itself is checked below
		}
		for i, at := range instants {
			g, err := c.StateAt(ctx, at)
			if hasBase && at.UnixNano() < base.HorizonNS {
				if !errors.Is(err, errs.Validation) {
					t.Fatalf("StateAt(%v) before horizon %d: err = %v, want validation", at, base.HorizonNS, err)
				}
				continue
			}
			if err != nil {
				t.Fatalf("StateAt(%v) after retention: %v", at, err)
			}
			if before[i] != nil && !g.Equal(before[i]) {
				t.Fatalf("StateAt(%v) changed by retention (horizon %d)", at, base.HorizonNS)
			}
		}
	})
}
