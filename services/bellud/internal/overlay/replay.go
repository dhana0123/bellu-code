package overlay

import (
	"context"
	"fmt"
	"time"
)

// DemoScript is the id of the scripted replay.
const DemoScript = "demo"

// ReplayInterval is the delay between replayed events.
const ReplayInterval = 1500 * time.Millisecond

// Replay emits steps for one connection, one event every ReplayInterval,
// numbering them from 1, then closes the channel. Only the "demo" script is
// known; any other id is an error.
func Replay(ctx context.Context, script string, steps []Event) (<-chan Event, error) {
	return ReplayEvery(ctx, script, steps, ReplayInterval)
}

// ReplayEvery is Replay with an explicit interval (used by tests).
func ReplayEvery(ctx context.Context, script string, steps []Event, interval time.Duration) (<-chan Event, error) {
	if script != DemoScript {
		return nil, fmt.Errorf("overlay: unknown replay script %q", script)
	}
	for _, s := range steps {
		if err := s.Validate(); err != nil {
			return nil, err
		}
	}
	out := make(chan Event)
	go func() {
		defer close(out)
		for i, s := range steps {
			if i > 0 || interval > 0 {
				t := time.NewTimer(interval)
				select {
				case <-ctx.Done():
					t.Stop()
					return
				case <-t.C:
				}
			}
			s.Seq = uint64(i + 1)
			select {
			case out <- s:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}
