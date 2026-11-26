//go:build linux

package main

import (
	"context"
	"sync"
	"time"
)

const (
	defaultRate     = 2000
	minRate         = 100
	maxRate         = 50000
	bufferCapacity  = 10000
	dropReportEvery = 10 * time.Second
	retryEvery      = 5 * time.Second
)

// dropRank orders types by drop priority; lower rank is dropped first (Requirement 15.10).
var dropRank = map[string]int{
	TypeNetConnect:         0,
	TypeProcessExec:        1,
	TypeFileWriteSensitive: 2,
	TypeShellInContainer:   3,
	TypePrivChange:         4,
	TypeContainerEscape:    5,
}

func rankOf(t string) int {
	if r, ok := dropRank[t]; ok {
		return r
	}
	return -1 // unknown types are dropped first
}

// clampRate bounds a configured rate to 100..50,000 events/s; 0 means the default.
func clampRate(n int) int {
	switch {
	case n == 0:
		return defaultRate
	case n < minRate:
		return minRate
	case n > maxRate:
		return maxRate
	}
	return n
}

// Limiter admits at most rate events per one-second window. When a window overflows,
// the lowest-priority events are dropped first and counted per type.
type Limiter struct {
	mu      sync.Mutex
	rate    int
	window  []Event
	dropped map[string]uint64
}

func NewLimiter(rate int) *Limiter {
	return &Limiter{rate: clampRate(rate), dropped: map[string]uint64{}}
}

// Offer adds an event to the current window.
func (l *Limiter) Offer(e Event) {
	l.mu.Lock()
	l.window = append(l.window, e)
	l.mu.Unlock()
}

// Flush closes the window and returns the admitted events in original order.
func (l *Limiter) Flush() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.window
	l.window = nil
	excess := len(w) - l.rate
	if excess <= 0 {
		return w
	}
	// Count events per rank, then decide how many of each rank to drop.
	// Within a rank, the newest events are dropped first.
	byRank := map[int]int{}
	for _, e := range w {
		byRank[rankOf(e.Type)]++
	}
	toDrop := map[int]int{}
	for r := -1; r <= 5 && excess > 0; r++ {
		n := min(byRank[r], excess)
		toDrop[r] = n
		excess -= n
	}
	kept := make([]Event, len(w))
	seen := map[int]int{}
	out := kept[:0]
	for _, e := range w {
		r := rankOf(e.Type)
		seen[r]++
		if seen[r] > byRank[r]-toDrop[r] {
			l.dropped[e.Type]++
			continue
		}
		out = append(out, e)
	}
	return out
}

// TakeDrops returns and resets the per-type drop counts.
func (l *Limiter) TakeDrops() map[string]uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	d := l.dropped
	l.dropped = map[string]uint64{}
	return d
}

// Run flushes every second and reports drop counts every 10 s until ctx ends.
func (l *Limiter) Run(ctx context.Context, out func(Event), report func(map[string]uint64)) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	last := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			for _, e := range l.Flush() {
				out(e)
			}
			if now.Sub(last) >= dropReportEvery {
				last = now
				if d := l.TakeDrops(); len(d) > 0 {
					report(d)
				}
			}
		}
	}
}

// ReconnectBuffer holds events while the channel is down. At capacity it drops the oldest.
type ReconnectBuffer struct {
	mu      sync.Mutex
	cap     int
	events  []Event
	dropped uint64
}

func NewReconnectBuffer(capacity int) *ReconnectBuffer {
	if capacity <= 0 {
		capacity = bufferCapacity
	}
	return &ReconnectBuffer{cap: capacity}
}

func (b *ReconnectBuffer) Push(e Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.events) >= b.cap {
		b.events = b.events[1:]
		b.dropped++
	}
	b.events = append(b.events, e)
}

func (b *ReconnectBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.events)
}

// Dropped returns the number of events discarded because the buffer was full.
func (b *ReconnectBuffer) Dropped() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.dropped
}

// Drain sends buffered events in original order. It stops at the first send error and
// keeps the unsent events.
func (b *ReconnectBuffer) Drain(send func(Event) error) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for len(b.events) > 0 {
		if err := send(b.events[0]); err != nil {
			return err
		}
		b.events = b.events[1:]
	}
	return nil
}

// Sender delivers events to the server, buffering while the channel is down and
// retrying every 5 s.
type Sender struct {
	buf  *ReconnectBuffer
	send func(Event) error
}

func NewSender(send func(Event) error, buf *ReconnectBuffer) *Sender {
	return &Sender{buf: buf, send: send}
}

// Send keeps order: new events queue behind any buffered ones.
func (s *Sender) Send(e Event) {
	s.buf.Push(e)
	_ = s.buf.Drain(s.send)
}

// Retry drains the buffer every 5 s until ctx ends.
func (s *Sender) Retry(ctx context.Context) {
	t := time.NewTicker(retryEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if s.buf.Len() > 0 {
				_ = s.buf.Drain(s.send)
			}
		}
	}
}
