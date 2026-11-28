package overlay

import "sync"

// SubscriberBuffer is the per-subscriber channel capacity.
const SubscriberBuffer = 64

// Hub fans events out to live subscribers. It keeps no history.
type Hub struct {
	mu   sync.Mutex
	subs map[*sub]struct{}
}

type sub struct {
	ch     chan Event
	closed bool
}

// NewHub returns an empty Hub.
func NewHub() *Hub { return &Hub{subs: map[*sub]struct{}{}} }

// Publish delivers e to every current subscriber in call order. A subscriber
// whose buffer is full is closed instead of skipping the event, so order is
// never violated; the client reconnects.
func (h *Hub) Publish(e Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.subs {
		select {
		case s.ch <- e:
		default:
			h.drop(s)
		}
	}
}

// Subscribe registers a subscriber. cancel is idempotent. The channel is
// closed on cancel or overflow.
func (h *Hub) Subscribe() (<-chan Event, func()) {
	s := &sub{ch: make(chan Event, SubscriberBuffer)}
	h.mu.Lock()
	h.subs[s] = struct{}{}
	h.mu.Unlock()
	return s.ch, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.drop(s)
	}
}

// drop must be called with h.mu held.
func (h *Hub) drop(s *sub) {
	if s.closed {
		return
	}
	s.closed = true
	delete(h.subs, s)
	close(s.ch)
}
