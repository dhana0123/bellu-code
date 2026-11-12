// Package subscribe is the Change_Event subscriber hub. Publishing never
// blocks: a Subscriber whose buffer is full is closed with an overflow error
// and every other Subscriber carries on.
//
// The hub is generic over the delivered value so that it depends on nothing
// but errs; the Engine supplies a function that extracts the filterable
// fields (Meta) from its change type.
package subscribe

import (
	"fmt"
	"sync"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
)

// DefaultBuffer is the per-Subscriber channel capacity.
const DefaultBuffer = 256

// Meta is the filterable description of one change.
type Meta struct {
	Seq        uint64
	Kind       string // "added", "changed", "removed"
	Subject    string // "entity", "relation"
	EntityKind string // kind of the subject entity (entity changes only)
	Entity     string // subject entity (entity changes)
	From, To   string // relation endpoints (relation changes)
}

// Filter narrows a subscription. Zero fields match everything. Entity matches
// a change about the entity or a relation touching it; EntityKind matches
// entity changes only.
type Filter struct {
	Kind       string
	Subject    string
	EntityKind string
	Entity     string
}

// Match reports whether m passes the filter.
func (f Filter) Match(m Meta) bool {
	if f.Kind != "" && f.Kind != m.Kind {
		return false
	}
	if f.Subject != "" && f.Subject != m.Subject {
		return false
	}
	if f.EntityKind != "" && (m.Subject != "entity" || m.EntityKind != f.EntityKind) {
		return false
	}
	if f.Entity != "" {
		if m.Subject == "relation" {
			return m.From == f.Entity || m.To == f.Entity
		}
		return m.Entity == f.Entity
	}
	return true
}

// OverflowError closes a Subscriber whose buffer filled. LastSeq is the last
// sequence that was queued for it, so a client can resume after it.
type OverflowError struct{ LastSeq uint64 }

func (e *OverflowError) Error() string {
	return fmt.Sprintf("subscriber buffer full after sequence %d", e.LastSeq)
}

// Unwrap lets errors.Is(err, errs.Overflow) match.
func (e *OverflowError) Unwrap() error { return errs.Overflow }

// Hub fans changes out to Subscribers.
type Hub[T any] struct {
	meta       func(T) Meta
	onCount    func(int)
	onOverflow func()

	mu     sync.Mutex
	subs   map[*Sub[T]]struct{}
	closed bool
}

// NewHub returns a Hub. meta extracts the filterable fields of a value.
// onCount (subscriber count changed) and onOverflow may be nil.
func NewHub[T any](meta func(T) Meta, onCount func(int), onOverflow func()) *Hub[T] {
	return &Hub[T]{meta: meta, onCount: onCount, onOverflow: onOverflow, subs: map[*Sub[T]]struct{}{}}
}

// Sub is one Subscriber.
type Sub[T any] struct {
	h      *Hub[T]
	f      Filter
	ch     chan T
	buf    int
	done   chan struct{}
	mu     sync.Mutex
	err    error
	closed bool
	// replaying is true while a replay goroutine owns delivery; live values
	// queue in pending meanwhile.
	replaying bool
	pending   []T
	lastSeq   uint64
}

// Subscribe registers a live Subscriber. buf <= 0 means DefaultBuffer.
func (h *Hub[T]) Subscribe(f Filter, buf int) *Sub[T] { return h.subscribe(f, buf, false) }

// SubscribeReplay registers a Subscriber that queues live values until
// StartReplay has delivered its history. Call StartReplay exactly once.
func (h *Hub[T]) SubscribeReplay(f Filter, buf int) *Sub[T] { return h.subscribe(f, buf, true) }

func (h *Hub[T]) subscribe(f Filter, buf int, replay bool) *Sub[T] {
	if buf <= 0 {
		buf = DefaultBuffer
	}
	s := &Sub[T]{h: h, f: f, ch: make(chan T, buf), buf: buf, done: make(chan struct{}), replaying: replay}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		s.closed = true
		s.replaying = false
		close(s.done)
		close(s.ch)
		return s
	}
	h.subs[s] = struct{}{}
	n := len(h.subs)
	h.mu.Unlock()
	h.count(n)
	return s
}

func (h *Hub[T]) count(n int) {
	if h.onCount != nil {
		h.onCount(n)
	}
}

func (h *Hub[T]) remove(s *Sub[T]) {
	h.mu.Lock()
	_, ok := h.subs[s]
	delete(h.subs, s)
	n := len(h.subs)
	h.mu.Unlock()
	if ok {
		h.count(n)
	}
}

// Publish offers values, in order, to every matching Subscriber. It never
// blocks; a Subscriber with a full buffer is closed with an OverflowError.
func (h *Hub[T]) Publish(vs []T) {
	h.mu.Lock()
	subs := make([]*Sub[T], 0, len(h.subs))
	for s := range h.subs {
		subs = append(subs, s)
	}
	h.mu.Unlock()
	for _, v := range vs {
		m := h.meta(v)
		for _, s := range subs {
			if s.f.Match(m) {
				s.offer(v, m.Seq)
			}
		}
	}
}

// Close closes every Subscriber (without error) and refuses new ones.
func (h *Hub[T]) Close() {
	h.mu.Lock()
	h.closed = true
	subs := make([]*Sub[T], 0, len(h.subs))
	for s := range h.subs {
		subs = append(subs, s)
	}
	h.mu.Unlock()
	for _, s := range subs {
		s.Close()
	}
}

// Len returns the number of registered Subscribers.
func (h *Hub[T]) Len() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}

// offer delivers one live value without blocking.
func (s *Sub[T]) offer(v T, seq uint64) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	if s.replaying {
		if len(s.pending) >= s.buf {
			s.finishLocked(&OverflowError{LastSeq: s.lastSeq}, true)
			return
		}
		s.pending = append(s.pending, v)
		s.lastSeq = seq
		s.mu.Unlock()
		return
	}
	select {
	case s.ch <- v:
		s.lastSeq = seq
		s.mu.Unlock()
	default:
		s.finishLocked(&OverflowError{LastSeq: s.lastSeq}, true)
	}
}

// finishLocked closes the Sub. s.mu is held on entry and released here.
func (s *Sub[T]) finishLocked(err error, overflow bool) {
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.err = err
	s.pending = nil
	close(s.done)
	if !s.replaying {
		close(s.ch) // otherwise the replay goroutine closes it on exit
	}
	s.mu.Unlock()
	s.h.remove(s)
	if overflow && s.h.onOverflow != nil {
		s.h.onOverflow()
	}
}

// C is the delivery channel. It is closed when the Sub ends; values already
// buffered stay readable.
func (s *Sub[T]) C() <-chan T { return s.ch }

// Err is the reason the Sub ended: nil for Close, an *OverflowError after an
// overflow, or the error given to CloseWithError. It is meaningful once C is
// closed.
func (s *Sub[T]) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// Close ends the Sub. It is idempotent.
func (s *Sub[T]) Close() { s.CloseWithError(nil) }

// CloseWithError ends the Sub with err (the first ending wins).
func (s *Sub[T]) CloseWithError(err error) {
	s.mu.Lock()
	s.finishLocked(err, false)
}

// StartReplay runs fn in a goroutine to deliver history. fn calls emit for
// each historical value in order; emit applies the filter, blocks on a slow
// consumer and returns false once the Sub has closed (fn should then return).
// When fn returns nil, the values queued meanwhile are delivered and the Sub
// switches to live delivery with no gap or duplicate; a non-nil error closes
// the Sub with that error.
func (s *Sub[T]) StartReplay(fn func(emit func(T) bool) error) {
	go func() {
		err := fn(func(v T) bool {
			if !s.f.Match(s.h.meta(v)) {
				return true
			}
			return s.send(v)
		})
		if err != nil {
			s.CloseWithError(err)
		}
		for err == nil {
			s.mu.Lock()
			if len(s.pending) == 0 {
				s.replaying = false
				s.mu.Unlock()
				break
			}
			batch := s.pending
			s.pending = nil
			s.mu.Unlock()
			for _, v := range batch {
				if !s.send(v) {
					break
				}
			}
		}
		s.mu.Lock()
		s.replaying = false
		if s.closed {
			close(s.ch)
		}
		s.mu.Unlock()
	}()
}

func (s *Sub[T]) send(v T) bool {
	select {
	case s.ch <- v:
		return true
	case <-s.done:
		return false
	}
}

// Done is closed when the Sub ends.
func (s *Sub[T]) Done() <-chan struct{} { return s.done }
