package store

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/cockroachdb/pebble"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/codec"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
)

type reader interface {
	Get(key []byte) ([]byte, io.Closer, error)
	NewIter(o *pebble.IterOptions) (*pebble.Iterator, error)
}

// view holds the read methods shared by Store (latest data) and View (a
// Pebble snapshot).
type view struct{ r reader }

// View is a consistent point-in-time read view of the store.
type View struct {
	view
	snap *pebble.Snapshot
}

// NewView takes a Pebble snapshot. Close it when done.
func (s *Store) NewView() *View {
	snap := s.db.NewSnapshot()
	return &View{view: view{r: snap}, snap: snap}
}

// Close releases the Pebble snapshot.
func (v *View) Close() error { return v.snap.Close() }

// Base is the retention boundary stored at m/base.
type Base struct {
	Seq       uint64
	HorizonNS int64
}

func (v view) get(key []byte) ([]byte, bool, error) {
	val, c, err := v.r.Get(key)
	if errors.Is(err, pebble.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer c.Close()
	return append([]byte(nil), val...), true, nil
}

// Seq returns m/seq, or 0 when absent.
func (v view) Seq() (uint64, error) {
	b, ok, err := v.get(keySeq)
	if err != nil || !ok {
		return 0, err
	}
	if len(b) != 8 {
		return 0, fmt.Errorf("%w: m/seq length %d", errs.Corrupt, len(b))
	}
	return binary.BigEndian.Uint64(b), nil
}

// Base returns m/base; ok is false when no retention has happened.
func (v view) Base() (base Base, ok bool, err error) {
	b, ok, err := v.get(keyBase)
	if err != nil || !ok {
		return Base{}, false, err
	}
	if len(b) != 16 {
		return Base{}, false, fmt.Errorf("%w: m/base length %d", errs.Corrupt, len(b))
	}
	return Base{binary.BigEndian.Uint64(b), int64(binary.BigEndian.Uint64(b[8:]))}, true, nil
}

func (b Base) encode() []byte {
	return binary.BigEndian.AppendUint64(be64(b.Seq), uint64(b.HorizonNS))
}

// EventRaw returns the stored envelope for seq, or errs.NotFound.
func (v view) EventRaw(seq uint64) ([]byte, error) {
	b, ok, err := v.get(eventKey(seq))
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%w: event %d", errs.NotFound, seq)
	}
	return b, nil
}

// Event returns the decoded, CRC-checked event for seq.
func (v view) Event(seq uint64) (codec.Event, error) {
	b, err := v.EventRaw(seq)
	if err != nil {
		return codec.Event{}, err
	}
	return codec.DecodeEvent(b)
}

// EventIter walks the log in ascending seq order.
type EventIter struct {
	it      *pebble.Iterator
	started bool
	ok      bool
}

// Events iterates e/ for from <= seq <= to; to == 0 means no upper bound.
func (v view) Events(from, to uint64) (*EventIter, error) {
	opts := &pebble.IterOptions{LowerBound: eventKey(from), UpperBound: upperBound(prefixEvent)}
	if to != 0 && to != ^uint64(0) {
		opts.UpperBound = eventKey(to + 1)
	}
	it, err := v.r.NewIter(opts)
	if err != nil {
		return nil, err
	}
	return &EventIter{it: it}, nil
}

// Next advances to the next event (the first call to the first) and reports
// whether one exists.
func (e *EventIter) Next() bool {
	if e.started {
		e.ok = e.it.Next()
	} else {
		e.started = true
		e.ok = e.it.First()
	}
	return e.ok
}

// Seq returns the current seq.
func (e *EventIter) Seq() uint64 { return binary.BigEndian.Uint64(e.it.Key()[len(prefixEvent):]) }

// Raw returns a copy of the current envelope.
func (e *EventIter) Raw() []byte { return append([]byte(nil), e.it.Value()...) }

// Event decodes the current envelope, verifying its CRC and that the seq
// matches the key.
func (e *EventIter) Event() (codec.Event, error) {
	ev, err := codec.DecodeEvent(e.it.Value())
	if err != nil {
		return ev, err
	}
	if ev.Seq != e.Seq() {
		return ev, fmt.Errorf("%w: event key seq %d != envelope seq %d", errs.Corrupt, e.Seq(), ev.Seq)
	}
	return ev, nil
}

// Close releases the iterator.
func (e *EventIter) Close() error { return e.it.Close() }
