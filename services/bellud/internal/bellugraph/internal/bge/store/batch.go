package store

import (
	"fmt"

	"github.com/cockroachdb/pebble"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/codec"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
)

// Batch accumulates the keys of one Apply and commits them atomically.
type Batch struct{ b *pebble.Batch }

// NewBatch starts an empty write batch.
func (s *Store) NewBatch() *Batch { return &Batch{b: s.db.NewBatch()} }

// AddEvent adds the event envelope and its index keys. ev.Seq must be set.
// ev.ID must hold the entity ID for entity and annotation events, including
// EntityCreated, whose ID is not part of the envelope.
func (b *Batch) AddEvent(ev codec.Event) error {
	raw, err := codec.EncodeEvent(ev)
	if err != nil {
		return err
	}
	idx, err := indexKeys(ev, func(codec.Event) string { return ev.ID })
	if err != nil {
		return err
	}
	if err := b.b.Set(eventKey(ev.Seq), raw, nil); err != nil {
		return err
	}
	for _, kv := range idx {
		if err := b.b.Set(kv.k, kv.v, nil); err != nil {
			return err
		}
	}
	return nil
}

// SetSeq records the last sequence number at m/seq.
func (b *Batch) SetSeq(seq uint64) error { return b.b.Set(keySeq, be64(seq), nil) }

// Commit writes the batch atomically with a sync.
func (b *Batch) Commit() error {
	defer b.b.Close()
	return b.b.Commit(pebble.Sync)
}

// Close discards an uncommitted batch.
func (b *Batch) Close() error { return b.b.Close() }

type kv struct{ k, v []byte }

// indexKeys lists the x/ keys of an event. entityID supplies the entity ID
// for entity and annotation events.
func indexKeys(ev codec.Event, entityID func(codec.Event) string) ([]kv, error) {
	val := append(be64(uint64(ev.ValidNS)), byte(ev.Type))
	out := []kv{{vtKey(ev.ValidNS, ev.Seq), []byte{byte(ev.Type)}}}
	switch ev.Type {
	case codec.EntityCreated, codec.EntityUpdated, codec.EntityRemoved, codec.Annotated:
		id := entityID(ev)
		if id == "" {
			return nil, fmt.Errorf("%w: event %d (type %d) has no entity ID", errs.Validation, ev.Seq, ev.Type)
		}
		out = append(out, kv{idxKey(prefixEnt, id, ev.Seq), val})
	case codec.RelationAdded, codec.RelationRemoved, codec.RelationUpdated:
		out = append(out, kv{idxKey(prefixRel, ev.From, ev.Seq), val}, kv{idxKey(prefixRel, ev.To, ev.Seq), val})
	}
	return out, nil
}
