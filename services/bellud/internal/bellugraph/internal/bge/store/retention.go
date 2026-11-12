package store

import (
	"fmt"

	"github.com/cockroachdb/pebble"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/codec"
)

// DefaultChunk is the number of events deleted per batch.
const DefaultChunk = 10000

// DeleteEventsThrough removes e/<seq> for seq <= through, together with each
// event's x/ index keys, in synced batches of chunk events (DefaultChunk when
// chunk <= 0). entityID returns the entity ID for entity and annotation
// events, because EntityCreated envelopes do not store it. It is safe to
// call again after a crash: it resumes from the lowest remaining event.
// It returns the number of events deleted.
func (s *Store) DeleteEventsThrough(through uint64, chunk int, entityID func(codec.Event) string) (int, error) {
	if chunk <= 0 {
		chunk = DefaultChunk
	}
	total := 0
	for {
		n, err := s.deleteChunk(through, chunk, entityID)
		total += n
		if err != nil || n < chunk {
			return total, err
		}
	}
}

func (s *Store) deleteChunk(through uint64, chunk int, entityID func(codec.Event) string) (int, error) {
	it, err := s.Events(0, through)
	if err != nil {
		return 0, err
	}
	defer it.Close()
	b := s.db.NewBatch()
	defer b.Close()
	n := 0
	for n < chunk && it.Next() {
		ev, err := it.Event()
		if err != nil {
			return 0, fmt.Errorf("deleting events: %w", err)
		}
		keys, err := indexKeys(ev, entityID)
		if err != nil {
			return 0, err
		}
		for _, e := range keys {
			if err := b.Delete(e.k, nil); err != nil {
				return 0, err
			}
		}
		if err := b.Delete(eventKey(ev.Seq), nil); err != nil {
			return 0, err
		}
		n++
	}
	if err := it.Err(); err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	return n, b.Commit(pebble.Sync)
}
