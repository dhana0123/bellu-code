package store

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/cockroachdb/pebble"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/codec"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
)

// Err returns the first iteration error.
func (e *EventIter) Err() error { return e.it.Error() }

// SnapEntity is an entity record in a Snapshot.
type SnapEntity struct {
	ID  string
	Rec codec.EntityRecord
}

// SnapRelation is a relation record in a Snapshot.
type SnapRelation struct {
	Type, From, To string
	Rec            codec.RelationRecord
}

// Snapshot is a full Projection export. Header.NEnt, NRel and CRC are
// computed on write.
type Snapshot struct {
	Header    codec.SnapshotHeader
	Entities  []SnapEntity
	Relations []SnapRelation
}

type snapRec struct{ key, val []byte }

// WriteSnapshot writes the Snapshot at s/<Header.Seq>/ in one synced batch,
// header last. When base is non-nil, m/base is written in the same batch.
// It returns the header as stored.
func (s *Store) WriteSnapshot(snap Snapshot, base *Base) (codec.SnapshotHeader, error) {
	h := snap.Header
	h.NEnt, h.NRel = uint32(len(snap.Entities)), uint32(len(snap.Relations))
	pre := snapPrefix(h.Seq)
	ents := make([]snapRec, len(snap.Entities))
	for i, e := range snap.Entities {
		ents[i] = snapRec{append(append(append([]byte(nil), pre...), "e/"...), e.ID...), e.Rec.Encode()}
	}
	rels := make([]snapRec, len(snap.Relations))
	for i, r := range snap.Relations {
		k := append(append([]byte(nil), pre...), "r/"...)
		k = append(append(append(append(append(k, r.Type...), 0), r.From...), 0), r.To...)
		rels[i] = snapRec{k, r.Rec.Encode()}
	}
	byKey := func(l []snapRec) {
		sort.Slice(l, func(i, j int) bool { return bytes.Compare(l[i].key, l[j].key) < 0 })
	}
	byKey(ents)
	byKey(rels)

	crc := codec.NewSnapshotCRC(h)
	b := s.db.NewBatch()
	defer b.Close()
	for _, r := range append(ents, rels...) {
		crc.Write(r.val)
		if err := b.Set(r.key, r.val, nil); err != nil {
			return h, err
		}
	}
	h.CRC = crc.Sum32()
	if err := b.Set(snapHeaderKey(h.Seq), h.Encode(), nil); err != nil {
		return h, err
	}
	if base != nil {
		if err := b.Set(keyBase, base.encode(), nil); err != nil {
			return h, err
		}
	}
	return h, b.Commit(pebble.Sync)
}

// ListSnapshots returns the headers found under s/, ascending by seq. A
// header that does not decode is skipped; use ValidateSnapshot for the full
// check.
func (v view) ListSnapshots() ([]codec.SnapshotHeader, error) {
	it, err := v.r.NewIter(&pebble.IterOptions{LowerBound: prefixSnap, UpperBound: upperBound(prefixSnap)})
	if err != nil {
		return nil, err
	}
	defer it.Close()
	var out []codec.SnapshotHeader
	for ok := it.First(); ok; ok = it.Next() {
		k := it.Key()
		// s/<8>/h
		if len(k) != len(prefixSnap)+8+2 || k[len(k)-2] != '/' || k[len(k)-1] != 'h' {
			continue
		}
		h, err := codec.DecodeSnapshotHeader(it.Value())
		if err != nil || h.Seq != binary.BigEndian.Uint64(k[len(prefixSnap):]) {
			continue
		}
		out = append(out, h)
	}
	return out, it.Error()
}

// ValidateSnapshot checks that the header exists, the record counts match
// and the CRC is correct. Failures wrap errs.Corrupt.
func (v view) ValidateSnapshot(seq uint64) error {
	_, err := v.loadSnapshot(seq, false)
	return err
}

// LoadSnapshot validates and decodes the Snapshot at seq.
func (v view) LoadSnapshot(seq uint64) (Snapshot, error) { return v.loadSnapshot(seq, true) }

func (v view) loadSnapshot(seq uint64, decode bool) (Snapshot, error) {
	corrupt := func(f string, a ...any) (Snapshot, error) {
		return Snapshot{}, fmt.Errorf("%w: snapshot %d: %s", errs.Corrupt, seq, fmt.Sprintf(f, a...))
	}
	hb, ok, err := v.get(snapHeaderKey(seq))
	if err != nil {
		return Snapshot{}, err
	}
	if !ok {
		return corrupt("header missing")
	}
	h, err := codec.DecodeSnapshotHeader(hb)
	if err != nil {
		return Snapshot{}, fmt.Errorf("snapshot %d: %w", seq, err)
	}
	if h.Seq != seq {
		return corrupt("header seq %d", h.Seq)
	}
	pre := snapPrefix(seq)
	it, err := v.r.NewIter(&pebble.IterOptions{LowerBound: pre, UpperBound: upperBound(pre)})
	if err != nil {
		return Snapshot{}, err
	}
	defer it.Close()

	snap := Snapshot{Header: h}
	crc := codec.NewSnapshotCRC(h)
	var nEnt, nRel uint32
	hk := snapHeaderKey(seq)
	for ok := it.First(); ok; ok = it.Next() {
		k := it.Key()
		if bytes.Equal(k, hk) {
			continue
		}
		rest := k[len(pre):]
		if len(rest) < 2 || rest[1] != '/' {
			return corrupt("unexpected key %q", k)
		}
		crc.Write(it.Value())
		switch rest[0] {
		case 'e':
			nEnt++
			if decode {
				rec, err := codec.DecodeEntityRecord(it.Value())
				if err != nil {
					return Snapshot{}, fmt.Errorf("snapshot %d: %w", seq, err)
				}
				snap.Entities = append(snap.Entities, SnapEntity{ID: string(rest[2:]), Rec: rec})
			}
		case 'r':
			nRel++
			if decode {
				parts := strings.Split(string(rest[2:]), "\x00")
				if len(parts) != 3 {
					return corrupt("bad relation key %q", k)
				}
				rec, err := codec.DecodeRelationRecord(it.Value())
				if err != nil {
					return Snapshot{}, fmt.Errorf("snapshot %d: %w", seq, err)
				}
				snap.Relations = append(snap.Relations, SnapRelation{parts[0], parts[1], parts[2], rec})
			}
		default:
			return corrupt("unexpected key %q", k)
		}
	}
	if err := it.Error(); err != nil {
		return Snapshot{}, err
	}
	if nEnt != h.NEnt || nRel != h.NRel {
		return corrupt("counts %d/%d, header says %d/%d", nEnt, nRel, h.NEnt, h.NRel)
	}
	if crc.Sum32() != h.CRC {
		return corrupt("crc mismatch")
	}
	return snap, nil
}

// DeleteSnapshots removes the given Snapshots (header and records) in one
// synced batch.
func (s *Store) DeleteSnapshots(seqs ...uint64) error {
	if len(seqs) == 0 {
		return nil
	}
	b := s.db.NewBatch()
	defer b.Close()
	for _, q := range seqs {
		pre := snapPrefix(q)
		if err := b.DeleteRange(pre, upperBound(pre), nil); err != nil {
			return err
		}
	}
	return b.Commit(pebble.Sync)
}

// SnapshotEntity returns the record of entity id in the Snapshot at seq
// without validating the rest of the Snapshot; ok is false when the Snapshot
// holds no such entity.
func (v view) SnapshotEntity(seq uint64, id string) (rec codec.EntityRecord, ok bool, err error) {
	b, ok, err := v.get(append(append(snapPrefix(seq), "e/"...), id...))
	if err != nil || !ok {
		return codec.EntityRecord{}, false, err
	}
	rec, err = codec.DecodeEntityRecord(b)
	if err != nil {
		return codec.EntityRecord{}, false, fmt.Errorf("snapshot %d: %w", seq, err)
	}
	return rec, true, nil
}
