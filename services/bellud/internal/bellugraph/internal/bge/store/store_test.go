package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cockroachdb/pebble"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/codec"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
)

func TestFreshOpenWritesFormat(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if !Exists(dir) {
		t.Fatal("CURRENT missing")
	}
	s, err = Open(dir) // reopen passes the format check
	if err != nil {
		t.Fatal(err)
	}
	v, c, err := s.db.Get(keyFormat)
	if err != nil || string(v) != FormatVersion {
		t.Fatalf("format = %q, %v", v, err)
	}
	c.Close()
	s.Close()
}

func snapshotFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	err := filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		out[p] = b
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestMissingFormatIsCorruptAndUntouched(t *testing.T) {
	dir := t.TempDir()
	db, err := pebble.Open(Path(dir), &pebble.Options{})
	if err != nil {
		t.Fatal(err)
	}
	db.Set([]byte("old/key"), []byte("v"), pebble.Sync)
	db.Close()
	before := snapshotFiles(t, dir)

	_, err = Open(dir)
	if !errors.Is(err, errs.Corrupt) || !strings.Contains(err.Error(), "delete "+dir) {
		t.Fatalf("err = %v", err)
	}
	after := snapshotFiles(t, dir)
	if len(before) != len(after) {
		t.Fatalf("file set changed: %d -> %d", len(before), len(after))
	}
	for p, b := range before {
		if !bytes.Equal(b, after[p]) {
			t.Fatalf("%s changed", p)
		}
	}
}

func TestUnknownFormatIsCorrupt(t *testing.T) {
	dir := t.TempDir()
	db, _ := pebble.Open(Path(dir), &pebble.Options{})
	db.Set(keyFormat, []byte("bellugraph-store/99"), pebble.Sync)
	db.Close()
	if _, err := Open(dir); !errors.Is(err, errs.Corrupt) {
		t.Fatalf("err = %v", err)
	}
}

func TestLockContention(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for name, open := range map[string]func(string) (*Store, error){"writable": Open, "readonly": OpenReadOnly} {
		_, err := open(dir)
		if !errors.Is(err, errs.Locked) || !strings.Contains(err.Error(), filepath.Join(dir, "default", "LOCK")) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
}

func TestEventsIndexesSnapshotsAndRetention(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	b := s.NewBatch()
	for i := uint64(1); i <= 5; i++ {
		ev := codec.Event{Seq: i, ValidNS: int64(i) * 10, RecordedNS: int64(i), Type: codec.EntityCreated,
			Collector: "c", Kind: "k", Identity: map[string]string{"a": "b"}, ID: "ent1"}
		if err := b.AddEvent(ev); err != nil {
			t.Fatal(err)
		}
	}
	b.SetSeq(5)
	if err := b.Commit(); err != nil {
		t.Fatal(err)
	}
	if seq, _ := s.Seq(); seq != 5 {
		t.Fatalf("seq = %d", seq)
	}

	// A view does not see later writes.
	v := s.NewView()
	defer v.Close()
	b = s.NewBatch()
	b.AddEvent(codec.Event{Seq: 6, Type: codec.EntityRemoved, ID: "ent1"})
	b.Commit()
	it, _ := v.Events(2, 0)
	var seqs []uint64
	for it.Next() {
		ev, err := it.Event()
		if err != nil {
			t.Fatal(err)
		}
		seqs = append(seqs, ev.Seq)
	}
	it.Close()
	if len(seqs) != 4 || seqs[0] != 2 || seqs[3] != 5 {
		t.Fatalf("view seqs = %v", seqs)
	}

	// Snapshot round trip, with base.
	snap := Snapshot{
		Header:    codec.SnapshotHeader{Seq: 3, MaxVTNS: 30, LastRTNS: 3},
		Entities:  []SnapEntity{{"b", codec.EntityRecord{Kind: "k", Live: true}}, {"a", codec.EntityRecord{Kind: "k"}}},
		Relations: []SnapRelation{{"t", "a", "b", codec.RelationRecord{Asserted: []string{"c"}, Seq: 2}}},
	}
	if _, err := s.WriteSnapshot(snap, &Base{Seq: 3, HorizonNS: 30}); err != nil {
		t.Fatal(err)
	}
	hs, _ := s.ListSnapshots()
	if len(hs) != 1 || hs[0].NEnt != 2 || hs[0].NRel != 1 {
		t.Fatalf("headers = %+v", hs)
	}
	got, err := s.LoadSnapshot(3)
	if err != nil || got.Entities[0].ID != "a" || got.Relations[0].To != "b" {
		t.Fatalf("load = %+v, %v", got, err)
	}
	if base, ok, _ := s.Base(); !ok || base.Seq != 3 {
		t.Fatalf("base = %+v", base)
	}

	// Corrupt a record: validation fails.
	s.db.Set(append(snapPrefix(3), "e/a"...), []byte{1, 2}, pebble.Sync)
	if err := s.ValidateSnapshot(3); !errors.Is(err, errs.Corrupt) {
		t.Fatalf("validate = %v", err)
	}

	// Chunked retention delete removes events and index keys through 3.
	n, err := s.DeleteEventsThrough(3, 2, func(codec.Event) string { return "ent1" })
	if err != nil || n != 3 {
		t.Fatalf("deleted %d, %v", n, err)
	}
	if _, err := s.EventRaw(3); !errors.Is(err, errs.NotFound) {
		t.Fatalf("event 3: %v", err)
	}
	if _, err := s.EventRaw(4); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.get(idxKey(prefixEnt, "ent1", 2)); ok {
		t.Fatal("index key not deleted")
	}
	if _, ok, _ := s.get(idxKey(prefixEnt, "ent1", 4)); !ok {
		t.Fatal("index key 4 lost")
	}
	if err := s.DeleteSnapshots(3); err != nil {
		t.Fatal(err)
	}
	if hs, _ := s.ListSnapshots(); len(hs) != 0 {
		t.Fatal("snapshot not deleted")
	}
}

type fileState struct {
	data []byte
	mode os.FileMode
}

func statFiles(t *testing.T, dir string) map[string]fileState {
	t.Helper()
	out := map[string]fileState{}
	err := filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			out[p] = fileState{mode: fi.Mode()}
			return nil
		}
		b, err := os.ReadFile(p)
		out[p] = fileState{b, fi.Mode()}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func requireUnchanged(t *testing.T, before, after map[string]fileState) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatalf("file set changed: %d -> %d", len(before), len(after))
	}
	for p, b := range before {
		a, ok := after[p]
		if !ok || !bytes.Equal(a.data, b.data) || a.mode != b.mode {
			t.Fatalf("%s changed", p)
		}
	}
}

func TestRejectedStoresAreByteAndModeIdentical(t *testing.T) {
	for name, format := range map[string][]byte{"missing": nil, "unknown": []byte("bellugraph-store/99")} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			db, err := pebble.Open(Path(dir), &pebble.Options{})
			if err != nil {
				t.Fatal(err)
			}
			db.Set([]byte("old/key"), []byte("v"), pebble.Sync)
			if format != nil {
				db.Set(keyFormat, format, pebble.Sync)
			}
			db.Close()
			before := statFiles(t, dir)
			for opName, open := range map[string]func(string) (*Store, error){"Open": Open, "OpenReadOnly": OpenReadOnly} {
				if _, err := open(dir); !errors.Is(err, errs.Corrupt) {
					t.Fatalf("%s: err = %v", opName, err)
				}
			}
			if err := Preflight(dir); !errors.Is(err, errs.Corrupt) {
				t.Fatalf("preflight: %v", err)
			}
			requireUnchanged(t, before, statFiles(t, dir))
		})
	}
}

func TestPreflightMissingStoreIsNil(t *testing.T) {
	dir := t.TempDir()
	if err := Preflight(dir); err != nil {
		t.Fatal(err)
	}
	if Exists(dir) {
		t.Fatal("Preflight created a store")
	}
}

func TestCorruptManifestAndCurrent(t *testing.T) {
	for _, target := range []string{"MANIFEST", "CURRENT"} {
		t.Run(target, func(t *testing.T) {
			dir := t.TempDir()
			s, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			s.Close()
			matches, _ := filepath.Glob(filepath.Join(Path(dir), target+"*"))
			if len(matches) == 0 {
				t.Fatalf("no %s file", target)
			}
			if err := os.WriteFile(matches[0], []byte("garbage\x00\xff not a manifest"), 0o600); err != nil {
				t.Fatal(err)
			}
			before := statFiles(t, dir)
			if _, err := Open(dir); !errors.Is(err, errs.Corrupt) {
				t.Fatalf("Open err = %v", err)
			}
			if err := Preflight(dir); !errors.Is(err, errs.Corrupt) {
				t.Fatalf("Preflight err = %v", err)
			}
			requireUnchanged(t, before, statFiles(t, dir))
		})
	}
}

func TestInvalidSnapshotIsSkippedByList(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	mk := func(seq uint64) {
		snap := Snapshot{
			Header:   codec.SnapshotHeader{Seq: seq},
			Entities: []SnapEntity{{"a", codec.EntityRecord{Kind: "k", Live: true}}},
		}
		if _, err := s.WriteSnapshot(snap, nil); err != nil {
			t.Fatal(err)
		}
	}
	mk(1)
	mk(2) // undecodable header
	mk(3) // header stored under another seq
	mk(4) // bad record: header decodes, CRC fails
	mk(5) // missing record: count mismatch

	if err := s.db.Set(snapHeaderKey(2), []byte{0xff}, pebble.Sync); err != nil {
		t.Fatal(err)
	}
	hb, _, err := s.get(snapHeaderKey(3))
	if err != nil {
		t.Fatal(err)
	}
	hb = append([]byte(nil), hb...)
	s.db.Delete(snapHeaderKey(3), pebble.Sync)
	s.db.Set(snapHeaderKey(30), hb, pebble.Sync) // key says 30, header says 3
	s.db.Set(append(snapPrefix(4), "e/a"...), []byte{1, 2, 3}, pebble.Sync)
	s.db.Delete(append(snapPrefix(5), "e/a"...), pebble.Sync)

	hs, err := s.ListSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	var seqs []uint64
	for _, h := range hs {
		seqs = append(seqs, h.Seq)
	}
	// 2 (bad header) and 30 (seq mismatch) are skipped; 4 and 5 still list.
	if len(seqs) != 3 || seqs[0] != 1 || seqs[1] != 4 || seqs[2] != 5 {
		t.Fatalf("listed seqs = %v", seqs)
	}
	if err := s.ValidateSnapshot(1); err != nil {
		t.Fatalf("valid snapshot: %v", err)
	}
	for _, seq := range []uint64{2, 3, 4, 5, 99} {
		if err := s.ValidateSnapshot(seq); err == nil {
			t.Fatalf("snapshot %d validated", seq)
		}
	}
	for _, seq := range []uint64{3, 4, 5, 99} {
		if err := s.ValidateSnapshot(seq); !errors.Is(err, errs.Corrupt) {
			t.Fatalf("snapshot %d: err = %v, want Corrupt", seq, err)
		}
	}
}
