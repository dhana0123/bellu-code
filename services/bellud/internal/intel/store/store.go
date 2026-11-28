// Package store is the Pebble-backed intel store. Imports write a new
// generation and flip the active pointer in one batch, so a failed import
// never changes what readers see. No read loads the whole corpus.
package store

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/cockroachdb/pebble"

	"github.com/bellu/bellucode/services/bellud/internal/intel/model"
)

const batchRecords = 5000

var metaKey = []byte("meta")

// ErrNoGeneration is returned by reads when no corpus has been imported.
var ErrNoGeneration = errors.New("intel store: no active generation")

// Meta is the active generation pointer and sync status.
type Meta struct {
	Gen         uint64    `json:"gen"`
	Version     string    `json:"version"`
	CreatedAt   time.Time `json:"created_at"`
	Records     int       `json:"records"`
	SyncedAt    time.Time `json:"synced_at"`
	ETag        string    `json:"etag"`
	LastError   string    `json:"last_error"`
	LastErrorAt time.Time `json:"last_error_at"`
}

// Active reports whether a corpus has been imported.
func (m Meta) Active() bool { return m.Gen > 0 }

// ImportInfo describes the corpus being imported.
type ImportInfo struct {
	Version   string
	CreatedAt time.Time
	ETag      string
}

// Store is an open intel store.
type Store struct {
	db *pebble.DB
	mu sync.Mutex // serializes meta writers (Replace, RecordError)
}

// Open opens or creates the store at dir (mode 0700) and deletes every
// generation other than the active one.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	db, err := pebble.Open(dir, &pebble.Options{})
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	m, err := s.readMeta(db)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := s.deleteExcept(m.Gen); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func genPrefix(g uint64) []byte { return []byte(fmt.Sprintf("g%010d/", g)) }

// genEnd is the exclusive upper bound of generation g's keys ('0' follows '/').
func genEnd(g uint64) []byte { return []byte(fmt.Sprintf("g%010d0", g)) }

func vKey(g uint64, id string) []byte { return append(genPrefix(g), append([]byte("v/"), id...)...) }
func aKey(g uint64, a string) []byte  { return append(genPrefix(g), append([]byte("a/"), a...)...) }
func pPrefix(g uint64, name string) []byte {
	return append(genPrefix(g), append([]byte("p/"+name), 0)...)
}

func prefixEnd(p []byte) []byte {
	e := append([]byte(nil), p...)
	e[len(e)-1]++ // prefixes here end in '/' or 0x00, never 0xff
	return e
}

// deleteExcept removes all generation data except generation keep (0 keeps none).
func (s *Store) deleteExcept(keep uint64) error {
	b := s.db.NewBatch()
	defer b.Close()
	if keep == 0 {
		if err := b.DeleteRange([]byte("g"), []byte("h"), nil); err != nil {
			return err
		}
	} else {
		if err := b.DeleteRange([]byte("g"), genPrefix(keep), nil); err != nil {
			return err
		}
		if err := b.DeleteRange(genEnd(keep), []byte("h"), nil); err != nil {
			return err
		}
	}
	return b.Commit(pebble.Sync)
}

type getter interface {
	Get(key []byte) ([]byte, io.Closer, error)
}

func (s *Store) readMeta(g getter) (Meta, error) {
	v, c, err := g.Get(metaKey)
	if errors.Is(err, pebble.ErrNotFound) {
		return Meta{}, nil
	}
	if err != nil {
		return Meta{}, err
	}
	defer c.Close()
	var m Meta
	if err := json.Unmarshal(v, &m); err != nil {
		return Meta{}, fmt.Errorf("intel store: corrupt meta: %w", err)
	}
	return m, nil
}

// Meta returns the active generation pointer and status.
func (s *Store) Meta() (Meta, error) { return s.readMeta(s.db) }

func putMeta(b *pebble.Batch, m Meta) error {
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return b.Set(metaKey, raw, nil)
}

// Replace imports JSONL records (one model.Vuln per line) into a new
// generation, then flips the active generation in a single batch. On any
// error the new generation is discarded and the previous one stays active.
func (s *Store) Replace(ctx context.Context, info ImportInfo, jsonl io.Reader) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	old, err := s.readMeta(s.db)
	if err != nil {
		return err
	}
	gen := old.Gen + 1
	cleanup := func() { _ = s.deleteRange(genPrefix(gen), genEnd(gen)) }
	if err := s.deleteRange(genPrefix(gen), genEnd(gen)); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			cleanup()
		}
	}()

	br := bufio.NewReaderSize(jsonl, 1<<20)
	b := s.db.NewBatch()
	defer func() { b.Close() }()
	n, inBatch := 0, 0
	for {
		if err = ctx.Err(); err != nil {
			return err
		}
		line, rerr := br.ReadBytes('\n')
		if t := bytes.TrimSpace(line); len(t) > 0 {
			var v model.Vuln
			if err = json.Unmarshal(t, &v); err != nil {
				return fmt.Errorf("intel store: record %d: %w", n+1, err)
			}
			if v.ID == "" {
				err = fmt.Errorf("intel store: record %d has no id", n+1)
				return err
			}
			if err = writeRecord(b, gen, v, t); err != nil {
				return err
			}
			n++
			inBatch++
			if inBatch >= batchRecords {
				if err = b.Commit(pebble.NoSync); err != nil {
					return err
				}
				b.Close()
				b = s.db.NewBatch()
				inBatch = 0
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			err = rerr
			return err
		}
	}
	if err = b.Commit(pebble.NoSync); err != nil {
		return err
	}
	b.Close()

	// Flip: one batch rewrites meta. Sync makes the data durable with it.
	if err = s.db.Flush(); err != nil {
		return err
	}
	now := time.Now().UTC()
	m := Meta{Gen: gen, Version: info.Version, CreatedAt: info.CreatedAt, Records: n, SyncedAt: now, ETag: info.ETag}
	fb := s.db.NewBatch()
	defer fb.Close()
	if err = putMeta(fb, m); err != nil {
		return err
	}
	if err = fb.Commit(pebble.Sync); err != nil {
		return err
	}
	if old.Gen > 0 {
		_ = s.deleteRange(genPrefix(old.Gen), genEnd(old.Gen))
	}
	return nil
}

func writeRecord(b *pebble.Batch, gen uint64, v model.Vuln, raw []byte) error {
	if err := b.Set(vKey(gen, v.ID), raw, nil); err != nil {
		return err
	}
	for _, a := range v.Aliases {
		if a == "" || a == v.ID {
			continue
		}
		if err := b.Set(aKey(gen, a), []byte(v.ID), nil); err != nil {
			return err
		}
	}
	seen := map[string]struct{}{}
	for _, ap := range v.Affected {
		if ap.Purl == "" {
			continue
		}
		if _, ok := seen[ap.Purl]; ok {
			continue
		}
		seen[ap.Purl] = struct{}{}
		k := append(pPrefix(gen, ap.Purl), v.ID...)
		if err := b.Set(k, nil, nil); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) deleteRange(start, end []byte) error {
	return s.db.DeleteRange(start, end, pebble.Sync)
}

// RecordError stores a sync failure in meta without touching the corpus.
func (s *Store) RecordError(msg string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.readMeta(s.db)
	if err != nil {
		return err
	}
	m.LastError = msg
	m.LastErrorAt = time.Now().UTC()
	b := s.db.NewBatch()
	defer b.Close()
	if err := putMeta(b, m); err != nil {
		return err
	}
	return b.Commit(pebble.Sync)
}

// Get returns the record for id, which may be the canonical id or an alias.
// The bool is false when nothing matches.
func (s *Store) Get(id string) (model.Vuln, bool, error) {
	snap := s.db.NewSnapshot()
	defer snap.Close()
	m, err := s.readMeta(snap)
	if err != nil {
		return model.Vuln{}, false, err
	}
	if !m.Active() {
		return model.Vuln{}, false, nil
	}
	return getIn(snap, m.Gen, id)
}

func getIn(g getter, gen uint64, id string) (model.Vuln, bool, error) {
	v, ok, err := loadV(g, gen, id)
	if err != nil || ok {
		return v, ok, err
	}
	raw, c, err := g.Get(aKey(gen, id))
	if errors.Is(err, pebble.ErrNotFound) {
		return model.Vuln{}, false, nil
	}
	if err != nil {
		return model.Vuln{}, false, err
	}
	canon := string(raw)
	c.Close()
	return loadV(g, gen, canon)
}

func loadV(g getter, gen uint64, id string) (model.Vuln, bool, error) {
	raw, c, err := g.Get(vKey(gen, id))
	if errors.Is(err, pebble.ErrNotFound) {
		return model.Vuln{}, false, nil
	}
	if err != nil {
		return model.Vuln{}, false, err
	}
	defer c.Close()
	var v model.Vuln
	if err := json.Unmarshal(raw, &v); err != nil {
		return model.Vuln{}, false, fmt.Errorf("intel store: corrupt record %q: %w", id, err)
	}
	return v, true, nil
}

// ByPurl returns the vulnerabilities indexed under a versionless purl name
// such as "pkg:npm/lodash", ordered by id. Only matching records are loaded.
func (s *Store) ByPurl(name string) ([]model.Vuln, error) {
	snap := s.db.NewSnapshot()
	defer snap.Close()
	m, err := s.readMeta(snap)
	if err != nil {
		return nil, err
	}
	if !m.Active() {
		return nil, nil
	}
	prefix := pPrefix(m.Gen, name)
	it, err := snap.NewIter(&pebble.IterOptions{LowerBound: prefix, UpperBound: prefixEnd(prefix)})
	if err != nil {
		return nil, err
	}
	var ids []string
	for ok := it.First(); ok; ok = it.Next() {
		ids = append(ids, string(it.Key()[len(prefix):]))
	}
	if err := it.Close(); err != nil {
		return nil, err
	}
	sort.Strings(ids)
	out := make([]model.Vuln, 0, len(ids))
	for _, id := range ids {
		v, ok, err := loadV(snap, m.Gen, id)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, v)
		}
	}
	return out, nil
}
