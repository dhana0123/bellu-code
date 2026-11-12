// Package store persists the Event_Log, indexes, Snapshots and retention
// metadata in a single Pebble database at <dir>/default.
package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/cockroachdb/pebble"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
)

// FormatVersion is the value stored at m/format.
const FormatVersion = "bellugraph-store/1"

// subdir is the Pebble directory below the configured store directory.
const subdir = "default"

var (
	keyFormat = []byte("m/format")
	keySeq    = []byte("m/seq")
	keyBase   = []byte("m/base")
)

// Store is an open Pebble database.
type Store struct {
	view
	dir string
	db  *pebble.DB
}

// Path returns <dir>/default, the Pebble directory.
func Path(dir string) string { return filepath.Join(dir, subdir) }

// Exists reports whether <dir>/default holds a Pebble database (CURRENT exists).
func Exists(dir string) bool {
	_, err := os.Stat(filepath.Join(Path(dir), "CURRENT"))
	return err == nil
}

// Preflight opens an existing store read-only, checks m/format and closes it.
// It writes nothing. A missing store returns nil. A lock error returns
// errs.Locked; a missing or unknown format, or any other open error, returns
// errs.Corrupt.
func Preflight(dir string) error {
	if !Exists(dir) {
		return nil
	}
	s, err := openRO(dir)
	if err != nil {
		return err
	}
	return s.Close()
}

// OpenReadOnly opens an existing store read-only after checking m/format.
// Write methods must not be used on the result.
func OpenReadOnly(dir string) (*Store, error) { return openRO(dir) }

func openRO(dir string) (*Store, error) {
	db, err := pebble.Open(Path(dir), &pebble.Options{ReadOnly: true})
	if err != nil {
		return nil, openErr(dir, err)
	}
	s := newStore(dir, db)
	if err := s.checkFormat(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Open opens the store for writing, creating it when absent. An existing
// store is preflighted first, so a bad one is rejected before any file is
// written. A fresh store gets m/format.
func Open(dir string) (*Store, error) {
	fresh := !Exists(dir)
	if !fresh {
		if err := Preflight(dir); err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating store directory: %w", err)
	}
	db, err := pebble.Open(Path(dir), &pebble.Options{})
	if err != nil {
		return nil, openErr(dir, err)
	}
	s := newStore(dir, db)
	if fresh {
		if err := db.Set(keyFormat, []byte(FormatVersion), pebble.Sync); err != nil {
			db.Close()
			return nil, fmt.Errorf("writing store format: %w", err)
		}
		return s, nil
	}
	if err := s.checkFormat(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func newStore(dir string, db *pebble.DB) *Store {
	return &Store{view: view{r: db}, dir: dir, db: db}
}

// Dir returns the configured store directory.
func (s *Store) Dir() string { return s.dir }

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) checkFormat() error {
	found := "missing"
	v, closer, err := s.db.Get(keyFormat)
	switch {
	case err == nil:
		found = string(v)
		closer.Close()
	case !errors.Is(err, pebble.ErrNotFound):
		return fmt.Errorf("%w: reading store format: %v", errs.Corrupt, err)
	}
	if found == FormatVersion {
		return nil
	}
	return fmt.Errorf("%w: store format %s: written by the previous engine or damaged; delete %s and restart, collectors rebuild the graph",
		errs.Corrupt, found, s.dir)
}

func openErr(dir string, err error) error {
	if isLockErr(err) {
		return fmt.Errorf("%w: store is held by another process (%s): %v",
			errs.Locked, filepath.Join(Path(dir), "LOCK"), err)
	}
	return fmt.Errorf("%w: opening store: %v", errs.Corrupt, err)
}

func isLockErr(err error) bool {
	if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EWOULDBLOCK) {
		return true
	}
	m := strings.ToLower(err.Error())
	return strings.Contains(m, "lock") || strings.Contains(m, "temporarily unavailable")
}
