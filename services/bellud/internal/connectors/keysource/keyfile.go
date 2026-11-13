package keysource

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type keyFile struct {
	path    string
	dataDir string
}

// NewKeyFile returns the key file source (BELLUCODE_MASTER_KEY_FILE). The file
// must be mode 0400, owned by the current user, and outside dataDir.
func NewKeyFile(path, dataDir string) Rotatable { return &keyFile{path: path, dataDir: dataDir} }

func (k *keyFile) Name() string { return NameKeyFile }

func (k *keyFile) Available(context.Context) bool {
	if k.path == "" {
		return false
	}
	fi, err := os.Stat(k.path)
	return err == nil && fi.Mode().IsRegular()
}

func (k *keyFile) Load(ctx context.Context) ([]byte, error) { return k.LoadSlot(ctx, SlotCurrent) }

func (k *keyFile) LoadSlot(_ context.Context, slot string) ([]byte, error) {
	p := k.slotPath(slot)
	if err := k.check(p); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoKey
	}
	if err != nil {
		return nil, err
	}
	defer zero(raw)
	return parseKey(raw)
}

// Store writes the key with mode 0400. The write replaces the file atomically.
func (k *keyFile) Store(_ context.Context, key []byte, slot string) error {
	if len(key) != KeyLen {
		return errors.New("keysource: master key must be 32 bytes")
	}
	p := k.slotPath(slot)
	if err := k.checkLocation(p); err != nil {
		return err
	}
	return writeFileAtomic(p, key, 0o400)
}

func (k *keyFile) Promote(context.Context) error {
	next := k.slotPath(SlotNext)
	if _, err := os.Stat(next); err != nil {
		return ErrNoKey
	}
	return os.Rename(next, k.path)
}

func (k *keyFile) slotPath(slot string) string {
	if slot == SlotNext {
		return k.path + ".next"
	}
	return k.path
}

// check enforces location, mode 0400 and ownership. On a wrong mode it tries
// chmod once (Requirement 6.9) and fails if the mode is still wrong.
func (k *keyFile) check(path string) error {
	if err := k.checkLocation(path); err != nil {
		return err
	}
	fi, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode().Perm() != 0o400 {
		if err := os.Chmod(path, 0o400); err != nil {
			return &PermissionError{Class: "key-file", Reason: "mode is not 0400"}
		}
		if fi, err = os.Stat(path); err != nil || fi.Mode().Perm() != 0o400 {
			return &PermissionError{Class: "key-file", Reason: "mode is not 0400"}
		}
	}
	if !ownedByCurrentUser(fi) {
		return &PermissionError{Class: "key-file", Reason: "not owned by the bellud user"}
	}
	return nil
}

func (k *keyFile) checkLocation(path string) error {
	if k.dataDir == "" {
		return nil
	}
	rel, err := filepath.Rel(resolve(k.dataDir), resolve(path))
	if err != nil {
		return nil
	}
	if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return &PermissionError{Class: "key-file", Reason: "must be outside the vault data directory"}
	}
	return nil
}

// resolve returns an absolute path with symlinks resolved as far as they exist.
func resolve(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	dir, base := filepath.Split(abs)
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		return filepath.Join(real, base)
	}
	return abs
}
