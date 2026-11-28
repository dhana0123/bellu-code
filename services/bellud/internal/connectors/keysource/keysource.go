// Package keysource supplies the 32-byte Master_Key that wraps vault data keys.
//
// Sources are tried in the priority order of Requirement 6.3: OS key store,
// systemd credential, key file, passphrase. The Master_Key never lives in the
// vault directory.
package keysource

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// KeyLen is the Master_Key length in bytes.
const KeyLen = 32

// Source names, shown to the user as the active key source.
const (
	NameOSKeyring  = "os-keyring"
	NameSystemd    = "systemd-creds"
	NameKeyFile    = "key-file"
	NamePassphrase = "passphrase"
)

// Slot names used for Master_Key rotation.
const (
	SlotCurrent = "current"
	SlotNext    = "next"
)

var (
	// ErrNoSource means no source is available; the vault falls back to memory-only mode.
	ErrNoSource = errors.New("keysource: no master key source available")
	// ErrNoKey means the source is available but holds no key yet.
	ErrNoKey = errors.New("keysource: no master key stored")
	// ErrStoreUnsupported is returned by sources that cannot store a key.
	ErrStoreUnsupported = errors.New("keysource: source cannot store a key")
	// ErrPassphraseTooShort rejects passphrases under MinPassphraseLen characters.
	ErrPassphraseTooShort = errors.New("keysource: passphrase must be at least 12 characters")
)

// PermissionError reports a mode or ownership problem. Class is "key-file" or "directory".
type PermissionError struct {
	Class  string
	Reason string
}

func (e *PermissionError) Error() string {
	return fmt.Sprintf("keysource: %s has unsafe permissions: %s", e.Class, e.Reason)
}

// Source provides the Master_Key.
type Source interface {
	Name() string
	Available(ctx context.Context) bool
	// Load returns the 32-byte key from the current slot. The caller owns and should zero it.
	Load(ctx context.Context) ([]byte, error)
	// Store saves key in slot. Sources that cannot store return ErrStoreUnsupported.
	Store(ctx context.Context, key []byte, slot string) error
}

// Rotatable is implemented by sources that support Master_Key rotation:
// write the new key to SlotNext, then Promote after the vault is re-wrapped.
type Rotatable interface {
	Source
	LoadSlot(ctx context.Context, slot string) ([]byte, error)
	// Promote makes the SlotNext key the current key.
	Promote(ctx context.Context) error
}

// Select returns the first available source in order.
func Select(ctx context.Context, order []Source) (Source, error) {
	for _, s := range order {
		if s == nil {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if s.Available(ctx) {
			return s, nil
		}
	}
	return nil, ErrNoSource
}

// Config describes where the non-OS sources read from.
type Config struct {
	// DataDir holds vault.json; the key file must live outside it.
	DataDir string
	// KeyFile is the BELLUCODE_MASTER_KEY_FILE path, empty when unset.
	KeyFile string
	// Passphrase returns the user's passphrase, or nil when no prompt is possible.
	// The returned slice is zeroed after use.
	Passphrase func(ctx context.Context) ([]byte, error)
}

// DefaultOrder returns the sources in Requirement 6.3 priority order.
func DefaultOrder(cfg Config) []Source {
	return []Source{
		NewOSKeyring(),
		NewSystemd(),
		NewKeyFile(cfg.KeyFile, cfg.DataDir),
		NewPassphrase(cfg.DataDir, cfg.Passphrase),
	}
}

// GenerateKey returns a fresh random Master_Key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// parseKey accepts raw 32 bytes, or 64 hex / base64 characters (surrounding whitespace ignored).
func parseKey(raw []byte) ([]byte, error) {
	if len(raw) == KeyLen {
		return append([]byte(nil), raw...), nil
	}
	text := strings.TrimSpace(string(raw))
	if b, err := hex.DecodeString(text); err == nil && len(b) == KeyLen {
		return b, nil
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(text); err == nil && len(b) == KeyLen {
			return b, nil
		}
	}
	return nil, errors.New("keysource: master key must be 32 bytes")
}

func zero(b []byte) { clear(b) }

// writeFileAtomic writes data to path through a temp file, fsync and rename.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".keysource-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	fail := func(err error) error {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
