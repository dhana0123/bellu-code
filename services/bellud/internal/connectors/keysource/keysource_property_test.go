package keysource

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"pgregory.net/rapid"
)

// fakeSource is an in-memory Source; it never touches the OS keyring.
type fakeSource struct {
	name      string
	available bool
}

func (f *fakeSource) Name() string                                { return f.name }
func (f *fakeSource) Available(context.Context) bool              { return f.available }
func (f *fakeSource) Load(context.Context) ([]byte, error)        { return nil, ErrNoKey }
func (f *fakeSource) Store(context.Context, []byte, string) error { return ErrStoreUnsupported }

func promptOf(pw string) func(context.Context) ([]byte, error) {
	return func(context.Context) ([]byte, error) { return []byte(pw), nil }
}

// Feature: cloud-connectors, Property 27: Master key source selection and passphrase rules
// Validates: Requirements 6.3
func TestPropertySelectFirstAvailable(t *testing.T) {
	names := []string{NameOSKeyring, NameSystemd, NameKeyFile, NamePassphrase}
	rapid.Check(t, func(t *rapid.T) {
		order := make([]Source, len(names))
		want := ""
		for i, n := range names {
			avail := rapid.Bool().Draw(t, n)
			order[i] = &fakeSource{name: n, available: avail}
			if avail && want == "" {
				want = n
			}
		}
		got, err := Select(context.Background(), order)
		if want == "" {
			if !errors.Is(err, ErrNoSource) {
				t.Fatalf("expected ErrNoSource, got %v", err)
			}
			return
		}
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Name() != want {
			t.Fatalf("selected %q, want %q", got.Name(), want)
		}
	})
}

// Feature: cloud-connectors, Property 27: Master key source selection and passphrase rules
// Validates: Requirements 6.6
func TestPropertyPassphraseAcceptedIffAtLeast12Chars(t *testing.T) {
	tt := t
	rapid.Check(t, func(t *rapid.T) {
		// Bias toward the boundary at 12 characters.
		pw := rapid.StringN(0, 24, -1).Draw(t, "passphrase")
		src := NewPassphrase(tt.TempDir(), promptOf(pw))
		key, err := src.Load(context.Background())
		long := len([]rune(pw)) >= 12
		if long {
			if err != nil {
				t.Fatalf("expected accept, got %v", err)
			}
			if len(key) != KeyLen {
				t.Fatalf("key length %d, want %d", len(key), KeyLen)
			}
			return
		}
		if !errors.Is(err, ErrPassphraseTooShort) {
			t.Fatalf("expected ErrPassphraseTooShort, got %v", err)
		}
	})
}

// Feature: cloud-connectors, Property 27: Master key source selection and passphrase rules
// Validates: Requirements 6.6
func TestPropertyPassphraseDerivationDeterminismAndSalt(t *testing.T) {
	tt := t
	ctx := context.Background()
	rapid.Check(t, func(t *rapid.T) {
		pw := rapid.StringN(12, 40, -1).Draw(t, "passphrase")
		dir := tt.TempDir()
		first, err := NewPassphrase(dir, promptOf(pw)).Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		// Same header (same salt): deterministic.
		again, err := NewPassphrase(dir, promptOf(pw)).Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first, again) {
			t.Fatal("same passphrase and salt produced different keys")
		}
		// Fresh directory: new random salt, so the key differs.
		other, err := NewPassphrase(tt.TempDir(), promptOf(pw)).Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(first, other) {
			t.Fatal("different salts produced the same key")
		}
	})
}

// Feature: cloud-connectors, Property 27: Master key source selection and passphrase rules
// Validates: Requirements 6.6
func TestPropertyPassphraseHeaderParamsAtLeastMinimum(t *testing.T) {
	tt := t
	rapid.Check(t, func(t *rapid.T) {
		pw := rapid.StringN(12, 20, -1).Draw(t, "passphrase")
		dir := tt.TempDir()
		if _, err := NewPassphrase(dir, promptOf(pw)).Load(context.Background()); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join(dir, headerFile))
		if err != nil {
			t.Fatal(err)
		}
		var h header
		if err := json.Unmarshal(raw, &h); err != nil {
			t.Fatal(err)
		}
		p, ok := h.Slots[SlotCurrent]
		if !ok {
			t.Fatal("no current slot in header")
		}
		if p.Memory < 64*1024 || p.Time < 3 || len(p.Salt) < 16 {
			t.Fatalf("weak params: m=%d t=%d saltLen=%d", p.Memory, p.Time, len(p.Salt))
		}
	})
}
