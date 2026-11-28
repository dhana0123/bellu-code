package keysource

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zalando/go-keyring"
)

func TestOSKeyringUnavailableWithoutSecretService(t *testing.T) {
	keyring.MockInitWithError(errors.New("no secret service"))
	t.Cleanup(func() { keyring.MockInit() })
	start := time.Now()
	if NewOSKeyring().Available(context.Background()) {
		t.Fatal("expected unavailable")
	}
	if d := time.Since(start); d > keyringTimeout+time.Second {
		t.Fatalf("took %v", d)
	}
}

func TestOSKeyringRoundTripAndPromote(t *testing.T) {
	keyring.MockInit()
	ctx := context.Background()
	k := NewOSKeyring()
	if !k.Available(ctx) {
		t.Fatal("expected available")
	}
	if _, err := k.Load(ctx); !errors.Is(err, ErrNoKey) {
		t.Fatalf("got %v", err)
	}
	cur, _ := GenerateKey()
	next, _ := GenerateKey()
	if err := k.Store(ctx, cur, SlotCurrent); err != nil {
		t.Fatal(err)
	}
	if err := k.Store(ctx, next, SlotNext); err != nil {
		t.Fatal(err)
	}
	if err := k.Promote(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := k.Load(ctx)
	if err != nil || !bytes.Equal(got, next) {
		t.Fatalf("promote failed: %v", err)
	}
}

func TestSystemdReadsCredentialAndUnsetsEnv(t *testing.T) {
	dir := t.TempDir()
	key, _ := GenerateKey()
	if err := os.WriteFile(filepath.Join(dir, systemdCredName), key, 0o400); err != nil {
		t.Fatal(err)
	}
	t.Setenv(credentialsEnv, dir)
	s := NewSystemd()
	if !s.Available(context.Background()) {
		t.Fatal("expected available")
	}
	got, err := s.Load(context.Background())
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("load: %v", err)
	}
	if v := os.Getenv(credentialsEnv); v != "" {
		t.Fatalf("env not unset: %q", v)
	}
	if err := s.Store(context.Background(), key, SlotCurrent); !errors.Is(err, ErrStoreUnsupported) {
		t.Fatalf("got %v", err)
	}
}

func TestSystemdUnavailableWithoutEnv(t *testing.T) {
	t.Setenv(credentialsEnv, "")
	if NewSystemd().Available(context.Background()) {
		t.Fatal("expected unavailable")
	}
}

func TestKeyFileModeOwnerAndLocation(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	data := filepath.Join(root, "data")
	os.MkdirAll(data, 0o700)
	path := filepath.Join(root, "master.key")
	k := NewKeyFile(path, data)
	key, _ := GenerateKey()
	if err := k.Store(ctx, key, SlotCurrent); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o400 {
		t.Fatalf("mode %v", fi.Mode())
	}
	got, err := k.Load(ctx)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("load: %v", err)
	}
	// A loose mode is corrected once.
	os.Chmod(path, 0o644)
	if _, err := k.Load(ctx); err != nil {
		t.Fatalf("expected chmod repair: %v", err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o400 {
		t.Fatal("mode not repaired")
	}
	// Inside the data dir is rejected.
	inside := NewKeyFile(filepath.Join(data, "master.key"), data)
	var perr *PermissionError
	if err := inside.Store(ctx, key, SlotCurrent); !errors.As(err, &perr) || perr.Class != "key-file" {
		t.Fatalf("got %v", err)
	}
}

func TestPassphraseRulesAndStableDerivation(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	pw := "correct horse battery"
	src := NewPassphrase(dir, func(context.Context) ([]byte, error) { return []byte(pw), nil })
	k1, err := src.Load(ctx)
	if err != nil || len(k1) != KeyLen {
		t.Fatalf("load: %v", err)
	}
	k2, err := src.Load(ctx)
	if err != nil || !bytes.Equal(k1, k2) {
		t.Fatalf("derivation not stable: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(dir, headerFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("header: %v", err)
	}
	short := NewPassphrase(t.TempDir(), func(context.Context) ([]byte, error) { return []byte("elevenchars"), nil })
	if _, err := short.Load(ctx); !errors.Is(err, ErrPassphraseTooShort) {
		t.Fatalf("got %v", err)
	}
}

func TestSelectPicksFirstAvailableInOrder(t *testing.T) {
	ctx := context.Background()
	t.Setenv(credentialsEnv, "")
	dir := t.TempDir()
	pass := NewPassphrase(dir, func(context.Context) ([]byte, error) { return nil, nil })
	got, err := Select(ctx, []Source{NewSystemd(), NewKeyFile("", dir), pass})
	if err != nil || got.Name() != NamePassphrase {
		t.Fatalf("got %v %v", got, err)
	}
	if _, err := Select(ctx, []Source{NewSystemd()}); !errors.Is(err, ErrNoSource) {
		t.Fatalf("got %v", err)
	}
}
