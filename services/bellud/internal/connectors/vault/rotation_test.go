package vault

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/audit"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/keysource"
)

// fixedSource can load a key but not store one (like env or systemd).
type fixedSource struct{ key []byte }

func (fixedSource) Name() string                   { return "fixed" }
func (fixedSource) Available(context.Context) bool { return true }
func (f fixedSource) Load(context.Context) ([]byte, error) {
	return append([]byte(nil), f.key...), nil
}
func (fixedSource) Store(context.Context, []byte, string) error {
	return keysource.ErrStoreUnsupported
}

func putSecret(t *testing.T, s *Store, secret string) {
	t.Helper()
	if err := s.Put(context.Background(), ref, "aws", []byte(secret), time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func TestRotateStagesNextThenPromotes(t *testing.T) {
	dir, src, log := filepath.Join(t.TempDir(), "v"), newMemSource(), newLog(t)
	s := openTest(t, dir, src, log)
	putSecret(t, s, "rotate-secret-value")
	var sawNext, sawNew bool
	s.opt.StepHook = func(step string) error {
		if step == "rename" {
			_, err := src.LoadSlot(context.Background(), keysource.SlotNext)
			sawNext = err == nil
			_, err = os.Stat(filepath.Join(dir, newFile))
			sawNew = err == nil
		}
		return nil
	}
	if err := s.RotateMasterKey(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !sawNext || !sawNew {
		t.Fatalf("next slot %v, vault.json.new %v before rename", sawNext, sawNew)
	}
	if _, err := src.LoadSlot(context.Background(), keysource.SlotNext); !errors.Is(err, keysource.ErrNoKey) {
		t.Fatalf("next slot not promoted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, newFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("vault.json.new remains")
	}
	cur, _ := src.Load(context.Background())
	if keyID(cur) != s.kid {
		t.Fatal("current slot does not hold the new key")
	}
}

func TestRotateWritesNoPlaintext(t *testing.T) {
	dir, src, log := filepath.Join(t.TempDir(), "v"), newMemSource(), newLog(t)
	s := openTest(t, dir, src, log)
	secret := []byte("plaintext-canary-value")
	putSecret(t, s, string(secret))
	s.opt.StepHook = func(step string) error {
		if step == "rename" {
			raw, _ := os.ReadFile(filepath.Join(dir, newFile))
			if len(raw) == 0 || bytes.Contains(raw, secret) {
				t.Error("vault.json.new empty or contains plaintext")
			}
		}
		return nil
	}
	if err := s.RotateMasterKey(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRotateFailureAtAnyStepKeepsOldFileAndKey(t *testing.T) {
	for _, step := range []string{"store-next", "rewrap", "write-new", "audit", "rename"} {
		t.Run(step, func(t *testing.T) {
			dir, src, log := filepath.Join(t.TempDir(), "v"), newMemSource(), newLog(t)
			s := openTest(t, dir, src, log)
			putSecret(t, s, "rotate-secret-value")
			before, _ := os.ReadFile(filepath.Join(dir, vaultFile))
			oldKid := s.kid
			s.opt.StepHook = func(got string) error {
				if got == step {
					return errors.New("boom")
				}
				return nil
			}
			if err := s.RotateMasterKey(context.Background()); err == nil {
				t.Fatal("expected error")
			}
			after, _ := os.ReadFile(filepath.Join(dir, vaultFile))
			if !bytes.Equal(before, after) {
				t.Fatal("vault.json changed")
			}
			if _, err := os.Stat(filepath.Join(dir, newFile)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("vault.json.new left behind")
			}
			if s.kid != oldKid {
				t.Fatal("kid changed")
			}
			if got, err := read(t, s, ref); err != nil || string(got) != "rotate-secret-value" {
				t.Fatalf("got %q, %v", got, err)
			}
			if got, err := read(t, openTest(t, dir, src, log), ref); err != nil || string(got) != "rotate-secret-value" {
				t.Fatalf("reopen: got %q, %v", got, err)
			}
		})
	}
}

func TestRotateAuditFailureReturnsErrorAndKeepsFile(t *testing.T) {
	dir, src, good := filepath.Join(t.TempDir(), "v"), newMemSource(), newLog(t)
	s := openTest(t, dir, src, good)
	putSecret(t, s, "rotate-secret-value")
	before, _ := os.ReadFile(filepath.Join(dir, vaultFile))
	s.opt.Audit = failingLog{good}
	if err := s.RotateMasterKey(context.Background()); !errors.Is(err, ErrAuditFailed) {
		t.Fatalf("err %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, vaultFile))
	if !bytes.Equal(before, after) {
		t.Fatal("vault.json changed")
	}
}

func TestRecoveryPromotesNextSlot(t *testing.T) {
	dir, src, log := filepath.Join(t.TempDir(), "v"), newMemSource(), newLog(t)
	s := openTest(t, dir, src, log)
	putSecret(t, s, "crash-secret-value")
	s.opt.StepHook = func(step string) error {
		if step == "promote" {
			return errors.New("crash")
		}
		return nil
	}
	if err := s.RotateMasterKey(context.Background()); err == nil {
		t.Fatal("expected error")
	}
	if _, err := src.LoadSlot(context.Background(), keysource.SlotNext); err != nil {
		t.Fatalf("next slot should still exist: %v", err)
	}
	s2 := openTest(t, dir, src, log)
	if _, err := src.LoadSlot(context.Background(), keysource.SlotNext); !errors.Is(err, keysource.ErrNoKey) {
		t.Fatalf("next not promoted on startup: %v", err)
	}
	if s2.kid != s.kid {
		t.Fatal("recovered kid differs")
	}
}

func TestRecoveryIgnoresNextWithWrongKid(t *testing.T) {
	dir, src, log := filepath.Join(t.TempDir(), "v"), newMemSource(), newLog(t)
	s := openTest(t, dir, src, log)
	putSecret(t, s, "secret-value-xyz")
	stray, _ := keysource.GenerateKey()
	_ = src.Store(context.Background(), stray, keysource.SlotNext)
	// Current key still matches the file: stray next slot is left alone.
	if got, err := read(t, openTest(t, dir, src, log), ref); err != nil || string(got) != "secret-value-xyz" {
		t.Fatalf("got %q, %v", got, err)
	}
	// Replace current with an unrelated key: neither slot matches.
	other, _ := keysource.GenerateKey()
	_ = src.Store(context.Background(), other, keysource.SlotCurrent)
	if _, err := Open(context.Background(), Options{Dir: dir, Audit: log, Order: []keysource.Source{src}}); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("err %v", err)
	}
}

func TestOpenRemovesStaleNewFile(t *testing.T) {
	dir, src, log := filepath.Join(t.TempDir(), "v"), newMemSource(), newLog(t)
	putSecret(t, openTest(t, dir, src, log), "secret-value-xyz")
	stale := filepath.Join(dir, newFile)
	if err := os.WriteFile(stale, []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	openTest(t, dir, src, log)
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stale vault.json.new remains")
	}
}

func TestRotationOnlyOfferedForStorableSources(t *testing.T) {
	log := newLog(t)
	key, _ := keysource.GenerateKey()
	fixed := openTest(t, filepath.Join(t.TempDir(), "v"), fixedSource{key}, log)
	if fixed.Status().CanRotate {
		t.Fatal("non-storable source must not offer rotation")
	}
	putSecret(t, fixed, "secret-value-xyz")
	before, _ := os.ReadFile(filepath.Join(fixed.opt.Dir, vaultFile))
	if err := fixed.RotateMasterKey(context.Background()); !errors.Is(err, ErrRotationUnsupported) {
		t.Fatalf("err %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(fixed.opt.Dir, vaultFile))
	if !bytes.Equal(before, after) {
		t.Fatal("vault.json changed")
	}
	mem := openTest(t, "", nil, log)
	if mem.Status().CanRotate {
		t.Fatal("memory-only must not offer rotation")
	}
	if err := mem.RotateMasterKey(context.Background()); !errors.Is(err, ErrRotationUnsupported) {
		t.Fatalf("err %v", err)
	}
	if !openTest(t, filepath.Join(t.TempDir(), "v"), newMemSource(), log).Status().CanRotate {
		t.Fatal("rotatable source must offer rotation")
	}
}

func TestForgetAllDropsKeyCredentialsAndAudits(t *testing.T) {
	dir, src, log := filepath.Join(t.TempDir(), "v"), newMemSource(), newLog(t)
	s := openTest(t, dir, src, log)
	putSecret(t, s, "forget-secret-value")
	rec := s.records[ref]
	key := s.key
	start := time.Now()
	if err := s.ForgetAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("ForgetAll exceeded 5s")
	}
	if s.key != nil || s.kid != "" || !bytes.Equal(key, make([]byte, len(key))) {
		t.Fatal("master key not dropped and zeroed")
	}
	if len(s.records) != 0 || !bytes.Equal(rec.Ciphertext, make([]byte, len(rec.Ciphertext))) {
		t.Fatal("in-memory credentials not cleared")
	}
	if _, ok := s.Meta(ref); ok {
		t.Fatal("meta remains")
	}
	for _, name := range []string{vaultFile, newFile, tmpFile} {
		if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s remains", name)
		}
	}
	page, err := log.List("", "", 50)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range page.Entries {
		found = found || e.Event == audit.EventVaultForget
	}
	if !found {
		t.Fatal("vault_forget not audited")
	}
}

func TestForgetAllMemoryOnly(t *testing.T) {
	s := openTest(t, "", nil, newLog(t))
	putSecret(t, s, "memory-secret")
	if err := s.ForgetAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := read(t, s, ref); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err %v", err)
	}
}

func TestForgetAllHonoursDeadline(t *testing.T) {
	s := openTest(t, "", nil, newLog(t))
	putSecret(t, s, "memory-secret")
	if ForgetTimeout != 5*time.Second {
		t.Fatalf("timeout %v", ForgetTimeout)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// A cancelled context must not hang; the call returns promptly either way.
	done := make(chan struct{})
	go func() { _ = s.ForgetAll(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ForgetAll hung")
	}
}
