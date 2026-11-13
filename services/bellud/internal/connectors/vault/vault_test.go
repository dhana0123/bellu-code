package vault

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/audit"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/keysource"
)

// memSource is an in-memory rotatable key source.
type memSource struct {
	mu    sync.Mutex
	slots map[string][]byte
}

func newMemSource() *memSource { return &memSource{slots: map[string][]byte{}} }

func (m *memSource) Name() string                   { return "mem" }
func (m *memSource) Available(context.Context) bool { return true }
func (m *memSource) Load(ctx context.Context) ([]byte, error) {
	return m.LoadSlot(ctx, keysource.SlotCurrent)
}
func (m *memSource) LoadSlot(_ context.Context, slot string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.slots[slot]
	if !ok {
		return nil, keysource.ErrNoKey
	}
	return append([]byte(nil), k...), nil
}
func (m *memSource) Store(_ context.Context, key []byte, slot string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.slots[slot] = append([]byte(nil), key...)
	return nil
}
func (m *memSource) Promote(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.slots[keysource.SlotCurrent] = m.slots[keysource.SlotNext]
	delete(m.slots, keysource.SlotNext)
	return nil
}

type failingLog struct{ audit.Log }

func (failingLog) Append(context.Context, audit.Entry) error { return errors.New("disk full") }

func openTest(t *testing.T, dir string, src keysource.Source, log audit.Log) *Store {
	t.Helper()
	opt := Options{Dir: dir, Audit: log}
	if src != nil {
		opt.Order = []keysource.Source{src}
	}
	s, err := Open(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newLog(t *testing.T) *audit.FileLog {
	t.Helper()
	l, err := audit.Open(filepath.Join(t.TempDir(), "audit"), audit.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func read(t *testing.T, s *Store, ref Ref) ([]byte, error) {
	t.Helper()
	var got []byte
	err := s.Use(context.Background(), ref, func(b []byte) error { got = append([]byte(nil), b...); return nil })
	return got, err
}

var ref = Ref{OwnerConnection, "cn_1", "primary"}

func TestRoundTripPersistsAcrossReopen(t *testing.T) {
	dir, src, log := filepath.Join(t.TempDir(), "v"), newMemSource(), newLog(t)
	s := openTest(t, dir, src, log)
	secret := []byte("ghp_secret-value-1234")
	if err := s.Put(context.Background(), ref, "github", append([]byte(nil), secret...), time.Time{}); err != nil {
		t.Fatal(err)
	}
	s2 := openTest(t, dir, src, log)
	got, err := read(t, s2, ref)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("got %q, %v", got, err)
	}
	m, ok := s2.Meta(ref)
	if !ok || m.Last4 != "1234" || m.Version != 1 {
		t.Fatalf("meta %+v", m)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "vault.json"))
	if bytes.Contains(raw, secret) {
		t.Fatal("plaintext in vault.json")
	}
	fi, _ := os.Stat(filepath.Join(dir, "vault.json"))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
}

func TestPutZeroesInputAndUseZeroesBuffer(t *testing.T) {
	s := openTest(t, "", nil, newLog(t))
	in := []byte("abcdefgh-secret")
	if err := s.Put(context.Background(), ref, "aws", in, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(in, make([]byte, len(in))) {
		t.Fatal("input not zeroed")
	}
	var buf []byte
	_ = s.Use(context.Background(), ref, func(b []byte) error { buf = b; return nil })
	if !bytes.Equal(buf, make([]byte, len(buf))) {
		t.Fatal("buffer not zeroed")
	}
}

func TestTamperAndAADBindingFailAndAudit(t *testing.T) {
	log := newLog(t)
	s := openTest(t, "", nil, log)
	if err := s.Put(context.Background(), ref, "aws", []byte("super-secret-value"), time.Time{}); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(r *record){
		"ciphertext": func(r *record) { r.Ciphertext[0] ^= 1 },
		"nonce":      func(r *record) { r.Nonce[0] ^= 1 },
		"wrapped":    func(r *record) { r.WrappedDEK[len(r.WrappedDEK)-1] ^= 1 },
		"connector":  func(r *record) { r.ConnectorID = "github" },
		"slot":       func(r *record) { r.Slot = "other" },
		"version":    func(r *record) { r.Version++ },
	}
	for name, mutate := range mutations {
		rec := *s.records[ref]
		rec.Ciphertext = bytes.Clone(rec.Ciphertext)
		rec.Nonce = bytes.Clone(rec.Nonce)
		rec.WrappedDEK = bytes.Clone(rec.WrappedDEK)
		orig := s.records[ref]
		mutate(&rec)
		s.records[ref] = &rec
		got, err := read(t, s, ref)
		s.records[ref] = orig
		if !errors.Is(err, ErrDecrypt) || got != nil {
			t.Fatalf("%s: got %q, %v", name, got, err)
		}
	}
	page, err := log.List("cn_1", "", 50)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range page.Entries {
		if e.Event == audit.EventDecryptFailed {
			n++
			for _, v := range e.Detail {
				if strings.Contains(v, "super-secret") {
					t.Fatal("secret in audit")
				}
			}
		}
	}
	if n != len(mutations) {
		t.Fatalf("decrypt_failed entries %d", n)
	}
}

func TestAuditFailureLeavesCredentialUnchanged(t *testing.T) {
	dir, src := filepath.Join(t.TempDir(), "v"), newMemSource()
	good := newLog(t)
	s := openTest(t, dir, src, good)
	if err := s.Put(context.Background(), ref, "aws", []byte("first-secret-value"), time.Time{}); err != nil {
		t.Fatal(err)
	}
	s.opt.Audit = failingLog{good}
	err := s.Put(context.Background(), ref, "aws", []byte("second-secret-value"), time.Time{})
	if !errors.Is(err, ErrAuditFailed) {
		t.Fatalf("err %v", err)
	}
	if got, _ := read(t, s, ref); string(got) != "first-secret-value" {
		t.Fatalf("got %q", got)
	}
}

func TestMemoryOnlyMode(t *testing.T) {
	s := openTest(t, "", nil, newLog(t))
	st := s.Status()
	if st.Persistent || st.Notice == "" {
		t.Fatalf("status %+v", st)
	}
	if err := s.Put(context.Background(), ref, "aws", []byte("memory-secret"), time.Time{}); err != nil {
		t.Fatal(err)
	}
	if got, _ := read(t, s, ref); string(got) != "memory-secret" {
		t.Fatal("round trip failed")
	}
}

func TestRefuseUnsafeModes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "v")
	src, log := newMemSource(), newLog(t)
	s := openTest(t, dir, src, log)
	if err := s.Put(context.Background(), ref, "aws", []byte("secret-value-xyz"), time.Time{}); err != nil {
		t.Fatal(err)
	}
	// A wrong mode is repaired once.
	if err := os.Chmod(filepath.Join(dir, "vault.json"), 0o644); err != nil {
		t.Fatal(err)
	}
	openTest(t, dir, src, log)
	fi, _ := os.Stat(filepath.Join(dir, "vault.json"))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode not repaired: %v", fi.Mode())
	}
}

func TestRotateMasterKey(t *testing.T) {
	dir, src, log := filepath.Join(t.TempDir(), "v"), newMemSource(), newLog(t)
	s := openTest(t, dir, src, log)
	if err := s.Put(context.Background(), ref, "aws", []byte("rotate-secret-value"), time.Time{}); err != nil {
		t.Fatal(err)
	}
	oldKid := s.kid
	if err := s.RotateMasterKey(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.kid == oldKid {
		t.Fatal("kid unchanged")
	}
	s2 := openTest(t, dir, src, log)
	if got, err := read(t, s2, ref); err != nil || string(got) != "rotate-secret-value" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestRotateFailureBeforeRenameKeepsOldFile(t *testing.T) {
	dir, src, log := filepath.Join(t.TempDir(), "v"), newMemSource(), newLog(t)
	s := openTest(t, dir, src, log)
	if err := s.Put(context.Background(), ref, "aws", []byte("rotate-secret-value"), time.Time{}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "vault.json"))
	s.opt.StepHook = func(step string) error {
		if step == "rename" {
			return errors.New("boom")
		}
		return nil
	}
	if err := s.RotateMasterKey(context.Background()); err == nil {
		t.Fatal("expected error")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "vault.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("vault.json changed")
	}
	if got, err := read(t, openTest(t, dir, src, log), ref); err != nil || string(got) != "rotate-secret-value" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestRecoveryPromotesNextAfterCrash(t *testing.T) {
	dir, src, log := filepath.Join(t.TempDir(), "v"), newMemSource(), newLog(t)
	s := openTest(t, dir, src, log)
	if err := s.Put(context.Background(), ref, "aws", []byte("crash-secret-value"), time.Time{}); err != nil {
		t.Fatal(err)
	}
	s.opt.StepHook = func(step string) error {
		if step == "promote" {
			return errors.New("crash")
		}
		return nil
	}
	_ = s.RotateMasterKey(context.Background())
	if got, err := read(t, openTest(t, dir, src, log), ref); err != nil || string(got) != "crash-secret-value" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestForgetAll(t *testing.T) {
	dir, src, log := filepath.Join(t.TempDir(), "v"), newMemSource(), newLog(t)
	s := openTest(t, dir, src, log)
	if err := s.Put(context.Background(), ref, "aws", []byte("forget-secret-value"), time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := s.ForgetAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := read(t, s, ref); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "vault.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("vault.json remains")
	}
	if err := s.Put(context.Background(), ref, "aws", []byte("after-forget-value"), time.Time{}); err != nil {
		t.Fatal(err)
	}
}
