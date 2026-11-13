// Package vault stores connector credentials with envelope encryption.
//
// Every credential gets its own random 256-bit data key (DEK) and is sealed
// with AES-256-GCM under a fresh 96-bit nonce. The DEK is wrapped under the
// Master_Key supplied by package keysource. The Master_Key never lives in the
// vault directory. Plaintext only exists inside the Opener.Use callback.
package vault

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/audit"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/keysource"
)

// OwnerKind says what a credential belongs to.
type OwnerKind string

const (
	OwnerConnection OwnerKind = "connection"
	OwnerAuthConfig OwnerKind = "authconfig"
)

// Limits and file names.
const (
	MaxSecretLen = 65536
	// ForgetTimeout bounds ForgetAll.
	ForgetTimeout = 5 * time.Second
	// MemoryOnlyNotice is shown in the UI when no key source is available.
	MemoryOnlyNotice = "No master key source is available. Credentials are kept in memory only and are lost when bellud stops."

	vaultFile  = "vault.json"
	newFile    = "vault.json.new"
	tmpFile    = "vault.json.tmp"
	aadPrefix  = "bellud.vault.v1"
	kidPrefix  = "bellud.kid"
	memorySrc  = "memory"
	fileFormat = 1
)

// Errors. Messages never contain key material, ciphertext or plaintext.
var (
	ErrNotFound            = errors.New("vault: credential not found")
	ErrDecrypt             = errors.New("vault: credential cannot be decrypted")
	ErrAuditFailed         = errors.New("audit_failed")
	ErrInvalidSecret       = errors.New("vault: secret must be 1-65536 bytes")
	ErrKeyMismatch         = errors.New("vault: master key does not match the vault")
	ErrRotationUnsupported = errors.New("vault: master key rotation is not supported by the active key source")
	ErrCorrupt             = errors.New("vault: vault.json is unreadable")
)

// Ref identifies one stored credential.
type Ref struct {
	Owner   OwnerKind
	OwnerID string
	Slot    string
}

// Meta is the non-secret description of a credential. Last4 is empty for
// secrets shorter than 8 characters so short secrets are never revealed.
type Meta struct {
	Last4     string
	CreatedAt time.Time
	ExpiresAt time.Time
	Version   uint64
}

// Status describes the active key source.
type Status struct {
	KeySource  string
	Persistent bool
	// CanRotate is true only when the key source can store a new key
	// (os-keyring, key file, passphrase). The UI offers rotation only then.
	CanRotate bool
	// Notice is the UI warning, empty when the vault is persistent.
	Notice string
	// Locked is true when a key source exists but the Master_Key is not cached
	// (after ForgetAll, or before a passphrase was entered).
	Locked bool
}

// Vault is the store side: no plaintext leaves it.
type Vault interface {
	// Put seals secret and zeroes it, also on failure.
	Put(ctx context.Context, ref Ref, connectorID string, secret []byte, exp time.Time) error
	Delete(ctx context.Context, ref Ref) error
	Meta(ref Ref) (Meta, bool)
	RotateMasterKey(ctx context.Context) error
	ForgetAll(ctx context.Context) error
	Status() Status
}

// Opener is the use side: plaintext only inside the callback.
type Opener interface {
	// Use calls fn with the plaintext and zeroes the buffer when fn returns.
	Use(ctx context.Context, ref Ref, fn func(secret []byte) error) error
}

// Options configures Open.
type Options struct {
	// Dir is the vault directory (mode 0700) that holds vault.json.
	Dir string
	// Order is the key source priority order; empty or all unavailable means memory-only.
	Order []keysource.Source
	// Audit receives vault events. Required.
	Audit audit.Log
	Now   func() time.Time
	// StepHook, if set, is called before each master-key rotation step
	// ("store-next", "rewrap", "write-new", "audit", "rename", "promote");
	// a non-nil result aborts at that step. For fault injection in tests.
	StepHook func(step string) error
}

type record struct {
	Owner       OwnerKind  `json:"owner"`
	OwnerID     string     `json:"ownerId"`
	Slot        string     `json:"slot"`
	ConnectorID string     `json:"connectorId"`
	Version     uint64     `json:"version"`
	CreatedAt   time.Time  `json:"createdAt"`
	ExpiresAt   *time.Time `json:"expiresAt"`
	Last4       string     `json:"last4"`
	WrappedDEK  []byte     `json:"wrappedDek"`
	Nonce       []byte     `json:"nonce"`
	Ciphertext  []byte     `json:"ciphertext"`
}

type fileDoc struct {
	Version int      `json:"version"`
	Kid     string   `json:"kid"`
	Records []record `json:"records"`
}

// Store implements Vault and Opener.
type Store struct {
	opt Options
	src keysource.Source // nil in memory-only mode

	mu      sync.RWMutex
	key     []byte
	kid     string
	records map[Ref]*record
}

var (
	_ Vault  = (*Store)(nil)
	_ Opener = (*Store)(nil)
)

// Open verifies the directory and file modes, selects the key source, loads
// the Master_Key and reads vault.json. With no available source it returns a
// memory-only vault.
func Open(ctx context.Context, opt Options) (*Store, error) {
	if opt.Audit == nil {
		return nil, errors.New("vault: audit log is required")
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	s := &Store{opt: opt, records: map[Ref]*record{}}
	src, err := keysource.Select(ctx, opt.Order)
	if errors.Is(err, keysource.ErrNoSource) {
		key, err := keysource.GenerateKey()
		if err != nil {
			return nil, err
		}
		s.setKey(key)
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	s.src = src
	if err := verifyModes(opt.Dir); err != nil {
		return nil, err
	}
	// A leftover vault.json.new is never authoritative: drop it.
	_ = os.Remove(filepath.Join(opt.Dir, newFile))
	doc, err := readDoc(opt.Dir)
	if err != nil {
		return nil, err
	}
	if err := s.loadKey(ctx, doc); err != nil {
		return nil, err
	}
	for i := range doc.Records {
		r := doc.Records[i]
		s.records[Ref{r.Owner, r.OwnerID, r.Slot}] = &r
	}
	return s, nil
}

// Close drops the cached Master_Key. Stored credentials stay on disk; the key
// is reloaded from the key source on the next use.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropKey()
	return nil
}

// Status reports the key source and whether credentials persist.
func (s *Store) Status() Status {
	if s.src == nil {
		return Status{KeySource: memorySrc, Notice: MemoryOnlyNotice}
	}
	s.mu.RLock()
	locked := s.key == nil
	s.mu.RUnlock()
	return Status{KeySource: s.src.Name(), Persistent: true, CanRotate: canRotate(s.src), Locked: locked}
}

// Unlock loads the Master_Key from the key source when it is not cached. It is
// a no-op for a memory-only vault and for an already unlocked one.
func (s *Store) Unlock(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.src == nil || s.key != nil {
		return nil
	}
	doc, err := readDoc(s.opt.Dir)
	if err != nil {
		return err
	}
	return s.loadKey(ctx, doc)
}

func canRotate(src keysource.Source) bool {
	if _, ok := src.(keysource.Rotatable); ok {
		return true
	}
	_, ok := src.(interface {
		PrepareNext(context.Context) ([]byte, error)
	})
	return ok
}

// Meta returns the non-secret description of ref.
func (s *Store) Meta(ref Ref) (Meta, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.records[ref]
	if !ok {
		return Meta{}, false
	}
	m := Meta{Last4: r.Last4, CreatedAt: r.CreatedAt, Version: r.Version}
	if r.ExpiresAt != nil {
		m.ExpiresAt = *r.ExpiresAt
	}
	return m, true
}

// Put seals secret under a fresh DEK and nonce. The audit entry is written
// first; if that fails nothing is stored. secret is zeroed before returning.
func (s *Store) Put(ctx context.Context, ref Ref, connectorID string, secret []byte, exp time.Time) error {
	defer func() { clear(secret); runtime.KeepAlive(secret) }()
	if len(secret) == 0 || len(secret) > MaxSecretLen {
		return ErrInvalidSecret
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureKey(ctx); err != nil {
		return err
	}
	prev := s.records[ref]
	version := uint64(1)
	event := audit.EventConnect
	if prev != nil {
		version = prev.Version + 1
		event = audit.EventRotate
	}
	if err := s.audit(ctx, ref, connectorID, event, audit.OutcomeSuccess, map[string]string{"slot": ref.Slot, "owner": string(ref.Owner)}); err != nil {
		return err
	}
	rec := &record{
		Owner: ref.Owner, OwnerID: ref.OwnerID, Slot: ref.Slot, ConnectorID: connectorID,
		Version: version, CreatedAt: s.opt.Now().UTC(), Last4: last4(secret),
	}
	if !exp.IsZero() {
		e := exp.UTC()
		rec.ExpiresAt = &e
	}
	if err := s.seal(rec, secret); err != nil {
		return err
	}
	s.records[ref] = rec
	if err := s.persist(); err != nil {
		restore(s.records, ref, prev)
		return err
	}
	return nil
}

// Delete removes a credential. Deleting a missing ref is not an error.
func (s *Store) Delete(_ context.Context, ref Ref) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, ok := s.records[ref]
	if !ok {
		return nil
	}
	delete(s.records, ref)
	if err := s.persist(); err != nil {
		restore(s.records, ref, prev)
		return err
	}
	return nil
}

// Use decrypts ref and passes the plaintext to fn. The buffer is zeroed when
// fn returns. A decrypt failure is audited with the ref only.
func (s *Store) Use(ctx context.Context, ref Ref, fn func(secret []byte) error) error {
	s.mu.RLock()
	rec, ok := s.records[ref]
	if !ok {
		s.mu.RUnlock()
		return ErrNotFound
	}
	plain, err := s.open(rec)
	connectorID := rec.ConnectorID
	s.mu.RUnlock()
	if err != nil {
		_ = s.audit(ctx, ref, connectorID, audit.EventDecryptFailed, audit.OutcomeFailure,
			map[string]string{"owner": string(ref.Owner), "ownerId": ref.OwnerID, "slot": ref.Slot})
		return ErrDecrypt
	}
	defer func() { clear(plain); runtime.KeepAlive(plain) }()
	return fn(plain)
}

// ForgetAll deletes every record and wrapped key, drops the cached
// Master_Key and clears in-memory credentials.
func (s *Store) ForgetAll(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, ForgetTimeout)
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.audit(ctx, Ref{}, "", audit.EventVaultForget, audit.OutcomeSuccess, nil); err != nil {
		return err
	}
	if s.src != nil {
		for _, name := range []string{vaultFile, newFile, tmpFile} {
			if err := os.Remove(filepath.Join(s.opt.Dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	for ref, r := range s.records {
		clear(r.Ciphertext)
		clear(r.WrappedDEK)
		delete(s.records, ref)
	}
	s.dropKey()
	return nil
}

// RotateMasterKey re-wraps every DEK under a new Master_Key. The old
// vault.json stays untouched until the new file is complete and renamed.
func (s *Store) RotateMasterKey(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.src == nil {
		return ErrRotationUnsupported
	}
	if err := s.ensureKey(ctx); err != nil {
		return err
	}
	newKey, promote, err := s.stageNextKey(ctx)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			clear(newKey)
		}
	}()
	newKid := keyID(newKey)
	if err := s.step("rewrap"); err != nil {
		return err
	}
	doc := fileDoc{Version: fileFormat, Kid: newKid}
	rewrapped := map[Ref]*record{}
	for ref, r := range s.records {
		dek, err := s.unwrap(r)
		if err != nil {
			return ErrDecrypt
		}
		c := *r
		c.WrappedDEK, err = wrapDEK(newKey, newKid, &c, dek)
		clear(dek)
		if err != nil {
			return err
		}
		rewrapped[ref] = &c
		doc.Records = append(doc.Records, c)
	}
	if err := s.step("write-new"); err != nil {
		return err
	}
	abort := func(err error) error {
		os.Remove(filepath.Join(s.opt.Dir, newFile))
		return err
	}
	if err := writeFile(filepath.Join(s.opt.Dir, newFile), doc); err != nil {
		return abort(err)
	}
	if err := s.step("audit"); err != nil {
		return abort(err)
	}
	if err := s.audit(ctx, Ref{}, "", audit.EventMasterKeyRotate, audit.OutcomeSuccess, map[string]string{"kid": newKid}); err != nil {
		return abort(err)
	}
	if err := s.step("rename"); err != nil {
		return abort(err)
	}
	if err := commit(s.opt.Dir, newFile); err != nil {
		return abort(err)
	}
	ok = true
	s.dropKey()
	s.setKey(newKey)
	s.records = rewrapped
	if err := s.step("promote"); err != nil {
		return err
	}
	return promote(ctx)
}

// stageNextKey creates the new key in SlotNext of the active source.
func (s *Store) stageNextKey(ctx context.Context) (key []byte, promote func(context.Context) error, err error) {
	if err := s.step("store-next"); err != nil {
		return nil, nil, err
	}
	switch src := s.src.(type) {
	case keysource.Rotatable:
		key, err = keysource.GenerateKey()
		if err != nil {
			return nil, nil, err
		}
		if err := src.Store(ctx, key, keysource.SlotNext); err != nil {
			clear(key)
			if errors.Is(err, keysource.ErrStoreUnsupported) {
				return nil, nil, ErrRotationUnsupported
			}
			return nil, nil, err
		}
		return key, src.Promote, nil
	case interface {
		PrepareNext(context.Context) ([]byte, error)
		Promote(context.Context) error
	}:
		key, err = src.PrepareNext(ctx)
		if err != nil {
			return nil, nil, err
		}
		return key, src.Promote, nil
	}
	return nil, nil, ErrRotationUnsupported
}

func (s *Store) step(name string) error {
	if s.opt.StepHook == nil {
		return nil
	}
	return s.opt.StepHook(name)
}

// loadKey loads the Master_Key and checks it against the file's kid. After a
// crash between the rename and the promote it adopts the "next" key.
func (s *Store) loadKey(ctx context.Context, doc fileDoc) error {
	key, err := s.src.Load(ctx)
	if errors.Is(err, keysource.ErrNoKey) {
		if len(doc.Records) > 0 {
			return ErrKeyMismatch
		}
		if key, err = keysource.GenerateKey(); err != nil {
			return err
		}
		if err := s.src.Store(ctx, key, keysource.SlotCurrent); err != nil {
			clear(key)
			return err
		}
	} else if err != nil {
		return err
	}
	if len(doc.Records) == 0 || doc.Kid == keyID(key) {
		s.setKey(key)
		return nil
	}
	if rot, ok := s.src.(keysource.Rotatable); ok {
		next, nerr := rot.LoadSlot(ctx, keysource.SlotNext)
		if nerr == nil && keyID(next) == doc.Kid {
			clear(key)
			if err := rot.Promote(ctx); err != nil {
				clear(next)
				return err
			}
			s.setKey(next)
			return nil
		}
		clear(next)
	}
	clear(key)
	return ErrKeyMismatch
}

// ensureKey reloads the key after ForgetAll. Caller holds s.mu.
func (s *Store) ensureKey(ctx context.Context) error {
	if s.key != nil {
		return nil
	}
	if s.src == nil {
		key, err := keysource.GenerateKey()
		if err != nil {
			return err
		}
		s.setKey(key)
		return nil
	}
	return s.loadKey(ctx, fileDoc{})
}

func (s *Store) setKey(key []byte) {
	_ = keysource.Lock(key)
	s.key = key
	s.kid = keyID(key)
}

func (s *Store) dropKey() {
	if s.key == nil {
		return
	}
	_ = keysource.Unlock(s.key)
	clear(s.key)
	s.key, s.kid = nil, ""
}

func (s *Store) audit(ctx context.Context, ref Ref, connectorID, event, outcome string, detail map[string]string) error {
	err := s.opt.Audit.Append(ctx, audit.Entry{
		TS: s.opt.Now().UTC(), ConnectionID: ref.OwnerID, ConnectorID: connectorID,
		Event: event, Outcome: outcome, Actor: audit.ActorSystem, Detail: detail,
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAuditFailed, err)
	}
	return nil
}

func (s *Store) persist() error {
	if s.src == nil {
		return nil
	}
	doc := fileDoc{Version: fileFormat, Kid: s.kid}
	for _, r := range s.records {
		doc.Records = append(doc.Records, *r)
	}
	if err := writeFile(filepath.Join(s.opt.Dir, tmpFile), doc); err != nil {
		return err
	}
	return commit(s.opt.Dir, tmpFile)
}

func restore(m map[Ref]*record, ref Ref, prev *record) {
	if prev == nil {
		delete(m, ref)
		return
	}
	m[ref] = prev
}

// seal fills the ciphertext fields of rec. The DEK never leaves this function unwrapped.
func (s *Store) seal(rec *record, secret []byte) error {
	dek := make([]byte, keysource.KeyLen)
	defer func() { clear(dek); runtime.KeepAlive(dek) }()
	if _, err := rand.Read(dek); err != nil {
		return err
	}
	gcm, err := newGCM(dek)
	if err != nil {
		return err
	}
	rec.Nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(rec.Nonce); err != nil {
		return err
	}
	rec.Ciphertext = gcm.Seal(nil, rec.Nonce, secret, sealAAD(rec))
	rec.WrappedDEK, err = wrapDEK(s.key, s.kid, rec, dek)
	return err
}

// open returns the plaintext of rec. The caller zeroes it.
func (s *Store) open(rec *record) ([]byte, error) {
	dek, err := s.unwrap(rec)
	if err != nil {
		return nil, err
	}
	defer func() { clear(dek); runtime.KeepAlive(dek) }()
	gcm, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	if len(rec.Nonce) != gcm.NonceSize() {
		return nil, ErrDecrypt
	}
	return gcm.Open(nil, rec.Nonce, rec.Ciphertext, sealAAD(rec))
}

func (s *Store) unwrap(rec *record) ([]byte, error) {
	if s.key == nil {
		return nil, ErrDecrypt
	}
	gcm, err := newGCM(s.key)
	if err != nil {
		return nil, err
	}
	n := gcm.NonceSize()
	if len(rec.WrappedDEK) < n {
		return nil, ErrDecrypt
	}
	return gcm.Open(nil, rec.WrappedDEK[:n], rec.WrappedDEK[n:], wrapAAD(s.kid, rec))
}

func wrapDEK(key []byte, kid string, rec *record, dek []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, dek, wrapAAD(kid, rec)), nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sealAAD binds connector id, owner id, slot and version, length-prefixed so fields cannot shift.
func sealAAD(r *record) []byte {
	b := []byte(aadPrefix)
	for _, f := range []string{r.ConnectorID, r.OwnerID, r.Slot} {
		b = binary.BigEndian.AppendUint32(b, uint32(len(f)))
		b = append(b, f...)
	}
	return binary.BigEndian.AppendUint64(b, r.Version)
}

func wrapAAD(kid string, r *record) []byte {
	return fmt.Appendf(nil, "%s|%s|%s|%s|%d", kid, r.Owner, r.OwnerID, r.Slot, r.Version)
}

func keyID(key []byte) string {
	h := sha256.Sum256(append([]byte(kidPrefix), key...))
	return hex.EncodeToString(h[:8])
}

// last4 returns the last four characters, or "" when the secret is shorter than eight.
func last4(secret []byte) string {
	if utf8.RuneCount(secret) < 8 {
		return ""
	}
	end := len(secret)
	start := end
	for i := 0; i < 4; i++ {
		_, size := utf8.DecodeLastRune(secret[:start])
		start -= size
	}
	return string(bytes.ToValidUTF8(secret[start:end], []byte("?")))
}
