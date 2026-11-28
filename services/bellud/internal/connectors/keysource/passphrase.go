package keysource

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters (Requirement 6.6, design D9).
const (
	MinPassphraseLen = 12
	saltLen          = 16
	argonMemoryKiB   = 65536 // 64 MiB
	argonTime        = 3
	argonThreads     = 4
	headerFile       = "keysource.json"
)

type kdfParams struct {
	Salt    []byte `json:"salt"`
	Memory  uint32 `json:"m"`
	Time    uint32 `json:"t"`
	Threads uint8  `json:"p"`
}

// header is the non-secret KDF description stored beside vault.json.
type header struct {
	Version int                  `json:"version"`
	KDF     string               `json:"kdf"`
	Slots   map[string]kdfParams `json:"slots"`
}

type passphrase struct {
	dir    string
	prompt func(ctx context.Context) ([]byte, error)
}

// NewPassphrase returns the passphrase source. dir is the vault directory that
// holds the header file keysource.json; prompt supplies the passphrase.
func NewPassphrase(dir string, prompt func(ctx context.Context) ([]byte, error)) Source {
	return &passphrase{dir: dir, prompt: prompt}
}

func (p *passphrase) Name() string { return NamePassphrase }

func (p *passphrase) Available(context.Context) bool { return p.prompt != nil && p.dir != "" }

// Load derives the key from the current slot, creating the header with a fresh
// salt on first use.
func (p *passphrase) Load(ctx context.Context) ([]byte, error) {
	h, err := p.readHeader()
	if err != nil {
		return nil, err
	}
	params, ok := h.Slots[SlotCurrent]
	if !ok {
		params = newParams()
		h.Slots[SlotCurrent] = params
	}
	key, err := p.derive(ctx, params)
	if err != nil {
		return nil, err
	}
	if !ok {
		if err := p.writeHeader(h); err != nil {
			zero(key)
			return nil, err
		}
	}
	return key, nil
}

// Store is unsupported: a passphrase cannot store an arbitrary key. Use PrepareNext.
func (p *passphrase) Store(context.Context, []byte, string) error { return ErrStoreUnsupported }

// PrepareNext derives a new key from a freshly prompted passphrase with a new
// salt and records it in SlotNext. Call Promote once the vault is re-wrapped.
func (p *passphrase) PrepareNext(ctx context.Context) ([]byte, error) {
	h, err := p.readHeader()
	if err != nil {
		return nil, err
	}
	params := newParams()
	key, err := p.derive(ctx, params)
	if err != nil {
		return nil, err
	}
	h.Slots[SlotNext] = params
	if err := p.writeHeader(h); err != nil {
		zero(key)
		return nil, err
	}
	return key, nil
}

// Promote makes SlotNext parameters the current ones.
func (p *passphrase) Promote(context.Context) error {
	h, err := p.readHeader()
	if err != nil {
		return err
	}
	next, ok := h.Slots[SlotNext]
	if !ok {
		return ErrNoKey
	}
	h.Slots[SlotCurrent] = next
	delete(h.Slots, SlotNext)
	return p.writeHeader(h)
}

func (p *passphrase) derive(ctx context.Context, params kdfParams) ([]byte, error) {
	pw, err := p.prompt(ctx)
	if err != nil {
		return nil, err
	}
	defer zero(pw)
	if utf8.RuneCount(pw) < MinPassphraseLen {
		return nil, ErrPassphraseTooShort
	}
	return argon2.IDKey(pw, params.Salt, params.Time, params.Memory, params.Threads, KeyLen), nil
}

func newParams() kdfParams {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		panic("keysource: crypto/rand failed: " + err.Error())
	}
	return kdfParams{Salt: salt, Memory: argonMemoryKiB, Time: argonTime, Threads: argonThreads}
}

func (p *passphrase) readHeader() (*header, error) {
	raw, err := os.ReadFile(filepath.Join(p.dir, headerFile))
	if errors.Is(err, os.ErrNotExist) {
		return &header{Version: 1, KDF: "argon2id", Slots: map[string]kdfParams{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var h header
	if err := json.Unmarshal(raw, &h); err != nil || h.KDF != "argon2id" {
		return nil, errors.New("keysource: invalid passphrase header")
	}
	if h.Slots == nil {
		h.Slots = map[string]kdfParams{}
	}
	for _, s := range h.Slots {
		// Refuse downgraded parameters so a tampered header cannot weaken the KDF.
		if len(s.Salt) < saltLen || s.Memory < argonMemoryKiB || s.Time < argonTime || s.Threads < 1 {
			return nil, errors.New("keysource: passphrase header parameters below minimum")
		}
	}
	return &h, nil
}

func (p *passphrase) writeHeader(h *header) error {
	raw, err := json.Marshal(h)
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(p.dir, headerFile), raw, 0o600)
}
