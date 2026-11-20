package cveupdate

import (
	"crypto/ed25519"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bellu/global-cv-graph/pkg/sign"
)

//go:embed pinned_keys
var pinnedFS embed.FS

// Errors returned by verification. Pack errors are wrapped in a PackError.
var (
	ErrNoPinnedKeys   = errors.New("no pinned keys configured")
	ErrIndexSignature = errors.New("index signature verification failed")
	ErrDowngrade      = errors.New("snapshot build time is earlier than the installed snapshot (use --allow-downgrade)")
)

// PackError names the pack that failed a check (Requirement 19.10).
type PackError struct {
	Pack string
	Err  error
}

func (e *PackError) Error() string { return fmt.Sprintf("pack %s rejected: %v", e.Pack, e.Err) }
func (e *PackError) Unwrap() error { return e.Err }

// Index is the part of index.json that the updater reads.
type Index struct {
	Product       string     `json:"product"`
	SchemaVersion string     `json:"schema_version"`
	Latest        Snapshot   `json:"latest"`
	Snapshots     []Snapshot `json:"snapshots"`
	Deltas        []Delta    `json:"deltas"`
}

// Snapshot is one full snapshot entry.
type Snapshot struct {
	ID        string    `json:"id"`
	URL       string    `json:"url"`
	SHA256    string    `json:"sha256"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"created_at"`
	SigURL    string    `json:"sig_url,omitempty"`
}

// Delta is one delta entry.
type Delta struct {
	Base   string `json:"base"`
	Target string `json:"target"`
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	SigURL string `json:"sig_url,omitempty"`
}

// Verifier checks the index and packs against a set of pinned keys.
type Verifier struct{ keys []ed25519.PublicKey }

// NewVerifier returns a Verifier for keys. It fails when keys is empty so that
// an unconfigured build can never accept an update.
func NewVerifier(keys []ed25519.PublicKey) (*Verifier, error) {
	if len(keys) == 0 {
		return nil, ErrNoPinnedKeys
	}
	return &Verifier{keys: keys}, nil
}

// NewPinnedVerifier returns a Verifier for the keys embedded with the release.
func NewPinnedVerifier() (*Verifier, error) {
	keys, err := PinnedKeys()
	if err != nil {
		return nil, err
	}
	return NewVerifier(keys)
}

// PinnedKeys parses the embedded pinned_keys/*.pub files.
func PinnedKeys() ([]ed25519.PublicKey, error) {
	entries, err := pinnedFS.ReadDir("pinned_keys")
	if err != nil {
		return nil, err
	}
	var keys []ed25519.PublicKey
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pub") {
			continue
		}
		b, err := pinnedFS.ReadFile("pinned_keys/" + e.Name())
		if err != nil {
			return nil, err
		}
		k, err := sign.ParsePublicKey(string(b))
		if err != nil {
			return nil, fmt.Errorf("pinned key %s: %w", e.Name(), err)
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// VerifyIndex checks the signature of the raw index.json bytes and, only if it
// holds, parses them. A bad signature rejects the index.
func (v *Verifier) VerifyIndex(raw, sigFile []byte) (*Index, error) {
	if _, err := sign.Verify(v.keys, raw, sigFile); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIndexSignature, err)
	}
	var idx Index
	if err := json.Unmarshal(raw, &idx); err != nil {
		return nil, fmt.Errorf("index.json: %w", err)
	}
	return &idx, nil
}

// VerifyPack checks data against the size and SHA256 recorded in the signed
// index and against its detached signature. name is used in the error.
func (v *Verifier) VerifyPack(name string, data []byte, wantSHA256 string, wantSize int64, sigFile []byte) error {
	if wantSize > 0 && int64(len(data)) != wantSize {
		return &PackError{name, fmt.Errorf("size %d differs from index (%d)", len(data), wantSize)}
	}
	if err := sign.VerifyPack(v.keys, data, wantSHA256, sigFile); err != nil {
		return &PackError{name, err}
	}
	return nil
}

// VerifyPackFile reads the downloaded pack at path and verifies it. On any
// failure it deletes the file and returns a PackError naming the pack.
func (v *Verifier) VerifyPackFile(name, path, wantSHA256 string, wantSize int64, sigFile []byte) error {
	data, err := os.ReadFile(path)
	if err == nil {
		err = v.VerifyPack(name, data, wantSHA256, wantSize, sigFile)
	} else {
		err = &PackError{name, err}
	}
	if err != nil {
		os.Remove(path)
		return err
	}
	return nil
}

// SHA256Hex returns the lower-case hex SHA256 of data.
func SHA256Hex(data []byte) string {
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}

// CheckDowngrade rejects a candidate whose build time is earlier than the
// installed one unless allow is true. A zero installed time means nothing is
// installed.
func CheckDowngrade(installed, candidate time.Time, allow bool) error {
	if allow || installed.IsZero() || !candidate.Before(installed) {
		return nil
	}
	return fmt.Errorf("%w: candidate %s, installed %s", ErrDowngrade,
		candidate.UTC().Format(time.RFC3339), installed.UTC().Format(time.RFC3339))
}
