package bundle

import (
	"crypto/ed25519"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

//go:embed pinned_key.txt
var embeddedKey string

// ErrNoPinnedKey means neither BELLU_INTEL_PUBKEY nor the embedded file holds a key.
var ErrNoPinnedKey = errors.New("no pinned key")

// LoadPinnedKey returns the key from BELLU_INTEL_PUBKEY, else from the embedded
// pinned_key.txt. The value is a base64 ed25519 public key.
func LoadPinnedKey() (ed25519.PublicKey, error) {
	raw := strings.TrimSpace(os.Getenv("BELLU_INTEL_PUBKEY"))
	if raw == "" {
		raw = embeddedKeyValue(embeddedKey)
	}
	if raw == "" {
		return nil, ErrNoPinnedKey
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("pinned key is not base64: %w", err)
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("pinned key has %d bytes, want %d", len(key), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(key), nil
}

// embeddedKeyValue returns the first non-blank, non-comment line.
func embeddedKeyValue(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			return line
		}
	}
	return ""
}
