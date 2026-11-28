package cce

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/bellu/bellucode/services/bellud/internal/canonical"
)

// MaxKeyLen is the longest accepted raw identity key, in characters.
const MaxKeyLen = 2048

// KeyType is the kind of identity key.
type KeyType string

const (
	CVEID               KeyType = "cve_id"
	PURL                KeyType = "purl"
	ARN                 KeyType = "arn"
	RepoFullName        KeyType = "repo_full_name"
	ImageDigest         KeyType = "image_digest"
	FilePathAtRevision  KeyType = "file_path_at_revision"
	SymbolQualifiedName KeyType = "symbol_qualified_name"
)

// IdentityKey is a typed raw key to resolve.
type IdentityKey struct {
	Type  KeyType
	Value string
}

// ErrInvalidKey is returned for keys that are empty, too long, of an
// unsupported type, or that fail normalization.
var ErrInvalidKey = errors.New("invalid identity key")

// KeyError names the offending key and the reason.
type KeyError struct {
	Type   KeyType
	Value  string
	Reason string
}

func (e *KeyError) Error() string {
	v := e.Value
	if len([]rune(v)) > 64 {
		v = string([]rune(v)[:64]) + "..."
	}
	return fmt.Sprintf("invalid identity key (type %q, value %q): %s", e.Type, v, e.Reason)
}

func (e *KeyError) Unwrap() error { return ErrInvalidKey }

// Normalize validates k and returns its normalized form. Normalizing the
// result again with the same type yields the same string.
func Normalize(k IdentityKey) (string, error) {
	fail := func(reason string) (string, error) {
		return "", &KeyError{Type: k.Type, Value: k.Value, Reason: reason}
	}
	if k.Value == "" {
		return fail("empty key")
	}
	if len([]rune(k.Value)) > MaxKeyLen {
		return fail(fmt.Sprintf("longer than %d characters", MaxKeyLen))
	}
	var canon string
	switch k.Type {
	case CVEID:
		canon = canonical.KindVuln
	case PURL:
		canon = canonical.KindPurl
	case ARN:
		canon = canonical.KindARN
	case RepoFullName:
		canon = canonical.KindGit
	case ImageDigest:
		canon = canonical.KindImage
	case FilePathAtRevision:
		return normalizePathAtRevision(k, fail)
	case SymbolQualifiedName:
		s := strings.TrimSpace(k.Value)
		if s == "" || hasControl(s) {
			return fail("empty or contains control characters")
		}
		return s, nil
	default:
		return fail("unsupported key type")
	}
	out, ok := canonical.Key(canon, k.Value)
	if !ok {
		return fail("normalization failed")
	}
	return out, nil
}

// normalizePathAtRevision accepts "<repo>@<revision>:<path>", the locator form.
func normalizePathAtRevision(k IdentityKey, fail func(string) (string, error)) (string, error) {
	s := strings.TrimSpace(k.Value)
	if hasControl(s) {
		return fail("contains control characters")
	}
	at := strings.IndexByte(s, '@')
	if at <= 0 {
		return fail("expected <repo>@<revision>:<path>")
	}
	rev, path, ok := strings.Cut(s[at+1:], ":")
	if !ok || rev == "" || path == "" || strings.ContainsAny(rev, " \t") {
		return fail("expected <repo>@<revision>:<path>")
	}
	return s[:at] + "@" + rev + ":" + path, nil
}

func hasControl(s string) bool {
	return strings.IndexFunc(s, unicode.IsControl) >= 0
}
