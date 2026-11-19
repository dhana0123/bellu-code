// Package ident holds the kind registry, identity hash, relation-type
// registry with Impact_Direction, labels and the secret-name rule.
package ident

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schemaall"
)

// The registry is the merged result of every source declaration. It is
// resolved on first use. After a failed merge every lookup behaves as if
// nothing is registered and Check returns the failure.
var (
	regMu  sync.Mutex
	regSet bool
	reg    *schema.Registry
	regErr error
)

func resolve() (*schema.Registry, error) {
	regMu.Lock()
	defer regMu.Unlock()
	if !regSet {
		reg, regErr = schemaall.Default()
		regSet = true
	}
	return reg, regErr
}

// lookup returns the registry, or nil when the merge failed.
func lookup() *schema.Registry {
	r, err := resolve()
	if err != nil {
		return nil
	}
	return r
}

// Registry returns the merged registry, or the merge error.
func Registry() (*schema.Registry, error) {
	r, err := resolve()
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Check returns nil when the merge of every source declaration succeeded.
// The error lists every failure.
func Check() error {
	_, err := resolve()
	return err
}

// Use installs r as the registry. It is for tests. The first call wins: a
// later call with a different registry, or any call after a lookup resolved
// the default, returns schema.ErrImmutable.
func Use(r *schema.Registry) error {
	if r == nil {
		return fmt.Errorf("%w: nil registry", errs.Validation)
	}
	regMu.Lock()
	defer regMu.Unlock()
	if regSet {
		if reg == r && regErr == nil {
			return nil
		}
		return schema.ErrImmutable
	}
	reg, regErr, regSet = r, nil, true
	return nil
}

// Kinds lists the registered kinds, sorted.
func Kinds() []string {
	r := lookup()
	if r == nil {
		return []string{}
	}
	ks := r.Kinds()
	out := make([]string, len(ks))
	for i, k := range ks {
		out[i] = k.Name
	}
	return out
}

// IdentityAttributes returns the registered identity attributes of kind in
// registered order.
func IdentityAttributes(kind string) ([]string, bool) {
	r := lookup()
	if r == nil {
		return nil, false
	}
	k, ok := r.Kind(kind)
	if !ok {
		return nil, false
	}
	return append([]string(nil), k.Identity...), true
}

// Hash computes the Entity_ID of kind. Attributes that are not registered
// identity attributes are ignored. It fails with errs.Validation for an
// unknown kind or a missing/empty identity attribute.
func Hash(kind string, attrs map[string]string) (string, error) {
	keys, ok := IdentityAttributes(kind)
	if !ok {
		return "", fmt.Errorf("%w: unknown entity kind %q", errs.Validation, kind)
	}
	sorted := append([]string(nil), keys...)
	sort.Strings(sorted)
	buf := []byte("bellugraph.id.v1")
	buf = append(buf, 0)
	buf = appendStr(buf, kind)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(sorted)))
	for _, k := range sorted {
		v := attrs[k]
		if v == "" {
			return "", fmt.Errorf("%w: entity kind %q is missing identity attribute %q", errs.Validation, kind, k)
		}
		buf = appendStr(buf, k)
		buf = append(buf, 1)
		buf = appendStr(buf, v)
	}
	sum := sha256.Sum256(buf)
	return kind + ":" + hex.EncodeToString(sum[:16]), nil
}

func appendStr(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

// Direction is an Impact_Direction.
type Direction int

const (
	// Reverse: failure of `to` impacts `from`.
	Reverse Direction = iota
	// Forward: failure of `from` impacts `to`.
	Forward
)

func (d Direction) String() string {
	if d == Forward {
		return "forward"
	}
	return "reverse"
}

// RelationTypes lists the registered relation types, sorted.
func RelationTypes() []string {
	r := lookup()
	if r == nil {
		return []string{}
	}
	rs := r.Relations()
	out := make([]string, len(rs))
	for i, d := range rs {
		out[i] = d.Name
	}
	return out
}

// DirectionOf returns the Impact_Direction of a relation type. isDefault is
// true when the type is unregistered and the reverse default applies.
func DirectionOf(relType string) (d Direction, isDefault bool) {
	if r := lookup(); r != nil {
		if rel, ok := r.Relation(relType); ok {
			if rel.Direction == schema.Forward {
				return Forward, false
			}
			return Reverse, false
		}
	}
	return Reverse, true
}

// DefaultConfidence returns the default confidence of a relation type. An
// unregistered type reports "extracted" and registered=false.
func DefaultConfidence(relType string) (conf string, registered bool) {
	if r := lookup(); r != nil {
		if rel, ok := r.Relation(relType); ok {
			return string(rel.Confidence), true
		}
	}
	return string(schema.Extracted), false
}

// Label returns the display label: a non-empty string `name` attribute, else
// the identity values in registered order joined by "/".
func Label(kind string, identity map[string]string, attrs map[string]any) string {
	if s, ok := attrs["name"].(string); ok && s != "" {
		return s
	}
	keys, _ := IdentityAttributes(kind)
	vals := make([]string, 0, len(keys))
	for _, k := range keys {
		vals = append(vals, identity[k])
	}
	return strings.Join(vals, "/")
}

// IsSecretName reports whether an attribute name looks secret-bearing. The
// rule lives in schema.IsSecretName.
func IsSecretName(name string) bool { return schema.IsSecretName(name) }

// IsStateAttr reports whether changing the attribute makes an update a
// state-changed update.
func IsStateAttr(name string) bool { return name == "state" || name == "status" }
