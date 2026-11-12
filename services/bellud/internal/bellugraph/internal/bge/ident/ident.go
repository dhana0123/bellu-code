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

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
)

var identityAttrs = map[string][]string{
	"host":             {"hostname"},
	"process":          {"host", "pid", "start_time"},
	"listening_port":   {"host", "protocol", "address", "port"},
	"container":        {"id"},
	"image":            {"id"},
	"network":          {"id"},
	"volume":           {"name"},
	"repository":       {"path"},
	"dependency":       {"repo", "name", "range"},
	"workflow":         {"repo", "path"},
	"secret_ref":       {"repo", "path", "name"},
	"iac_resource":     {"path", "address"},
	"k8s_object":       {"source", "kind", "namespace", "name"},
	"secret_finding":   {"path", "line", "rule"},
	"collector_status": {"collector"},
	"endpoint":         {"protocol", "address", "port"},
}

// Kinds lists the registered kinds, sorted.
func Kinds() []string {
	out := make([]string, 0, len(identityAttrs))
	for k := range identityAttrs {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// IdentityAttributes returns the registered identity attributes of kind in
// registered order.
func IdentityAttributes(kind string) ([]string, bool) {
	a, ok := identityAttrs[kind]
	return append([]string(nil), a...), ok
}

// Hash computes the Entity_ID of kind. Attributes that are not registered
// identity attributes are ignored. It fails with errs.Validation for an
// unknown kind or a missing/empty identity attribute.
func Hash(kind string, attrs map[string]string) (string, error) {
	keys, ok := identityAttrs[kind]
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

var relDirections = map[string]Direction{
	"runs_on":     Reverse,
	"on":          Reverse,
	"owned_by":    Reverse,
	"uses":        Reverse,
	"attached_to": Reverse,
	"mounts":      Reverse,
	"depends_on":  Reverse,
	"resolves_to": Reverse,
	"found_in":    Forward,
}

// RelationTypes lists the registered relation types, sorted.
func RelationTypes() []string {
	out := make([]string, 0, len(relDirections))
	for k := range relDirections {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// DirectionOf returns the Impact_Direction of a relation type. isDefault is
// true when the type is unregistered and the reverse default applies.
func DirectionOf(relType string) (d Direction, isDefault bool) {
	if d, ok := relDirections[relType]; ok {
		return d, false
	}
	return Reverse, true
}

// Label returns the display label: a non-empty string `name` attribute, else
// the identity values in registered order joined by "/".
func Label(kind string, identity map[string]string, attrs map[string]any) string {
	if s, ok := attrs["name"].(string); ok && s != "" {
		return s
	}
	keys := identityAttrs[kind]
	vals := make([]string, 0, len(keys))
	for _, k := range keys {
		vals = append(vals, identity[k])
	}
	return strings.Join(vals, "/")
}

var secretFragments = []string{"secret", "token", "password", "passwd", "credential", "private", "apikey", "api_key", "hash"}

// IsSecretName reports whether an attribute name looks secret-bearing.
func IsSecretName(name string) bool {
	l := strings.ToLower(name)
	for _, f := range secretFragments {
		if strings.Contains(l, f) {
			return true
		}
	}
	return false
}

// IsStateAttr reports whether changing the attribute makes an update a
// state-changed update.
func IsStateAttr(name string) bool { return name == "state" || name == "status" }
