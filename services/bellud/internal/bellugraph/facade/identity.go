package facade

import (
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
)

// Kinds lists the registered entity kinds, sorted.
func Kinds() []string { return ident.Kinds() }

// IdentityAttributes returns the registered identity attributes of kind in
// registered order.
func IdentityAttributes(kind string) ([]string, bool) { return ident.IdentityAttributes(kind) }

// Hash computes the Entity_ID of kind over its registered identity attributes
// ("kind:<32 hex>"). It is independent of map order, process, OS and CPU
// architecture. Attributes in attrs that are not registered identity
// attributes are ignored.
//
// It returns an error wrapping ErrValidation for an unknown kind or for a
// missing (absent or empty) identity attribute, naming the attribute.
func Hash(kind string, attrs map[string]string) (EntityID, error) {
	id, err := ident.Hash(kind, attrs)
	if err != nil {
		return "", err
	}
	return EntityID(id), nil
}
