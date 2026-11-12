// Package identity computes Entity_IDs for collectors without importing the
// engine. It re-exports the facade's registry-backed hash.
package identity

import "github.com/bellu/bellucode/services/bellud/internal/bellugraph/facade"

// ID is an Entity_ID.
type ID = facade.EntityID

// Hash returns the Entity_ID of kind over its registered identity attributes.
// It rejects an unknown kind or a missing identity attribute with an error
// wrapping graph.ErrValidation. Non-identity attributes are ignored.
func Hash(kind string, attrs map[string]string) (ID, error) { return facade.Hash(kind, attrs) }

// Kinds lists the registered entity kinds.
func Kinds() []string { return facade.Kinds() }

// Attributes returns the registered identity attributes of kind.
func Attributes(kind string) ([]string, bool) { return facade.IdentityAttributes(kind) }
