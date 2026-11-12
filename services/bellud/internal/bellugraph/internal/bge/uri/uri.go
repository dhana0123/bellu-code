// Package uri formats and parses bellugraph:// URIs that name entities,
// relations and events.
//
//	bellugraph://<kind>/<hex>
//	bellugraph://relation/<type>/<from-kind>/<from-hex>/<to-kind>/<to-hex>
//	bellugraph://event/<ulid>
package uri

import (
	"fmt"
	"strings"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
)

const (
	scheme    = "bellugraph://"
	hexLen    = 32
	ulidLen   = 26
	kindRel   = "relation"
	kindEvent = "event"
)

// Ref is a parsed URI: Entity, Relation or Event. All implementations are
// comparable values.
type Ref interface {
	isRef()
}

// Entity names an entity by kind and 32 lowercase hex digits.
type Entity struct {
	Kind string
	Hex  string
}

// Relation names a relation by type and its two endpoints.
type Relation struct {
	Type     string
	FromKind string
	FromHex  string
	ToKind   string
	ToHex    string
}

// Event names an event by its ULID.
type Event struct {
	ULID string
}

func (Entity) isRef()   {}
func (Relation) isRef() {}
func (Event) isRef()    {}

// Format renders r as a URI. It returns an error wrapping errs.Validation
// when r holds a malformed component or is nil.
func Format(r Ref) (string, error) {
	switch v := r.(type) {
	case Entity:
		if err := checkEntity(v.Kind, v.Hex); err != nil {
			return "", err
		}
		return scheme + v.Kind + "/" + v.Hex, nil
	case Relation:
		if !validName(v.Type) {
			return "", invalid("relation type %q", v.Type)
		}
		if err := checkEntity(v.FromKind, v.FromHex); err != nil {
			return "", err
		}
		if err := checkEntity(v.ToKind, v.ToHex); err != nil {
			return "", err
		}
		return scheme + kindRel + "/" + v.Type + "/" + v.FromKind + "/" + v.FromHex + "/" + v.ToKind + "/" + v.ToHex, nil
	case Event:
		if !validULID(v.ULID) {
			return "", invalid("event id %q", v.ULID)
		}
		return scheme + kindEvent + "/" + v.ULID, nil
	}
	return "", invalid("unsupported reference %T", r)
}

// Parse parses a bellugraph:// URI. Any other scheme or malformed input
// yields an error wrapping errs.Validation.
func Parse(s string) (Ref, error) {
	rest, ok := strings.CutPrefix(s, scheme)
	if !ok {
		return nil, invalid("uri must use the bellugraph scheme")
	}
	parts := strings.Split(rest, "/")
	switch parts[0] {
	case kindRel:
		if len(parts) != 6 {
			return nil, invalid("relation uri needs type, from-kind, from-hex, to-kind, to-hex")
		}
		r := Relation{Type: parts[1], FromKind: parts[2], FromHex: parts[3], ToKind: parts[4], ToHex: parts[5]}
		if !validName(r.Type) {
			return nil, invalid("relation type %q", r.Type)
		}
		if err := checkEntity(r.FromKind, r.FromHex); err != nil {
			return nil, err
		}
		if err := checkEntity(r.ToKind, r.ToHex); err != nil {
			return nil, err
		}
		return r, nil
	case kindEvent:
		if len(parts) != 2 || !validULID(parts[1]) {
			return nil, invalid("event uri needs a 26 character ulid")
		}
		return Event{ULID: parts[1]}, nil
	}
	if len(parts) != 2 {
		return nil, invalid("entity uri needs kind and hex")
	}
	if err := checkEntity(parts[0], parts[1]); err != nil {
		return nil, err
	}
	return Entity{Kind: parts[0], Hex: parts[1]}, nil
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{errs.Validation}, args...)...)
}

func checkEntity(kind, hex string) error {
	if !validName(kind) || kind == kindRel || kind == kindEvent {
		return invalid("entity kind %q", kind)
	}
	if len(hex) != hexLen {
		return invalid("entity hex must be %d characters", hexLen)
	}
	for i := 0; i < len(hex); i++ {
		c := hex[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return invalid("entity hex must be lowercase hex")
		}
	}
	return nil
}

// validName accepts [a-z][a-z0-9_]*.
func validName(s string) bool {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// validULID accepts 26 Crockford base32 characters whose first digit is at
// most '7' (128-bit range).
func validULID(s string) bool {
	if len(s) != ulidLen || s[0] > '7' {
		return false
	}
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(alphabet, s[i]) < 0 {
			return false
		}
	}
	return true
}
