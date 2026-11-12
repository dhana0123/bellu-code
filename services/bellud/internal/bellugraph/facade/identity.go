package facade

import (
	"fmt"
	"sort"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/model"
)

// identityAttrs registers, per entity kind, the attributes that identify an
// entity. The Entity_ID covers exactly these; every other attribute is
// descriptive and never changes the ID. Values must be non-empty; use a fixed
// placeholder (for example "-") for an absent scope such as a cluster-scoped
// Kubernetes namespace.
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
}

// Kinds lists the registered entity kinds, sorted.
func Kinds() []string {
	out := make([]string, 0, len(identityAttrs))
	for k := range identityAttrs {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// IdentityAttributes returns the registered identity attributes of kind.
func IdentityAttributes(kind string) ([]string, bool) {
	a, ok := identityAttrs[kind]
	return append([]string(nil), a...), ok
}

// Hash computes the Entity_ID of kind over its registered identity attributes.
// It is the engine's own identity fingerprint (SHA-256 truncated to 128 bits
// over the kind and the key-sorted, type-tagged identity attributes), so it is
// independent of map order, process, OS and CPU architecture. Attributes in
// attrs that are not registered identity attributes are ignored.
//
// It returns an error wrapping ErrValidation for an unknown kind or for a
// missing (absent or empty) identity attribute, naming the attribute.
func Hash(kind string, attrs map[string]string) (EntityID, error) {
	kvs, err := identityKVs(kind, attrs)
	if err != nil {
		return "", err
	}
	return EntityID(model.Entity{Type: kind, Identity: kvs}.IdentityHash()), nil
}

func identityKVs(kind string, attrs map[string]string) ([]model.KeyValue, error) {
	keys, ok := identityAttrs[kind]
	if !ok {
		return nil, fmt.Errorf("%w: unknown entity kind %q", ErrValidation, kind)
	}
	kvs := make([]model.KeyValue, 0, len(keys))
	for _, k := range keys {
		v, ok := attrs[k]
		if !ok || v == "" {
			return nil, fmt.Errorf("%w: entity kind %q is missing identity attribute %q", ErrValidation, kind, k)
		}
		kvs = append(kvs, model.KeyValue{Key: k, Value: model.StringValue(v)})
	}
	return kvs, nil
}
