// Package batch defines the unit of work collectors hand to the graph facade.
package batch

import "time"

// Entity is a node observation. Identity attributes determine the entity ID
// and must never be altered by downstream guards.
type Entity struct {
	Type       string
	Identity   map[string]string
	Attributes map[string]any
}

// Relation is a typed edge. From and To are Entity_IDs (identity.Hash of the
// endpoint kind and identity attributes), and each must name an entity in the
// same Batch or one already in the graph. Attributes may hold only the edge
// attributes "evidence" (string, at most 512 bytes), "confidence" ("extracted"
// or "inferred") and "observed_at" (RFC 3339 string), each optional. Any other
// name or an invalid value rejects the whole Batch. Attributes are not part of
// the relation identity (Type, From, To).
type Relation struct {
	Type       string
	From       string
	To         string
	Attributes map[string]any
}

// Retain is a retention rule. In a full observation, an entity that is not in
// the Batch and matches any rule is neither retired nor dropped from the
// collector's scope, and a relation not in the Batch is kept when its From or
// To entity matches. Retain is planner input only; it creates no event.
type Retain struct {
	// Kind is the required entity kind.
	Kind string
	// Attrs must all equal the entity's string attributes. Empty matches any.
	Attrs map[string]string
}

// Batch is one collector run's observations.
type Batch struct {
	Collector string
	// ObservedAt is the valid time of the observation, preserved exactly as
	// supplied. Zero means "now" (the engine never rewrites a supplied value).
	ObservedAt time.Time
	Entities   []Entity
	Relations  []Relation
	// Retain lists entities (and their relations) a full observation must not
	// retire because the collector could not observe them this run.
	Retain []Retain
}
