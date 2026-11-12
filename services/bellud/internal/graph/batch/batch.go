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
// same Batch or one already in the graph. Relations carry no attributes: a
// non-empty Attributes rejects the whole Batch.
type Relation struct {
	Type       string
	From       string
	To         string
	Attributes map[string]any
}

// Batch is one collector run's observations.
type Batch struct {
	Collector string
	// ObservedAt is the valid time of the observation, preserved exactly as
	// supplied. Zero means "now" (the engine never rewrites a supplied value).
	ObservedAt time.Time
	Entities   []Entity
	Relations  []Relation
}
