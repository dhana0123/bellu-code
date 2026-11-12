package gql

import "time"

//go:generate go tool gqlgen generate

// Entity is the GraphQL view of one entity. The schema fields without a
// struct field (localId, neighbors, history, dependents) have resolvers.
type Entity struct {
	ID                  string
	IdentityFingerprint string
	Kind                string
	Label               string
	Attributes          any // map[string]any
	Annotations         any // map[string]string
	ObservedAt          time.Time
	RecordedAt          time.Time
	URI                 string

	// at is the as-of instant the entity was read at; nil means live. Nested
	// neighbors are read at the same instant.
	at *time.Time
}

// Edge is the GraphQL view of one relation. The endpoint entities have
// resolvers that read them at the instant the edge was read at.
type Edge struct {
	Type      string
	Direction Direction
	Hops      int
	Derived   bool

	fromID, toID string
	at           *time.Time
}
