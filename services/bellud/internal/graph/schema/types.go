// Package schema holds the declarations that sources make about the entity
// kinds and relation types they write to the graph, the check that merges
// them, and the immutable registry the merge produces.
//
// The package imports only the standard library.
package schema

// Direction is the impact direction of a relation type. Forward means failure
// or compromise of the from end impacts the to end. Reverse means failure or
// compromise of the to end impacts the from end. The numeric values equal
// ident.Direction.
type Direction uint8

const (
	Reverse Direction = iota
	Forward
)

// String returns "forward" or "reverse", and "invalid" for any other value.
func (d Direction) String() string {
	switch d {
	case Forward:
		return "forward"
	case Reverse:
		return "reverse"
	}
	return "invalid"
}

// Confidence is the default confidence of a relation type.
type Confidence string

const (
	Extracted Confidence = "extracted"
	Inferred  Confidence = "inferred"
)

// Status says whether a collection category has a collector.
type Status string

const (
	Implemented    Status = "implemented"
	RegisteredOnly Status = "registered-only"
)

// Source names a producer of graph facts that owns a namespace of names.
type Source string

const (
	SourceCore       Source = "core"
	SourceGitHub     Source = "github"
	SourceAWS        Source = "aws"
	SourceCorrelator Source = "correlator"
)

// KindDeclaration declares an entity kind.
type KindDeclaration struct {
	Name string
	// Identity lists the identity attributes in registered order (1..16,
	// unique, non-empty).
	Identity    []string
	Description string // 1..500 characters after trimming, not blank
	// Discriminator optionally names the attribute that selects Types.
	Discriminator string
	Types         []TypeDeclaration
}

// TypeDeclaration declares one value of a kind's discriminator attribute.
type TypeDeclaration struct {
	Name        string // for example "ec2:subnet"
	Category    string // CategoryDeclaration.ID
	Description string
}

// RelationDeclaration declares a relation type.
type RelationDeclaration struct {
	Name        string
	Direction   Direction
	Confidence  Confidence
	Description string
	// From and To name kinds or type names. Empty means any.
	From, To []string
	// Derived marks a relation that no connector collector asserts.
	Derived bool
	// Category optionally names a CategoryDeclaration.ID.
	Category string
}

// CategoryDeclaration declares a collection category.
type CategoryDeclaration struct {
	ID      string
	Name    string
	Status  Status
	ReadOps []string // read operations a future collector needs
}

// SourceDeclaration is everything one source registers.
type SourceDeclaration struct {
	Source Source
	// Prefix is "" for core and for sources without one, "aws_" for aws.
	Prefix     string
	Kinds      []KindDeclaration
	Relations  []RelationDeclaration
	Categories []CategoryDeclaration
}

// Requirement lists names that a source's declaration must contain.
type Requirement struct {
	Kinds      []string
	Types      []string
	Relations  []string
	Categories []string
}
