// Package cce is the Graph Context and Correlation Engine: identity, relation
// state, and evidence for cross-graph relations.
package cce

import "time"

// GraphID names a graph: "code", "cve", or "unified".
type GraphID string

// WorkspaceID is the single local workspace identity kept in every row.
type WorkspaceID string

// StableID is the shared identity: "bid:<class>:<base32 digest>" or "bid:vuln:<canonical id>".
type StableID string

// EvidenceID is "ev:" followed by the content digest.
type EvidenceID string

// RelationID is the 64-character lowercase hex SHA256 computed by NewRelationID.
type RelationID string

// EdgeState is the lifecycle state of a relation.
type EdgeState string

const (
	Hypothesis EdgeState = "hypothesis"
	Candidate  EdgeState = "candidate"
	Confirmed  EdgeState = "confirmed"
	Retracted  EdgeState = "retracted"
)

// Method says how a relation was derived.
type Method string

const (
	MethodExactID           Method = "exact_id"
	MethodExactPURL         Method = "exact_purl"
	MethodGraphifyExtracted Method = "graphify_extracted"
	MethodGraphifyInferred  Method = "graphify_inferred"
	MethodSemantic          Method = "semantic"
	MethodLLM               Method = "llm"
)

// Trust is the trust level of a piece of evidence.
type Trust string

const (
	TrustedSource Trust = "trusted_source"
	Derived       Trust = "derived"
	UntrustedText Trust = "untrusted_text"
)

// EvidenceKind classifies evidence content.
type EvidenceKind string

const (
	SourceSpan    EvidenceKind = "source_span"
	ManifestEntry EvidenceKind = "manifest_entry"
	AdvisoryRec   EvidenceKind = "advisory_record"
	APIResponse   EvidenceKind = "api_response"
	ScanResult    EvidenceKind = "scan_result"
	LLMTrace      EvidenceKind = "llm_trace"
)

// Temporal carries the time fields of a relation or evidence row.
type Temporal struct {
	EventTime      *time.Time
	RecordedAt     time.Time
	ValidFrom      time.Time
	ValidUntil     *time.Time // nil means open
	ObservedAt     time.Time
	SourceRevision string
}

// Relation is a typed edge between two stable entities.
type Relation struct {
	ID         RelationID
	Workspace  WorkspaceID
	Type       string
	From, To   StableID
	State      EdgeState
	Confidence float64
	Method     Method
	Temporal   Temporal
	Evidence   []EvidenceID
}

// Evidence is stored proof for a relation.
type Evidence struct {
	ID            EvidenceID
	Workspace     WorkspaceID
	Kind          EvidenceKind
	Content       []byte
	ContentSHA256 [32]byte
	Locator       string
	Temporal      Temporal
	Trust         Trust
}

// Proposal is a fuzzy candidate. It is never auto-promoted.
type Proposal struct {
	ID    StableID
	Score float64
}
