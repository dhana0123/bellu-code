// Package findings holds the Finding model, its deterministic ID and the
// common severity scale shared by scanners, rules and the overview.
package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
)

// Type is the kind of problem a Finding reports.
type Type string

const (
	TypeVulnerability    Type = "vulnerability"
	TypeMisconfiguration Type = "misconfiguration"
	TypeSecret           Type = "secret"
	TypeLicense          Type = "license"
	TypeMalware          Type = "malware"
	TypeRuntimeThreat    Type = "runtime_threat"
	TypeAIRisk           Type = "ai_risk"
	TypeDataExposure     Type = "data_exposure"
	TypeIdentityRisk     Type = "identity_risk"
)

// Status is the lifecycle state of a Finding.
type Status string

const (
	StatusOpen         Status = "open"
	StatusInProgress   Status = "in_progress"
	StatusResolved     Status = "resolved"
	StatusIgnored      Status = "ignored"
	StatusAcceptedRisk Status = "accepted_risk"
)

// Severity uses the same strings as risk.Severity.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

// MaxEvidence is the largest number of evidence references per Finding.
const MaxEvidence = 50

// EvidenceRef points at the proof for a Finding. Excerpt must already be
// redacted; the model never stores a secret value.
type EvidenceRef struct {
	Kind    string `json:"kind"`              // e.g. file, entity, edge, scan_output
	Ref     string `json:"ref"`               // path, Entity_ID or other locator
	Line    int    `json:"line,omitempty"`    // 1-based, 0 when not applicable
	Excerpt string `json:"excerpt,omitempty"` // redacted text
}

// Finding is one problem on one asset.
type Finding struct {
	ID, WorkspaceID, RuleID, Title, Description string
	Category                                    schema.OverviewCategory
	Type                                        Type
	Severity                                    Severity
	Status                                      Status
	AssetID                                     string        // Entity_ID
	Evidence                                    []EvidenceRef // 0..MaxEvidence
	FirstSeen, LastSeen                         time.Time
	ResolvedAt                                  *time.Time
	Source, SourceRevision                      string
	RulePackVersion                             string
	Occurrences                                 int // runtime_threat dedupe counter
	RiskScore                                   *float64
	// UnmappedSeverity records that the scanner severity was outside the
	// mapping table and Severity fell back to info (Requirement 3.14).
	UnmappedSeverity bool
	Details          json.RawMessage // type-specific, already redacted
	// IgnoreReason, when set on a finding that does not exist yet, creates it
	// directly as ignored with this reason (for example "inline"). An existing
	// finding keeps its status.
	IgnoreReason string
}

// ID is hex(sha256(ruleID 0x00 assetID 0x00 discriminator))[:32].
func ID(ruleID, assetID, discriminator string) string {
	h := sha256.New()
	h.Write([]byte(ruleID))
	h.Write([]byte{0})
	h.Write([]byte(assetID))
	h.Write([]byte{0})
	h.Write([]byte(discriminator))
	return hex.EncodeToString(h.Sum(nil))[:32]
}
