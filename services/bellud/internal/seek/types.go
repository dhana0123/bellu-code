// Package seek implements the deterministic retrieval half of the seek
// planner: plan validation, CWE scoping, CVE ranking and Top_K allocation.
package seek

import (
	"context"
	"encoding/json"
)

// Plan and request limits. String lengths are counted in Unicode code points.
const (
	MaxWeaknesses = 8
	MaxLanguage   = 64
	MaxReasoning  = 4000
	MaxRootCause  = 1000
	MaxSnippet    = 2000

	DefaultTopK = 4
	MinTopK     = 1
	MaxTopK     = 10

	// MaxScope caps the number of CWEs searched for one unit.
	MaxScope = 50
)

// Ranking weights. They sum to 1.0.
const (
	WIdent   = 0.30
	WOverlap = 0.25
	WKEV     = 0.15
	WEPSS    = 0.10
	WCVSS    = 0.10
	WFix     = 0.10
)

// DefaultMinRelevance is the score below which a candidate is dropped.
const DefaultMinRelevance = 0.20

// Unit is one predicted weakness in a Plan.
type Unit struct {
	CWEID     string `json:"cwe_id"`
	RootCause string `json:"root_cause"`
	Snippet   string `json:"code_snippet"`
}

// Plan is the validated planner output.
type Plan struct {
	Language   string `json:"language"`
	Reasoning  string `json:"reasoning"`
	Weaknesses []Unit `json:"weaknesses"` // marshals as [] when nil
}

// MarshalJSON encodes a nil Weaknesses slice as [].
func (p Plan) MarshalJSON() ([]byte, error) {
	type plain Plan
	if p.Weaknesses == nil {
		p.Weaknesses = []Unit{}
	}
	return json.Marshal(plain(p))
}

// Issue names a field path such as "weaknesses[2].root_cause" or "top_k".
type Issue struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// Dropped is a unit rejected from the submitted plan.
type Dropped struct {
	Index  int    `json:"index"` // position in the submitted weaknesses list
	Reason string `json:"reason"`
}

// Edge is a CHILD_OF relation, child to parent.
type Edge struct{ Child, Parent string }

// WeaknessInfo is the BSKG weakness data the seek tool uses.
type WeaknessInfo struct {
	CWEID string
	Name  string
}

// VulnRef is a CVE reference attached to a weakness.
type VulnRef struct {
	CVEID string
	CVSS  *float64 // v3 base score, nil when absent
	CWEID string   // scope CWE it was listed under
}

// VulnDetail is the BSKG vulnerability data used for scoring.
type VulnDetail struct {
	CVEID       string
	Description string
	CVSS        *float64 // v3 base score 0..10, nil when absent
	KEV         bool
	EPSS        *float64 // 0..1, nil when absent
	FixCommit   string
	Repository  string
}

// Candidate is a ranked CVE returned to the agent.
type Candidate struct {
	CVEID       string   `json:"cve_id"`
	CWEID       string   `json:"cwe_id"`   // scope CWE it is attached to
	CWEName     string   `json:"cwe_name"` // from the weakness lookup
	Score       float64  `json:"score"`
	Description string   `json:"description"` // cut to 800 code points
	KEV         bool     `json:"kev"`
	EPSS        *float64 `json:"epss,omitempty"`
	CVSS        *float64 `json:"cvss,omitempty"`
	FixCommit   string   `json:"fix_commit,omitempty"`
	Repository  string   `json:"repository,omitempty"` // only together with a fix commit
}

// ErrInfo describes a failure without upstream URLs, keys or bodies.
type ErrInfo struct {
	Category string `json:"category"` // unconfigured | unreachable | timeout | authentication
	Message  string `json:"message"`
}

// UnitResult is the outcome for one accepted unit.
type UnitResult struct {
	CWEID      string      `json:"cwe_id"`
	Status     string      `json:"status"` // ok | no_candidates | unknown_cwe | unavailable
	Scope      []string    `json:"scope"`
	Expanded   bool        `json:"expanded"`
	Error      *ErrInfo    `json:"error,omitempty"`
	Candidates []Candidate `json:"candidates"`
}

// MarshalJSON encodes nil Scope and Candidates as [].
func (u UnitResult) MarshalJSON() ([]byte, error) {
	type plain UnitResult
	if u.Scope == nil {
		u.Scope = []string{}
	}
	if u.Candidates == nil {
		u.Candidates = []Candidate{}
	}
	return json.Marshal(plain(u))
}

// Result is the seek_retrieve tool output.
type Result struct {
	Status   string       `json:"status"` // ok | cve_unavailable | invalid_plan
	Error    *ErrInfo     `json:"error,omitempty"`
	Issues   []Issue      `json:"issues,omitempty"`
	TopK     int          `json:"top_k"`
	Rejected []Dropped    `json:"rejected,omitempty"`
	Units    []UnitResult `json:"units"`
}

// MarshalJSON encodes a nil Units slice as [].
func (r Result) MarshalJSON() ([]byte, error) {
	type plain Result
	if r.Units == nil {
		r.Units = []UnitResult{}
	}
	return json.Marshal(plain(r))
}

// Source is the BSKG read surface. bskg.Client implements it; tests fake it.
type Source interface {
	// Weakness returns ErrNotFound-style errors when the CWE is absent.
	Weakness(ctx context.Context, cwe string) (WeaknessInfo, error)
	// Children returns CHILD_OF edges (child to parent) within depth of cwe.
	Children(ctx context.Context, cwe string, depth int) ([]Edge, error)
	// WeaknessVulns lists CVEs of a weakness; limit <= MaxScope.
	WeaknessVulns(ctx context.Context, cwe string, limit int) ([]VulnRef, error)
	Vulnerability(ctx context.Context, id string) (VulnDetail, error)
}
