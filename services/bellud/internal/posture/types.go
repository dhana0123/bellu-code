// Package posture holds the Policy_Engine types and the Rule_Pack loader.
package posture

import (
	"io/fs"
	"strings"

	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
)

// RuleKind says what a rule detects.
type RuleKind string

const (
	KindPosture          RuleKind = "posture"
	KindToxicCombination RuleKind = "toxic_combination"
	KindRuntime          RuleKind = "runtime"
	KindIdentity         RuleKind = "identity"
)

// Valid reports whether k is a known rule kind.
func (k RuleKind) Valid() bool {
	switch k {
	case KindPosture, KindToxicCombination, KindRuntime, KindIdentity:
		return true
	}
	return false
}

// Rule is one policy rule (Requirement 10.2). Rego names the rule's .rego file
// inside its pack directory.
type Rule struct {
	ID, Title, Description, Remediation string
	Severity                            findings.Severity
	Category                            schema.OverviewCategory
	AppliesTo                           []string // entity kinds, 1..50
	Benchmarks                          []string // 0..20, for example "CIS-AWS-1.4:2.1.1"
	Kind                                RuleKind
	Rego                                string
}

// Pack is a versioned bundle of rules. Source is the pack directory, which
// holds the .rego files.
type Pack struct {
	ID, Version string
	Rules       []Rule
	Source      fs.FS
}

// Benchmark is a parsed benchmark mapping such as "CIS-AWS-1.4:2.1.1".
type Benchmark struct{ Name, Control string }

// ParseBenchmark splits "<benchmark>:<control>".
func ParseBenchmark(s string) (Benchmark, bool) {
	name, control, ok := strings.Cut(s, ":")
	if !ok || strings.TrimSpace(name) == "" || strings.TrimSpace(control) == "" {
		return Benchmark{}, false
	}
	return Benchmark{Name: name, Control: control}, true
}

// Hop is one step of a toxic-combination path.
type Hop struct{ EntityID, Relation string }

// Match is one violation emitted by a rule.
type Match struct {
	PackID, RuleID, EntityID, Discriminator string
	Evidence                                map[string]string
	Path                                    []Hop // toxic-combination rules only
}

// Result is the outcome of evaluating one rule on one entity.
type Result string

const (
	ResultPass  Result = "pass"
	ResultFail  Result = "fail"
	ResultError Result = "error"
)

// Evaluation is one row of the posture evaluation table.
type Evaluation struct {
	PackID, RuleID, EntityID string
	Result                   Result
	Error                    string
}

// Override changes a rule's state. RuleID empty targets the whole pack; a rule
// override beats a pack override (Requirement 10.8).
type Override struct {
	PackID, RuleID string
	Enabled        *bool
	Severity       *findings.Severity
}
