// Package effective computes AWS effective permissions from identity policies,
// a permission boundary and service control policies. It is pure: no I/O.
// A condition that cannot be evaluated yields Unknown, which neither grants
// nor denies.
package effective

import (
	"path"
	"sort"
	"strings"
)

// Decision is the tri-state outcome of an evaluation.
type Decision string

const (
	Allow   Decision = "allow"
	Deny    Decision = "deny"
	Unknown Decision = "unknown"
)

// CondState is the evaluation result of a statement's condition block.
// The zero value means the statement has no condition or it is satisfied.
type CondState int

const (
	CondMet CondState = iota
	CondNotMet
	CondUnknown
)

// Statement is one policy statement.
type Statement struct {
	Deny         bool
	Actions      []string
	NotActions   []string
	Resources    []string
	NotResources []string
	Condition    CondState
	// ConditionKeys names the condition keys, reported when Condition is CondUnknown.
	ConditionKeys []string
}

// Policy is a list of statements.
type Policy []Statement

// Inputs are the collected policy layers. Nil layers were not collected and are
// skipped. Every non-nil layer must allow the request (SCPs: one entry per level,
// account then parent OUs and root).
type Inputs struct {
	Identity []Policy
	Boundary *Policy
	SCPs     []Policy
}

// Result is the effective permission for one action on one resource.
type Result struct {
	Decision Decision
	// UnknownConditions lists condition keys that could not be evaluated and
	// influenced the result.
	UnknownConditions []string
}

func match(patterns []string, v string) bool {
	for _, p := range patterns {
		if p == "*" {
			return true
		}
		if ok, _ := path.Match(strings.ToLower(escape(p)), strings.ToLower(escape(v))); ok {
			return true
		}
	}
	return false
}

// escape makes '/' and ':' ordinary for path.Match by treating '*' as spanning them.
func escape(s string) string { return strings.NewReplacer("/", "\x01", ":", "\x02").Replace(s) }

func (s Statement) applies(action, resource string) bool {
	if len(s.Actions) > 0 && !match(s.Actions, action) {
		return false
	}
	if len(s.NotActions) > 0 && match(s.NotActions, action) {
		return false
	}
	if len(s.Resources) > 0 && !match(s.Resources, resource) {
		return false
	}
	if len(s.NotResources) > 0 && match(s.NotResources, resource) {
		return false
	}
	return true
}

// evalLayer evaluates the union of policies in one layer.
func evalLayer(layer []Policy, action, resource string, keys map[string]struct{}) Decision {
	var allowMet, allowUnk, denyMet, denyUnk bool
	var unkKeys []string
	for _, p := range layer {
		for _, s := range p {
			if s.Condition == CondNotMet || !s.applies(action, resource) {
				continue
			}
			switch {
			case s.Deny && s.Condition == CondMet:
				denyMet = true
			case s.Deny:
				denyUnk = true
				unkKeys = append(unkKeys, s.ConditionKeys...)
			case s.Condition == CondMet:
				allowMet = true
			default:
				allowUnk = true
				unkKeys = append(unkKeys, s.ConditionKeys...)
			}
		}
	}
	var d Decision
	switch {
	case denyMet:
		return Deny
	case allowMet && !denyUnk:
		return Allow
	case allowMet || allowUnk:
		d = Unknown
	default:
		return Deny // implicit deny
	}
	if d == Unknown {
		for _, k := range unkKeys {
			keys[k] = struct{}{}
		}
	}
	return d
}

// Evaluate computes the effective decision for action on resource.
func Evaluate(in Inputs, action, resource string) Result {
	keys := map[string]struct{}{}
	layers := [][]Policy{in.Identity}
	if in.Boundary != nil {
		layers = append(layers, []Policy{*in.Boundary})
	}
	for _, scp := range in.SCPs {
		layers = append(layers, []Policy{scp})
	}
	out := Allow
	for i, l := range layers {
		d := evalLayer(l, action, resource, keys)
		if d == Deny {
			return Result{Decision: Deny}
		}
		if d == Unknown {
			out = Unknown
		}
		_ = i
	}
	r := Result{Decision: out}
	if out == Unknown {
		for k := range keys {
			r.UnknownConditions = append(r.UnknownConditions, k)
		}
		sort.Strings(r.UnknownConditions)
	}
	return r
}
