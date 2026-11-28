package posture

import (
	"context"
	"errors"
	"sort"

	"github.com/bellu/bellucode/services/bellud/internal/findings"
)

// PackInfo describes a loaded pack and its effective state (Requirement 10.8).
type PackInfo struct {
	ID, Version string
	Enabled     bool
	Rules       int
}

// RuleInfo is a loaded rule with its effective enabled state and severity,
// where a rule override beats a pack override beats the rule default.
type RuleInfo struct {
	PackID   string
	Rule     Rule
	Enabled  bool
	Severity findings.Severity
}

// Packs lists the loaded packs ordered by id with their rule counts.
func (e *Engine) Packs(ctx context.Context) ([]PackInfo, error) {
	ov, err := e.overridesOrDefault(ctx)
	if err != nil {
		return nil, err
	}
	counts := map[string]int{}
	for _, pr := range e.rules {
		counts[pr.pack]++
	}
	out := make([]PackInfo, 0, len(e.versions))
	for id, v := range e.versions {
		on := true
		if b, ok := ov.packEnabled[id]; ok {
			on = b
		}
		out = append(out, PackInfo{ID: id, Version: v, Enabled: on, Rules: counts[id]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// RulesOf lists the rules of a pack with effective state. ok is false for an unknown pack.
func (e *Engine) RulesOf(ctx context.Context, pack string) (rules []RuleInfo, ok bool, err error) {
	if _, known := e.versions[pack]; !known {
		return nil, false, nil
	}
	ov, err := e.overridesOrDefault(ctx)
	if err != nil {
		return nil, true, err
	}
	rules = []RuleInfo{}
	for _, pr := range e.rules {
		if pr.pack == pack {
			rules = append(rules, RuleInfo{PackID: pack, Rule: pr.rule, Enabled: ov.enabled(pack, pr.rule.ID), Severity: ov.severity(pack, pr.rule.ID, pr.rule.Severity)})
		}
	}
	return rules, true, nil
}

func (e *Engine) overridesOrDefault(ctx context.Context) (*overrideSet, error) {
	if e.run.db == nil {
		return nil, errors.New("posture: engine has no database")
	}
	return e.loadOverrides(ctx)
}
