package posture

import (
	"context"
	"fmt"
	"sort"
)

// ControlStatus is the compliance status of one benchmark control (10.9).
type ControlStatus string

const (
	StatusPass          ControlStatus = "pass"
	StatusFail          ControlStatus = "fail"
	StatusNotApplicable ControlStatus = "not_applicable"
	StatusError         ControlStatus = "error"
)

// ControlResult is one row of a compliance report.
type ControlResult struct {
	Benchmark, Control string
	Status             ControlStatus
	FailingEntities    int
}

// ControlCounts are the distinct-entity tallies behind one control.
// EnabledRules is the number of mapped rules that are not disabled.
type ControlCounts struct {
	Failing, Passed, Errored, EnabledRules int
}

// ComputeStatus applies the status rules in order: fail, pass, not_applicable,
// error. No evaluated entity and no error means no entity of the declared kinds
// exists.
func ComputeStatus(c ControlCounts) ControlStatus {
	switch {
	case c.Failing > 0:
		return StatusFail
	case c.Passed > 0:
		return StatusPass
	case c.EnabledRules == 0 || c.Errored == 0:
		return StatusNotApplicable
	default:
		return StatusError
	}
}

// Benchmarks lists the benchmark names that the loaded packs map rules to.
func (e *Engine) Benchmarks() []string {
	seen := map[string]bool{}
	for _, pr := range e.rules {
		for _, b := range pr.rule.Benchmarks {
			if bm, ok := ParseBenchmark(b); ok {
				seen[bm.Name] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Compliance returns one row per control that a rule of benchmark maps to,
// ordered by control, from the posture_eval rows and the rule overrides.
func (e *Engine) Compliance(ctx context.Context, benchmark string) ([]ControlResult, error) {
	if e.run.db == nil {
		return nil, fmt.Errorf("posture: engine is not configured")
	}
	ov, err := e.loadOverrides(ctx)
	if err != nil {
		return nil, err
	}
	type key struct{ pack, rule string }
	controls := map[string][]key{}
	for _, pr := range e.rules {
		for _, b := range pr.rule.Benchmarks {
			if bm, ok := ParseBenchmark(b); ok && bm.Name == benchmark {
				controls[bm.Control] = append(controls[bm.Control], key{pr.pack, pr.rule.ID})
			}
		}
	}
	if len(controls) == 0 {
		return nil, nil
	}

	rows, err := e.run.db.DB().QueryContext(ctx, `SELECT pack_id, rule_id, entity_id, result FROM posture_eval WHERE workspace_id=?`, e.run.db.WorkspaceID())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type ent struct {
		pack, rule, entity string
	}
	byRule := map[key][]struct{ entity, result string }{}
	for rows.Next() {
		var e ent
		var res string
		if err := rows.Scan(&e.pack, &e.rule, &e.entity, &res); err != nil {
			return nil, err
		}
		k := key{e.pack, e.rule}
		byRule[k] = append(byRule[k], struct{ entity, result string }{e.entity, res})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	names := make([]string, 0, len(controls))
	for c := range controls {
		names = append(names, c)
	}
	sort.Strings(names)
	out := make([]ControlResult, 0, len(names))
	for _, c := range names {
		failing, passed, errored := map[string]bool{}, map[string]bool{}, map[string]bool{}
		var counts ControlCounts
		for _, k := range controls[c] {
			if !ov.enabled(k.pack, k.rule) {
				continue // rows of a disabled rule are stale
			}
			counts.EnabledRules++
			for _, r := range byRule[k] {
				switch Result(r.result) {
				case ResultFail:
					failing[r.entity] = true
				case ResultPass:
					passed[r.entity] = true
				case ResultError:
					errored[r.entity] = true
				}
			}
		}
		counts.Failing, counts.Passed, counts.Errored = len(failing), len(passed), len(errored)
		out = append(out, ControlResult{Benchmark: benchmark, Control: c, Status: ComputeStatus(counts), FailingEntities: counts.Failing})
	}
	return out, nil
}
