package posture

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/facade"
	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
)

// SourcePrefix starts the findings source of a pack: "posture:<pack>".
const SourcePrefix = "posture:"

var defaultBackoff = []time.Duration{5 * time.Second, 15 * time.Second, 45 * time.Second}

// FindingsSink is the findings writer for one evaluation run. findings.JobSink
// satisfies it.
type FindingsSink interface {
	Findings([]findings.Finding) error
	ResolveMissing(ctx context.Context, asset, source string) (int, error)
}

type runConfig struct {
	db      *sqlite.Store
	newSink func(ctx context.Context) FindingsSink
	backoff []time.Duration
	now     func() time.Time
}

// Configure sets the database that holds overrides and posture_eval, and the
// factory that makes one findings writer per run.
func (e *Engine) Configure(db *sqlite.Store, newSink func(ctx context.Context) FindingsSink) {
	e.run.db, e.run.newSink = db, newSink
	if e.run.now == nil {
		e.run.now = time.Now
	}
}

// Scope selects what Evaluate checks. Full evaluates every entity. Otherwise
// the Changed entities and their one-hop neighbours are evaluated. A pack
// version change turns any scope into a full run (10.10).
type Scope struct {
	Full    bool
	Changed []facade.EntityID
}

// Summary describes one finished run.
type Summary struct {
	Full               bool
	Entities, Findings int
	Resolved           int
	Errors             []EvalError
}

// Evaluate runs the rules over scope. A failed run is retried after 5, 15 and
// 45 seconds; while it fails no finding is resolved, so open Issues stay.
func (e *Engine) Evaluate(ctx context.Context, scope Scope) (Summary, error) {
	if e.run.db == nil || e.run.newSink == nil {
		return Summary{}, fmt.Errorf("posture: engine is not configured")
	}
	var sum Summary
	var err error
	for attempt := 0; ; attempt++ {
		if sum, err = e.evaluateOnce(ctx, scope); err == nil || attempt >= len(e.run.backoff) || ctx.Err() != nil {
			return sum, err
		}
		select {
		case <-ctx.Done():
			return sum, ctx.Err()
		case <-time.After(e.run.backoff[attempt]):
		}
	}
}

func (e *Engine) evaluateOnce(ctx context.Context, scope Scope) (Summary, error) {
	ov, err := e.loadOverrides(ctx)
	if err != nil {
		return Summary{}, err
	}
	full := scope.Full
	for pack, v := range e.versions {
		if ov.versions[pack] != v {
			full = true
		}
	}
	sum := Summary{Full: full}

	rules := slices.Clone(e.rules)
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].pack != rules[j].pack {
			return rules[i].pack < rules[j].pack
		}
		return rules[i].rule.ID < rules[j].rule.ID
	})
	kinds := map[string]bool{}
	for _, r := range rules {
		for _, k := range r.rule.AppliesTo {
			kinds[k] = true
		}
	}
	entities, err := e.scopeEntities(ctx, full, scope.Changed, kinds)
	if err != nil {
		return sum, err
	}
	sum.Entities = len(entities)

	sink := e.run.newSink(ctx)
	var out []findings.Finding
	var evals []Evaluation
	resolve := map[[2]string]bool{} // (asset, pack) to resolve after the run
	for _, ent := range entities {
		in := Input{ID: string(ent.ID), Type: ent.Type, Label: ent.Label, Attributes: ent.Attributes}
		entErr := false
		var entFindings []findings.Finding
		var entEvals []Evaluation
		for i := range rules {
			pr := &rules[i]
			if !slices.Contains(pr.rule.AppliesTo, ent.Type) {
				continue
			}
			if ctx.Err() != nil {
				return sum, ctx.Err()
			}
			if !ov.enabled(pr.pack, pr.rule.ID) {
				continue
			}
			ms, ee := e.evalRule(ctx, pr, in)
			ev := Evaluation{PackID: pr.pack, RuleID: pr.rule.ID, EntityID: in.ID, Result: ResultPass}
			switch {
			case ee != nil:
				ev.Result, ev.Error = ResultError, ee.Error()
				sum.Errors = append(sum.Errors, *ee)
				entErr = true
			case len(ms) > 0:
				ev.Result = ResultFail
				sort.SliceStable(ms, func(a, b int) bool { return ms[a].Discriminator < ms[b].Discriminator })
				for _, m := range ms {
					entFindings = append(entFindings, e.toFinding(pr, ov, m))
				}
			}
			entEvals = append(entEvals, ev)
		}
		evals = append(evals, entEvals...)
		out = append(out, entFindings...)
		if !entErr { // a rule that errored may not have run to its end: keep its Issues
			for _, p := range e.packsFor(ent.Type) {
				resolve[[2]string{in.ID, p}] = true
			}
		}
	}
	sum.Findings = len(out)
	if len(out) > 0 {
		if err := sink.Findings(out); err != nil {
			return sum, err
		}
	}
	keys := make([][2]string, 0, len(resolve))
	for k := range resolve {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i][0] != keys[j][0] {
			return keys[i][0] < keys[j][0]
		}
		return keys[i][1] < keys[j][1]
	})
	for _, k := range keys {
		n, err := sink.ResolveMissing(ctx, k[0], SourcePrefix+k[1])
		if err != nil {
			return sum, err
		}
		sum.Resolved += n
	}
	if err := e.persist(ctx, evals, rules, ov, full); err != nil {
		return sum, err
	}
	return sum, nil
}

func (e *Engine) packsFor(kind string) []string {
	var ps []string
	for _, r := range e.rules {
		if slices.Contains(r.rule.AppliesTo, kind) && !slices.Contains(ps, r.pack) {
			ps = append(ps, r.pack)
		}
	}
	sort.Strings(ps)
	return ps
}

// scopeEntities returns the entities to check, sorted by ID.
func (e *Engine) scopeEntities(ctx context.Context, full bool, changed []facade.EntityID, kinds map[string]bool) ([]facade.Entity, error) {
	byID := map[facade.EntityID]facade.Entity{}
	if full {
		for kind := range kinds {
			cursor := ""
			for {
				pg, err := e.reader.Find(ctx, facade.FindQuery{Type: kind, Paging: facade.Paging{PageSize: facade.MaxPageSize, Cursor: cursor}})
				if err != nil {
					return nil, err
				}
				for _, en := range pg.Items {
					byID[en.ID] = en
				}
				if pg.NextCursor == "" {
					break
				}
				cursor = pg.NextCursor
			}
		}
	} else {
		ids := map[facade.EntityID]bool{}
		for _, id := range changed {
			ids[id] = true
			cursor := ""
			for {
				pg, err := e.reader.Neighbors(ctx, id, facade.NeighborOpts{Direction: facade.DirBoth, Depth: 1,
					Paging: facade.Paging{PageSize: facade.MaxPageSize, Cursor: cursor}})
				if err != nil {
					return nil, err
				}
				for _, ed := range pg.Items {
					ids[ed.From], ids[ed.To] = true, true
				}
				if pg.NextCursor == "" {
					break
				}
				cursor = pg.NextCursor
			}
		}
		for id := range ids {
			en, err := e.reader.Entity(ctx, id, nil)
			if err != nil { // removed or unknown entity: nothing to evaluate
				continue
			}
			if kinds[en.Type] {
				byID[id] = en
			}
		}
	}
	out := make([]facade.Entity, 0, len(byID))
	for _, en := range byID {
		out = append(out, en)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func findingType(r Rule) findings.Type {
	switch {
	case r.Kind == KindIdentity:
		return findings.TypeIdentityRisk
	case r.Category == schema.OvData:
		return findings.TypeDataExposure
	}
	return findings.TypeMisconfiguration
}

func (e *Engine) toFinding(pr *preparedRule, ov *overrideSet, m Match) findings.Finding {
	r := pr.rule
	f := findings.Finding{
		ID:              findings.ID(pr.pack+"/"+r.ID, m.EntityID, m.Discriminator),
		RuleID:          r.ID,
		Title:           r.Title,
		Description:     r.Description,
		Category:        r.Category,
		Type:            findingType(r),
		Severity:        ov.severity(pr.pack, r.ID, r.Severity),
		Status:          findings.StatusOpen,
		AssetID:         m.EntityID,
		Source:          SourcePrefix + pr.pack,
		RulePackVersion: e.versions[pr.pack],
	}
	f.Evidence = append(f.Evidence, findings.EvidenceRef{Kind: "entity", Ref: m.EntityID})
	keys := make([]string, 0, len(m.Evidence))
	for k := range m.Evidence {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		f.Evidence = append(f.Evidence, findings.EvidenceRef{Kind: "attribute", Ref: k, Excerpt: m.Evidence[k]})
	}
	for _, h := range m.Path {
		f.Evidence = append(f.Evidence, findings.EvidenceRef{Kind: "edge", Ref: h.EntityID, Excerpt: h.Relation})
	}
	if len(f.Evidence) > findings.MaxEvidence {
		f.Evidence = f.Evidence[:findings.MaxEvidence]
	}
	if r.Remediation != "" {
		f.Details, _ = json.Marshal(map[string]string{"remediation": r.Remediation})
	}
	return f
}

// persist writes posture_eval rows and the pack versions of a finished run.
func (e *Engine) persist(ctx context.Context, evals []Evaluation, rules []preparedRule, ov *overrideSet, full bool) error {
	ws := e.run.db.WorkspaceID()
	now := e.run.now().UTC().Format(time.RFC3339Nano)
	return e.run.db.Write(ctx, ws, func(tx *sql.Tx) error {
		// Rows of rules that are now disabled would still count in compliance.
		for _, pr := range rules {
			if !ov.enabled(pr.pack, pr.rule.ID) {
				if _, err := tx.ExecContext(ctx, `DELETE FROM posture_eval WHERE workspace_id=? AND pack_id=? AND rule_id=?`, ws, pr.pack, pr.rule.ID); err != nil {
					return err
				}
			}
		}
		for _, ev := range evals {
			var msg any
			if ev.Error != "" {
				msg = ev.Error
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO posture_eval (workspace_id, pack_id, rule_id, entity_id, result, error, pack_version, evaluated_at)
				VALUES (?,?,?,?,?,?,?,?)
				ON CONFLICT (workspace_id, pack_id, rule_id, entity_id) DO UPDATE SET result=excluded.result, error=excluded.error,
				pack_version=excluded.pack_version, evaluated_at=excluded.evaluated_at`,
				ws, ev.PackID, ev.RuleID, ev.EntityID, string(ev.Result), msg, e.versions[ev.PackID], now); err != nil {
				return err
			}
		}
		if full {
			for pack, v := range e.versions {
				if _, err := tx.ExecContext(ctx, `INSERT INTO rule_pack_state (workspace_id, pack_id, version, enabled) VALUES (?,?,?,1)
					ON CONFLICT (workspace_id, pack_id) DO UPDATE SET version=excluded.version`, ws, pack, v); err != nil {
					return err
				}
			}
		}
		return nil
	})
}
