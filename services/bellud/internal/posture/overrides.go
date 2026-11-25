package posture

import (
	"context"
	"database/sql"
	"errors"

	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
)

// overrideSet is the loaded override state of a workspace.
type overrideSet struct {
	packEnabled map[string]bool
	packSev     map[string]findings.Severity
	ruleEnabled map[[2]string]bool
	ruleSev     map[[2]string]findings.Severity
	versions    map[string]string // versions at the last successful run
}

// enabled reports whether a rule runs. A rule setting beats the pack setting (10.8).
func (o *overrideSet) enabled(pack, rule string) bool {
	if v, ok := o.ruleEnabled[[2]string{pack, rule}]; ok {
		return v
	}
	if v, ok := o.packEnabled[pack]; ok {
		return v
	}
	return true
}

// severity returns the effective severity; a rule override beats a pack override.
func (o *overrideSet) severity(pack, rule string, def findings.Severity) findings.Severity {
	if v, ok := o.ruleSev[[2]string{pack, rule}]; ok {
		return v
	}
	if v, ok := o.packSev[pack]; ok {
		return v
	}
	return def
}

func (e *Engine) loadOverrides(ctx context.Context) (*overrideSet, error) {
	db := e.run.db.DB()
	ws := e.run.db.WorkspaceID()
	o := &overrideSet{packEnabled: map[string]bool{}, packSev: map[string]findings.Severity{},
		ruleEnabled: map[[2]string]bool{}, ruleSev: map[[2]string]findings.Severity{}, versions: map[string]string{}}
	rows, err := db.QueryContext(ctx, `SELECT pack_id, version, enabled, severity_override FROM rule_pack_state WHERE workspace_id=?`, ws)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var pack, ver string
		var en int
		var sev sql.NullString
		if err := rows.Scan(&pack, &ver, &en, &sev); err != nil {
			rows.Close()
			return nil, err
		}
		o.versions[pack] = ver
		o.packEnabled[pack] = en != 0
		if sev.Valid && sev.String != "" {
			o.packSev[pack] = findings.Severity(sev.String)
		}
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	rows, err = db.QueryContext(ctx, `SELECT pack_id, rule_id, enabled, severity_override FROM rule_override WHERE workspace_id=?`, ws)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var pack, rule string
		var en sql.NullInt64
		var sev sql.NullString
		if err := rows.Scan(&pack, &rule, &en, &sev); err != nil {
			return nil, err
		}
		k := [2]string{pack, rule}
		if en.Valid {
			o.ruleEnabled[k] = en.Int64 != 0
		}
		if sev.Valid && sev.String != "" {
			o.ruleSev[k] = findings.Severity(sev.String)
		}
	}
	return o, rows.Err()
}

// SetOverride stores an override. RuleID empty targets the pack. A nil field
// means "inherit": the pack default for a rule, enabled/unchanged for a pack.
// The next Evaluate sees it; findings of a disabled rule are resolved by it.
func (e *Engine) SetOverride(ctx context.Context, o Override) error {
	return e.setOverride(ctx, o, nil)
}

// OverrideAudit describes the audit row written with an override.
type OverrideAudit struct{ Actor, Action, Target, Outcome string }

// SetOverrideAudited stores the override and appends the audit row in the same
// transaction, so either both persist or neither does.
func (e *Engine) SetOverrideAudited(ctx context.Context, o Override, a OverrideAudit) error {
	return e.setOverride(ctx, o, &a)
}

func (e *Engine) setOverride(ctx context.Context, o Override, a *OverrideAudit) error {
	if e.run.db == nil {
		return errors.New("posture: engine has no database")
	}
	if o.Severity != nil && !validSeverity(*o.Severity) {
		return errors.New("posture: unknown severity " + string(*o.Severity))
	}
	var en any
	if o.Enabled != nil {
		en = boolInt(*o.Enabled)
	}
	var sev any
	if o.Severity != nil {
		sev = string(*o.Severity)
	}
	ws := e.run.db.WorkspaceID()
	return e.run.db.Write(ctx, ws, func(tx *sql.Tx) error {
		if a != nil {
			if err := sqlite.AppendAudit(ctx, tx, ws, sqlite.AuditEntry{Actor: a.Actor, Action: a.Action, Target: a.Target, Outcome: a.Outcome}); err != nil {
				return err
			}
		}
		if o.RuleID != "" {
			_, err := tx.ExecContext(ctx, `INSERT INTO rule_override (workspace_id, pack_id, rule_id, enabled, severity_override) VALUES (?,?,?,?,?)
				ON CONFLICT (workspace_id, pack_id, rule_id) DO UPDATE SET enabled=excluded.enabled, severity_override=excluded.severity_override`,
				ws, o.PackID, o.RuleID, en, sev)
			return err
		}
		// A new row gets version "", which differs from any pack version, so the
		// next run is a full one; only a successful run stores the real version.
		enabled := 1
		if o.Enabled != nil {
			enabled = boolInt(*o.Enabled)
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO rule_pack_state (workspace_id, pack_id, version, enabled, severity_override) VALUES (?,?,?,?,?)
			ON CONFLICT (workspace_id, pack_id) DO UPDATE SET enabled=excluded.enabled, severity_override=excluded.severity_override`,
			ws, o.PackID, "", enabled, sev)
		return err
	})
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func validSeverity(s findings.Severity) bool {
	switch s {
	case findings.SevCritical, findings.SevHigh, findings.SevMedium, findings.SevLow, findings.SevInfo:
		return true
	}
	return false
}
