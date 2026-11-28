package misconfig

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
	"github.com/bellu/bellucode/services/bellud/internal/scanners"
)

// Convert maps Trivy results to findings: one per (check, resource), failed
// checks only. The Finding asset is the repository target, so ResolveMissing
// works per repository. A finding whose file and resource address match an
// iac_resource of links (keyed "path\x00address", the path joined to the
// target path) carries that Entity_ID in an entity evidence reference and in
// Details.iac_resource; otherwise it is unlinked.
func Convert(results scan.Results, t scanners.Target, links map[string]string) ([]findings.Finding, error) {
	seen := map[string]bool{}
	var out []findings.Finding
	for _, r := range results {
		status := r.Status()
		if status != scan.StatusFailed && status != scan.StatusIgnored {
			continue
		}
		rule := r.Rule()
		if status == scan.StatusIgnored && rule.AVDID == "" && rule.ID == "" {
			continue
		}
		ruleID := rule.AVDID
		if ruleID == "" {
			ruleID = rule.ID
		}
		if !strings.HasPrefix(ruleID, "AVD-") {
			ruleID = "AVD-" + ruleID
		}
		rng := r.Range()
		file := filepath.ToSlash(rng.GetFilename())
		addr := r.Metadata().Reference()
		id := findings.ID(ruleID, t.ID, file+"\x00"+addr)
		if seen[id] {
			continue
		}
		seen[id] = true

		sev, unmapped := findings.MapSeverity("trivy", string(r.Severity()))
		title := rule.Summary
		if title == "" {
			title = r.Description()
		}
		if title == "" {
			title = ruleID
		}
		ev := []findings.EvidenceRef{{Kind: "file", Ref: file, Line: rng.GetStartLine()}}
		details := map[string]any{
			"path": file, "start_line": rng.GetStartLine(), "end_line": rng.GetEndLine(),
			"resource": addr, "remediation": rule.Resolution,
		}
		if eid, ok := links[filepath.Join(t.Path, file)+"\x00"+addr]; ok {
			ev = append(ev, findings.EvidenceRef{Kind: "entity", Ref: eid})
			details["iac_resource"] = eid
		}
		raw, err := json.Marshal(details)
		if err != nil {
			return nil, err
		}
		st, reason := findings.StatusOpen, ""
		if status == scan.StatusIgnored {
			st, reason = findings.StatusIgnored, "inline" // Trivy's #trivy:ignore comment (8.8)
		}
		out = append(out, findings.Finding{
			ID: id, RuleID: ruleID, Title: title, Description: r.Description(),
			Category: schema.OvCode, Type: findings.TypeMisconfiguration, Severity: sev,
			Status: st, IgnoreReason: reason, AssetID: t.ID, Evidence: ev,
			Source: Name, UnmappedSeverity: unmapped, Details: raw,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		return strings.Compare(out[i].ID, out[j].ID) < 0
	})
	return out, nil
}
