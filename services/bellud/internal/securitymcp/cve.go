package securitymcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/cvesource"
)

// QueryCVE is the read-only CVE lookup tool name.
const QueryCVE = "security_query_cve"

// MaxCVEResults bounds the vulnerabilities returned by a purl lookup.
const MaxCVEResults = 50

var cveSchema = obj([]string{}, map[string]any{
	"id":      map[string]any{"type": "string", "description": "CVE id or alias"},
	"purl":    map[string]any{"type": "string", "description": "package url, used when id is empty"},
	"version": map[string]any{"type": "string", "description": "version for purl"},
	"mode":    map[string]any{"type": "string", "enum": []string{"db", "graph", "both"}, "description": "with id, returns the detail view in that mode; omitted means local DB lookup"},
})

type cveOut struct {
	ID            string   `json:"id"`
	Aliases       []string `json:"aliases"`
	Summary       string   `json:"summary,omitempty"`
	Severity      string   `json:"severity,omitempty"`
	CVSSScore     float64  `json:"cvss_score,omitempty"`
	FixedVersions []string `json:"fixed_versions"`
	KEV           bool     `json:"kev"`
	EPSS          float64  `json:"epss,omitempty"`
	Published     string   `json:"published,omitempty"`
	Modified      string   `json:"modified,omitempty"`
	AffectedState string   `json:"affected_state,omitempty"`
	Origin        string   `json:"origin,omitempty"`
}

func trimVuln(v cvesource.Vuln) cveOut {
	o := cveOut{ID: v.ID, Aliases: append([]string{}, v.Aliases...), Summary: v.Summary, Severity: v.Severity,
		CVSSScore: v.CVSSScore, FixedVersions: append([]string{}, v.FixedVersions...), KEV: v.KEV, EPSS: v.EPSS,
		AffectedState: v.AffectedState, Origin: v.Origin}
	if !v.Published.IsZero() {
		o.Published = v.Published.UTC().Format(time.RFC3339)
	}
	if !v.Modified.IsZero() {
		o.Modified = v.Modified.UTC().Format(time.RFC3339)
	}
	return o
}

func cveMeta(gaps []cvesource.Gap, warns []cvesource.Warning, trunc bool) map[string]any {
	g := make([]map[string]string, 0, len(gaps))
	for _, x := range gaps {
		g = append(g, map[string]string{"kind": x.Kind, "cause": x.Cause})
	}
	w := make([]map[string]string, 0, len(warns))
	for _, x := range warns {
		w = append(w, map[string]string{"code": x.Code, "message": x.Message})
	}
	return map[string]any{"gaps": g, "warnings": w, "truncated": trunc}
}

func refIDs(rs []cvesource.Ref) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.ID)
	}
	return out
}

func queryCVE(ctx context.Context, src cvesource.Source, raw json.RawMessage) (any, error) {
	var in struct {
		ID      string `json:"id"`
		Purl    string `json:"purl"`
		Version string `json:"version"`
		Mode    string `json:"mode"`
	}
	if err := decode(raw, &in); err != nil {
		return nil, err
	}
	id, purl := strings.TrimSpace(in.ID), strings.TrimSpace(in.Purl)
	if (id == "") == (purl == "") {
		return nil, errors.New("invalid arguments: set exactly one of id or purl")
	}
	switch in.Mode {
	case "", "db", "graph", "both":
	default:
		return nil, errors.New("invalid mode: must be db, graph or both")
	}
	if in.Mode != "" && id != "" {
		res, err := src.Detail(ctx, id, cvesource.Mode(in.Mode))
		if err != nil {
			return nil, err
		}
		out := cveMeta(res.Gaps, res.Warnings, res.Truncated)
		out["vulnerability"] = trimVuln(res.Data.Vuln)
		out["cwes"] = refIDs(res.Data.CWEs)
		out["exploits"] = refIDs(res.Data.Exploits)
		out["affected"] = refIDs(res.Data.Affected)
		out["related"] = refIDs(res.Data.Related)
		conf := make([]string, 0, len(res.Data.Conflicts))
		for k := range res.Data.Conflicts {
			conf = append(conf, k)
		}
		out["conflicts"] = conf
		return out, nil
	}
	if in.Mode != "" {
		return nil, errors.New("invalid arguments: mode needs id")
	}
	res, err := src.Lookup(ctx, cvesource.LookupQuery{ID: id, Purl: purl, Version: in.Version})
	if err != nil {
		return nil, err
	}
	trunc := res.Truncated
	data := res.Data
	if len(data) > MaxCVEResults {
		data, trunc = data[:MaxCVEResults], true
	}
	items := make([]cveOut, 0, len(data))
	for _, v := range data {
		items = append(items, trimVuln(v))
	}
	out := cveMeta(res.Gaps, res.Warnings, trunc)
	out["items"] = items
	return out, nil
}
