// Package rules serves the experimental rules API under
// /api/experimental/rules: packs, pack rules, overrides and compliance
// (Requirements 10.8, 10.9). Authentication is applied by the front door
// through the route table.
package rules

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	"github.com/bellu/bellucode/services/bellud/internal/api/listquery"
	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/posture"
)

// Prefix is the route prefix; handlers register full paths, so mount at "/".
const Prefix = "/api/experimental/rules"

// LocalActor is the audit actor when no authenticated identity is on the request.
const LocalActor = "local-user"

const (
	maxBody  = 16 << 10
	maxIDLen = 256
)

// Engine is the part of posture.Engine the handlers use.
type Engine interface {
	Packs(ctx context.Context) ([]posture.PackInfo, error)
	RulesOf(ctx context.Context, pack string) ([]posture.RuleInfo, bool, error)
	SetOverride(ctx context.Context, o posture.Override) error
	Benchmarks() []string
	Compliance(ctx context.Context, benchmark string) ([]posture.ControlResult, error)
}

// Auditor stores an override and its audit row atomically. *posture.Engine
// implements it.
type Auditor interface {
	SetOverrideAudited(ctx context.Context, o posture.Override, a posture.OverrideAudit) error
}

type handler struct {
	engine Engine
	audit  Auditor
}

// New returns a handler serving the four routes. See Mount.
func New(engine Engine, audit Auditor, enabled bool) http.Handler {
	mux := http.NewServeMux()
	Mount(mux, engine, audit, enabled)
	return mux
}

// Mount registers the rules routes on mux. When the security_posture flag is
// off (enabled false) or there is no engine, the routes answer 404.
func Mount(mux *http.ServeMux, engine Engine, audit Auditor, enabled bool) {
	packs, rules := "GET "+Prefix+"/packs", "GET "+Prefix+"/packs/{id}/rules"
	over, comp := "PUT "+Prefix+"/overrides", "GET "+Prefix+"/compliance"
	if !enabled || engine == nil {
		for _, p := range []string{packs, rules, over, comp} {
			mux.HandleFunc(p, func(w http.ResponseWriter, _ *http.Request) { notFound(w, "rules are not enabled") })
		}
		return
	}
	h := &handler{engine: engine, audit: audit}
	mux.HandleFunc(packs, h.packs)
	mux.HandleFunc(rules, h.rules)
	mux.HandleFunc(over, h.override)
	mux.HandleFunc(comp, h.compliance)
}

// ---- wire types ----

type wirePack struct {
	ID        string `json:"id"`
	Version   string `json:"version"`
	Enabled   bool   `json:"enabled"`
	RuleCount int    `json:"ruleCount"`
}

type wireRule struct {
	ID          string   `json:"id"`
	PackID      string   `json:"packId"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Kind        string   `json:"kind"`
	Category    string   `json:"category"`
	AppliesTo   []string `json:"appliesTo"`
	Benchmarks  []string `json:"benchmarks"`
	Enabled     bool     `json:"enabled"`
	Severity    string   `json:"severity"`
	DefaultSev  string   `json:"defaultSeverity"`
}

type wireControl struct {
	Control         string `json:"control"`
	Status          string `json:"status"`
	FailingEntities int    `json:"failingEntities"`
}

// ---- handlers ----

func (h *handler) packs(w http.ResponseWriter, r *http.Request) {
	ps, err := h.engine.Packs(r.Context())
	if err != nil {
		fail(w)
		return
	}
	out := make([]wirePack, 0, len(ps))
	for _, p := range ps {
		out = append(out, wirePack{ID: p.ID, Version: p.Version, Enabled: p.Enabled, RuleCount: p.Rules})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *handler) rules(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" || len(id) > maxIDLen {
		invalid(w, "id", "must be 1 to 256 characters")
		return
	}
	rs, ok, err := h.engine.RulesOf(r.Context(), id)
	if err != nil {
		fail(w)
		return
	}
	if !ok {
		notFound(w, "rule pack not found")
		return
	}
	out := make([]wireRule, 0, len(rs))
	for _, x := range rs {
		out = append(out, toWireRule(x))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func toWireRule(x posture.RuleInfo) wireRule {
	return wireRule{ID: x.Rule.ID, PackID: x.PackID, Title: x.Rule.Title, Description: x.Rule.Description,
		Kind: string(x.Rule.Kind), Category: string(x.Rule.Category), AppliesTo: nonNil(x.Rule.AppliesTo), Benchmarks: nonNil(x.Rule.Benchmarks),
		Enabled: x.Enabled, Severity: string(x.Severity), DefaultSev: string(x.Rule.Severity)}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

type overrideBody struct {
	PackID   string  `json:"packId"`
	RuleID   string  `json:"ruleId"`
	Enabled  *bool   `json:"enabled"`
	Severity *string `json:"severity"`
}

func (h *handler) override(w http.ResponseWriter, r *http.Request) {
	var b overrideBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		invalid(w, "body", "must be a JSON object {packId, ruleId?, enabled?, severity?}")
		return
	}
	if strings.TrimSpace(b.PackID) == "" || len(b.PackID) > maxIDLen {
		invalid(w, "packId", "required")
		return
	}
	if len(b.RuleID) > maxIDLen {
		invalid(w, "ruleId", "too long")
		return
	}
	o := posture.Override{PackID: b.PackID, RuleID: b.RuleID, Enabled: b.Enabled}
	if b.Severity != nil {
		if !slices.Contains([]string{"critical", "high", "medium", "low", "info"}, *b.Severity) {
			invalid(w, "severity", "must be one of critical, high, medium, low, info")
			return
		}
		sev := findings.Severity(*b.Severity)
		o.Severity = &sev
	}
	rs, ok, err := h.engine.RulesOf(r.Context(), b.PackID)
	if err != nil {
		fail(w)
		return
	}
	if !ok {
		notFound(w, "rule pack not found")
		return
	}
	if b.RuleID != "" && !slices.ContainsFunc(rs, func(x posture.RuleInfo) bool { return x.Rule.ID == b.RuleID }) {
		notFound(w, "rule not found")
		return
	}
	target := b.PackID
	if b.RuleID != "" {
		target += "/" + b.RuleID
	}
	var err2 error
	if h.audit != nil {
		detail, _ := json.Marshal(map[string]any{"enabled": b.Enabled, "severity": b.Severity})
		err2 = h.audit.SetOverrideAudited(r.Context(), o, posture.OverrideAudit{Actor: actorOf(r.Context()), Action: "rule.override", Target: target, Outcome: string(detail)})
	} else {
		err2 = h.engine.SetOverride(r.Context(), o)
	}
	if err2 != nil {
		fail(w)
		return
	}
	if b.RuleID == "" {
		ps, err := h.engine.Packs(r.Context())
		if err != nil {
			fail(w)
			return
		}
		for _, p := range ps {
			if p.ID == b.PackID {
				writeJSON(w, http.StatusOK, wirePack{ID: p.ID, Version: p.Version, Enabled: p.Enabled, RuleCount: p.Rules})
				return
			}
		}
	}
	rs, _, err = h.engine.RulesOf(r.Context(), b.PackID)
	if err != nil {
		fail(w)
		return
	}
	for _, x := range rs {
		if x.Rule.ID == b.RuleID {
			writeJSON(w, http.StatusOK, toWireRule(x))
			return
		}
	}
	fail(w)
}

func (h *handler) compliance(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	for k := range q {
		if k != "benchmark" {
			invalid(w, k, "unknown parameter")
			return
		}
	}
	bs, given := q["benchmark"]
	if !given {
		list := h.engine.Benchmarks()
		if list == nil {
			list = []string{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"benchmarks": list})
		return
	}
	if len(bs) != 1 || bs[0] == "" || len(bs[0]) > maxIDLen {
		invalid(w, "benchmark", "must be given once and not empty")
		return
	}
	if !slices.Contains(h.engine.Benchmarks(), bs[0]) {
		notFound(w, "benchmark not found")
		return
	}
	ctx, cancel := listquery.Budget(r.Context())
	defer cancel()
	cs, err := h.engine.Compliance(ctx, bs[0])
	if err != nil {
		fail(w)
		return
	}
	out := make([]wireControl, 0, len(cs))
	for _, c := range cs {
		out = append(out, wireControl{Control: c.Control, Status: string(c.Status), FailingEntities: c.FailingEntities})
	}
	writeJSON(w, http.StatusOK, map[string]any{"benchmark": bs[0], "controls": out})
}

func actorOf(ctx context.Context) string {
	if c, ok := graph.CallerFrom(ctx); ok && strings.TrimSpace(c.Identity) != "" {
		return c.Identity
	}
	return LocalActor
}

// ---- responses ----

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func invalid(w http.ResponseWriter, field, msg string) {
	listquery.WriteError(w, &listquery.Error{Param: field, Msg: msg})
}

func notFound(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusNotFound, map[string]string{"_tag": "NotFoundError", "message": msg})
}

func fail(w http.ResponseWriter) {
	writeJSON(w, http.StatusInternalServerError, map[string]string{"_tag": "UnknownError", "message": "internal error"})
}
