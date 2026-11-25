// Package cve serves the experimental CVE API under /api/experimental/cve:
// lookup, detail, graph, status and the mode change (Requirements 17.11 to
// 17.15, 21.9). Authentication is applied by the front door through the route
// table before a request reaches these handlers.
//
// Gating: the routes need security_scanners (DB mode) and answer 404 when it
// is off. Graph mode needs security_cve_graph. When that flag is off, a request
// that asks for mode=graph or mode=both (on any route, including PUT /mode)
// and GET /cve/graph return 400 invalid_request naming `mode`. They do not
// fall back to db. The key never appears in any response.
package cve

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/api/listquery"
	"github.com/bellu/bellucode/services/bellud/internal/config"
	"github.com/bellu/bellucode/services/bellud/internal/cvesource"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
)

// Prefix is the route prefix; handlers register full paths, so mount at "/".
const Prefix = "/api/experimental/cve"

// LocalActor is the audit actor when no authenticated identity is on the request.
const LocalActor = "local-user"

const (
	maxBody  = 4 << 10
	maxIDLen = 256
)

// ModeSetter changes the mode and appends the audit row atomically.
// *cvesource.DB implements it.
type ModeSetter interface {
	SetModeAudited(ctx context.Context, v, actor string) (cvesource.Mode, error)
}

// Deps are the handler dependencies. Modes may be nil, which makes PUT /mode answer 404.
type Deps struct {
	Source cvesource.Source
	Modes  ModeSetter
}

// Flags are the gating flags.
type Flags struct {
	Scanners bool // security_scanners
	Graph    bool // security_cve_graph
}

type handler struct {
	Deps
	graphOn bool
}

// New returns a handler serving the routes. See Mount.
func New(d Deps, f Flags) http.Handler {
	mux := http.NewServeMux()
	Mount(mux, d, f)
	return mux
}

// Mount registers the CVE routes on mux. Without the security_scanners flag or
// a source the routes answer 404.
func Mount(mux *http.ServeMux, d Deps, f Flags) {
	lookup, graphP, status := "GET "+Prefix+"/lookup", "GET "+Prefix+"/graph", "GET "+Prefix+"/status"
	mode, detail := "PUT "+Prefix+"/mode", "GET "+Prefix+"/{id}"
	if !f.Scanners || d.Source == nil {
		for _, p := range []string{lookup, graphP, status, mode, detail} {
			mux.HandleFunc(p, func(w http.ResponseWriter, _ *http.Request) { notFound(w, "cve is not enabled") })
		}
		return
	}
	h := &handler{Deps: d, graphOn: f.Graph}
	mux.HandleFunc(lookup, h.lookup)
	mux.HandleFunc(graphP, h.graph)
	mux.HandleFunc(status, h.status)
	mux.HandleFunc(mode, h.setMode)
	mux.HandleFunc(detail, h.detail)
}

// ---- wire types ----

type wireGap struct {
	Kind  string `json:"kind"`
	Cause string `json:"cause"`
}
type wireWarning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
type wireRange struct {
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
}
type wireVuln struct {
	ID            string      `json:"id"`
	Aliases       []string    `json:"aliases"`
	Summary       string      `json:"summary"`
	Severity      string      `json:"severity"`
	CVSSScore     float64     `json:"cvssScore"`
	CVSSVector    string      `json:"cvssVector,omitempty"`
	CVSSVersion   string      `json:"cvssVersion,omitempty"`
	Ranges        []wireRange `json:"ranges"`
	FixedVersions []string    `json:"fixedVersions"`
	KEV           bool        `json:"kev"`
	EPSS          float64     `json:"epss"`
	Published     string      `json:"published,omitempty"`
	Modified      string      `json:"modified,omitempty"`
	AffectedState string      `json:"affectedState,omitempty"`
	Origin        string      `json:"origin"`
}
type wireRef struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Key   string `json:"key"`
	Label string `json:"label"`
}
type wireMeta struct {
	Gaps      []wireGap         `json:"gaps"`
	Warnings  []wireWarning     `json:"warnings"`
	FieldFrom map[string]string `json:"fieldFrom"`
	Truncated bool              `json:"truncated"`
}
type wireLookup struct {
	Vulns []wireVuln `json:"vulns"`
	wireMeta
}
type wireDetail struct {
	wireVuln
	CWEs      []wireRef                     `json:"cwes"`
	Exploits  []wireRef                     `json:"exploits"`
	Affected  []wireRef                     `json:"affected"`
	Related   []wireRef                     `json:"related"`
	Conflicts map[string]cvesource.Conflict `json:"conflicts,omitempty"`
	wireMeta
}
type wireGraph struct {
	Nodes []cvesource.Node `json:"nodes"`
	Edges []cvesource.Edge `json:"edges"`
	wireMeta
}

func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func toVuln(v cvesource.Vuln) wireVuln {
	w := wireVuln{ID: v.ID, Aliases: nn(v.Aliases), Summary: v.Summary, Severity: v.Severity, CVSSScore: v.CVSSScore,
		CVSSVector: v.CVSSVector, CVSSVersion: v.CVSSVersion, FixedVersions: nn(v.FixedVersions), KEV: v.KEV, EPSS: v.EPSS,
		Published: ts(v.Published), Modified: ts(v.Modified), AffectedState: v.AffectedState, Origin: v.Origin,
		Ranges: make([]wireRange, 0, len(v.Ranges))}
	for _, r := range v.Ranges {
		w.Ranges = append(w.Ranges, wireRange{r.Introduced, r.Fixed})
	}
	return w
}

func nn(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func refs(rs []cvesource.Ref) []wireRef {
	out := make([]wireRef, 0, len(rs))
	for _, r := range rs {
		out = append(out, wireRef{r.ID, r.Type, r.Key, r.Label})
	}
	return out
}

func meta[T any](r cvesource.Result[T]) wireMeta {
	m := wireMeta{Gaps: []wireGap{}, Warnings: []wireWarning{}, FieldFrom: map[string]string{}, Truncated: r.Truncated}
	for _, g := range r.Gaps {
		m.Gaps = append(m.Gaps, wireGap{g.Kind, g.Cause})
	}
	for _, x := range r.Warnings {
		m.Warnings = append(m.Warnings, wireWarning{x.Code, x.Message})
	}
	for k, v := range r.FieldFrom {
		m.FieldFrom[k] = string(v)
	}
	return m
}

// ---- handlers ----

// modeParam parses an optional mode and applies the flag gate. ok false means
// the response is written.
func (h *handler) modeParam(w http.ResponseWriter, v string, required bool) (cvesource.Mode, bool) {
	if strings.TrimSpace(v) == "" && !required {
		return "", true
	}
	m, err := config.ParseCVEMode(config.CVEModeDB, v)
	if err != nil {
		invalid(w, "mode", "mode must be one of db, graph, both")
		return "", false
	}
	if m != config.CVEModeDB && !h.graphOn {
		invalid(w, "mode", "mode "+string(m)+" needs the security_cve_graph flag; allowed values: db")
		return "", false
	}
	return m, true
}

func (h *handler) lookup(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if _, ok := h.modeParam(w, q.Get("mode"), false); !ok {
		return
	}
	res, err := h.Source.Lookup(r.Context(), cvesource.LookupQuery{ID: q.Get("id"), Purl: q.Get("purl"), Version: q.Get("version"), CPE: q.Get("cpe")})
	if err != nil {
		h.fail(w, err)
		return
	}
	out := wireLookup{Vulns: make([]wireVuln, 0, len(res.Data)), wireMeta: meta(res)}
	for _, v := range res.Data {
		out.Vulns = append(out.Vulns, toVuln(v))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handler) detail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" || len(id) > maxIDLen {
		invalid(w, "id", "id must be 1 to 256 characters")
		return
	}
	m, ok := h.modeParam(w, r.URL.Query().Get("mode"), false)
	if !ok {
		return
	}
	res, err := h.Source.Detail(r.Context(), id, m)
	if err != nil {
		h.fail(w, err)
		return
	}
	if res.Data.Vuln.ID == "" && len(res.Gaps) == 0 {
		notFound(w, "no CVE record for "+id)
		return
	}
	d := res.Data
	writeJSON(w, http.StatusOK, wireDetail{wireVuln: toVuln(d.Vuln), CWEs: refs(d.CWEs), Exploits: refs(d.Exploits),
		Affected: refs(d.Affected), Related: refs(d.Related), Conflicts: d.Conflicts, wireMeta: meta(res)})
}

func (h *handler) graph(w http.ResponseWriter, r *http.Request) {
	if !h.graphOn {
		invalid(w, "mode", "graph queries need the security_cve_graph flag; allowed values: db")
		return
	}
	q := r.URL.Query()
	gq := cvesource.GraphQuery{ID: q.Get("id"), RelTypes: csv(q.Get("relTypes")), NodeTypes: csv(q.Get("nodeTypes"))}
	for _, p := range []struct {
		name string
		dst  *int
		min  int
	}{{"depth", &gq.Depth, 1}, {"limit", &gq.Limit, 1}} {
		if v := q.Get(p.name); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < p.min {
				invalid(w, p.name, p.name+" must be a positive integer")
				return
			}
			*p.dst = n
		}
	}
	res, err := h.Source.Graph(r.Context(), gq)
	if err != nil {
		h.fail(w, err)
		return
	}
	nodes, edges := res.Data.Nodes, res.Data.Edges
	if nodes == nil {
		nodes = []cvesource.Node{}
	}
	if edges == nil {
		edges = []cvesource.Edge{}
	}
	writeJSON(w, http.StatusOK, wireGraph{Nodes: nodes, Edges: edges, wireMeta: meta(res)})
}

func (h *handler) status(w http.ResponseWriter, _ *http.Request) {
	s := h.Source.Status()
	out := map[string]any{
		"mode": string(s.Mode), "dbInstalled": s.DBInstalled, "dataAgeHours": int(s.DBAge / time.Hour),
		"stale": s.DBStale, "staleLimitHours": int(s.StaleLimit / time.Hour), "bskgReachable": s.BSKGReachable,
		"graphEnabled": h.graphOn, "lastGap": nil,
	}
	if s.LastGap != nil {
		out["lastGap"] = wireGap{s.LastGap.Kind, s.LastGap.Cause}
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handler) setMode(w http.ResponseWriter, r *http.Request) {
	if h.Modes == nil {
		notFound(w, "cve mode changes are not available")
		return
	}
	var b struct {
		Mode *string `json:"mode"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	if err := dec.Decode(&b); err != nil || b.Mode == nil {
		invalid(w, "mode", "body must be {\"mode\": \"db|graph|both\"}")
		return
	}
	m, ok := h.modeParam(w, *b.Mode, true)
	if !ok {
		return
	}
	got, err := h.Modes.SetModeAudited(r.Context(), string(m), actorOf(r.Context()))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"mode": string(got)})
}

func (h *handler) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, cvesource.ErrGraphModeDisabled):
		invalid(w, "mode", "graph queries need cve.mode graph or both; allowed values: db, graph, both")
	case errors.Is(err, cvesource.ErrInvalidQuery):
		invalid(w, "query", err.Error())
	case errors.Is(err, cvesource.ErrAuditWrite):
		writeJSON(w, http.StatusInternalServerError, map[string]string{"_tag": "UnknownError", "code": "audit_write_failed", "message": "audit write failed; mode unchanged"})
	case strings.Contains(err.Error(), "cve.mode"):
		invalid(w, "mode", err.Error())
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"_tag": "UnknownError", "message": "internal error"})
	}
}

func csv(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func actorOf(ctx context.Context) string {
	if c, ok := graph.CallerFrom(ctx); ok && strings.TrimSpace(c.Identity) != "" {
		return c.Identity
	}
	return LocalActor
}

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
