// Package issues serves the experimental issues API under
// /api/experimental/issues: list, get and setStatus (Requirements 4.11).
// Authentication is applied by the front door through the route table.
package issues

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/api/listquery"
	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
	"github.com/bellu/bellucode/services/bellud/internal/issues"
)

// Prefix is the route prefix; handlers register full paths, so mount at "/".
const Prefix = "/api/experimental/issues"

// LocalActor is the status-change actor when no authenticated identity is on the request.
const LocalActor = "local-user"

const (
	maxStatusBody = 16 << 10
	maxIDLen      = 128
	// maxWindow is the most issues one query can page through (issues.Store.List cap).
	maxWindow = 1000
)

// Store is the part of issues.Store the handlers use.
type Store interface {
	List(ctx context.Context, q issues.Query) ([]issues.Issue, error)
	Get(ctx context.Context, id string) (issues.Issue, error)
	SetStatus(ctx context.Context, id string, to issues.Status, actor string) error
}

// Findings resolves member findings; *findings.Store satisfies it. May be nil.
type Findings interface {
	Get(ctx context.Context, id string) (findings.Finding, []findings.StatusEvent, error)
}

// Spec is the list query contract of GET /issues. Order is fixed: risk score
// descending, then updated_at descending.
var Spec = listquery.Spec{
	Filters:     []string{listquery.Category, listquery.Severity, listquery.Status, listquery.Asset},
	Sorts:       []string{"risk_score"},
	DefaultSort: "-risk_score",
	Domains: map[string][]string{
		listquery.Status: {string(issues.StatusOpen), string(issues.StatusResolved), string(issues.StatusIgnored)},
	},
}

type handler struct {
	store    Store
	findings Findings
}

// New returns a handler serving the three routes. See Mount.
func New(store Store, fs Findings, enabled bool) http.Handler {
	mux := http.NewServeMux()
	Mount(mux, store, fs, enabled)
	return mux
}

// Mount registers the issue routes on mux. When the security_posture flag is
// off (enabled false) or there is no store, the routes answer 404.
func Mount(mux *http.ServeMux, store Store, fs Findings, enabled bool) {
	list, get, set := "GET "+Prefix, "GET "+Prefix+"/{id}", "POST "+Prefix+"/{id}/status"
	if !enabled || store == nil {
		for _, p := range []string{list, get, set} {
			mux.HandleFunc(p, func(w http.ResponseWriter, _ *http.Request) { notFound(w, "issues are not enabled") })
		}
		return
	}
	h := &handler{store: store, findings: fs}
	mux.HandleFunc(list, h.list)
	mux.HandleFunc(get, h.get)
	mux.HandleFunc(set, h.setStatus)
}

// ---- wire types ----

type wireHop struct {
	EntityID string   `json:"entityId"`
	Relation string   `json:"relation,omitempty"`
	Evidence []string `json:"evidence"`
	Inferred bool     `json:"inferred"`
}

type wireIssue struct {
	ID               string    `json:"id"`
	Title            string    `json:"title"`
	RuleID           string    `json:"ruleId"`
	Severity         string    `json:"severity"`
	RiskScore        float64   `json:"riskScore"`
	Status           string    `json:"status"`
	Category         string    `json:"category"`
	IncludesInferred bool      `json:"includesInferred"`
	FindingCount     int       `json:"findingCount"`
	Path             []wireHop `json:"path"`
	CreatedAt        string    `json:"createdAt"`
	UpdatedAt        string    `json:"updatedAt"`
}

type wireMember struct {
	ID       string `json:"id"`
	Title    string `json:"title,omitempty"`
	RuleID   string `json:"ruleId,omitempty"`
	Severity string `json:"severity,omitempty"`
	Status   string `json:"status,omitempty"`
	AssetID  string `json:"assetId,omitempty"`
}

type wireDetail struct {
	wireIssue
	Findings []wireMember `json:"findings"`
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func toWire(is issues.Issue) wireIssue {
	path := make([]wireHop, 0, len(is.Path))
	for _, h := range is.Path {
		ev := h.Evidence
		if ev == nil {
			ev = []string{}
		}
		path = append(path, wireHop{EntityID: h.EntityID, Relation: h.Relation, Evidence: ev, Inferred: h.Inferred})
	}
	return wireIssue{ID: is.ID, Title: is.Title, RuleID: is.RuleID, Severity: string(is.Severity), RiskScore: is.RiskScore,
		Status: string(is.Status), Category: string(is.Category), IncludesInferred: is.IncludesInferred,
		FindingCount: len(is.FindingIDs), Path: path, CreatedAt: ts(is.CreatedAt), UpdatedAt: ts(is.UpdatedAt)}
}

// ---- handlers ----

func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	q, err := Spec.Parse(r.URL.Query())
	if listquery.WriteIfInvalid(w, err) {
		return
	}
	offset := 0
	if q.Position != "" {
		offset, err = strconv.Atoi(q.Position)
		if err != nil || offset < 0 {
			invalid(w, "cursor", "malformed cursor")
			return
		}
	}
	if len(q.Assets) > 1 {
		invalid(w, "asset", "only one asset may be given")
		return
	}
	sq := issues.Query{Limit: maxWindow}
	for _, c := range q.Categories {
		sq.Categories = append(sq.Categories, schema.OverviewCategory(c))
	}
	for _, s := range q.Severities {
		sq.Severities = append(sq.Severities, findings.Severity(s))
	}
	for _, s := range q.Statuses {
		sq.Statuses = append(sq.Statuses, issues.Status(s))
	}
	if len(q.Assets) == 1 {
		sq.AssetID = q.Assets[0]
	}
	ctx, cancel := listquery.Budget(r.Context())
	defer cancel()
	all, err := h.store.List(ctx, sq)
	out := listquery.Page[wireIssue]{Items: []wireIssue{}}
	switch {
	case err != nil && listquery.Truncated(ctx, err):
		out.Truncated = true
	case err != nil:
		fail(w, err)
		return
	default:
		end := min(offset+q.Limit, len(all))
		for _, is := range all[min(offset, end):end] {
			out.Items = append(out.Items, toWire(is))
		}
		if end < len(all) {
			out.NextCursor = q.NextCursor(strconv.Itoa(end))
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handler) get(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	h.writeDetail(w, r, id)
}

func (h *handler) writeDetail(w http.ResponseWriter, r *http.Request, id string) {
	is, err := h.store.Get(r.Context(), id)
	if err != nil {
		fail(w, err)
		return
	}
	d := wireDetail{wireIssue: toWire(is), Findings: make([]wireMember, 0, len(is.FindingIDs))}
	for _, fid := range is.FindingIDs {
		m := wireMember{ID: fid}
		if h.findings != nil {
			if f, _, err := h.findings.Get(r.Context(), fid); err == nil {
				m = wireMember{ID: fid, Title: f.Title, RuleID: f.RuleID, Severity: string(f.Severity), Status: string(f.Status), AssetID: f.AssetID}
			}
		}
		d.Findings = append(d.Findings, m)
	}
	writeJSON(w, http.StatusOK, d)
}

type statusBody struct {
	Status string `json:"status"`
}

func (h *handler) setStatus(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var body statusBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxStatusBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		invalid(w, "body", "must be a JSON object {status}")
		return
	}
	switch issues.Status(body.Status) {
	case issues.StatusOpen, issues.StatusResolved, issues.StatusIgnored:
	default:
		invalid(w, "status", "must be one of open, resolved, ignored")
		return
	}
	if err := h.store.SetStatus(r.Context(), id, issues.Status(body.Status), actorOf(r.Context())); err != nil {
		fail(w, err)
		return
	}
	h.writeDetail(w, r, id)
}

func actorOf(ctx context.Context) string {
	if c, ok := graph.CallerFrom(ctx); ok && strings.TrimSpace(c.Identity) != "" {
		return c.Identity
	}
	return LocalActor
}

func idParam(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if id == "" || len(id) > maxIDLen {
		invalid(w, "id", "must be 1 to 128 characters")
		return "", false
	}
	return id, true
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

func fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, issues.ErrNotFound):
		notFound(w, "issue not found")
	case errors.Is(err, issues.ErrInvalid):
		invalid(w, "status", "invalid")
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"_tag": "UnknownError", "message": "internal error"})
	}
}
