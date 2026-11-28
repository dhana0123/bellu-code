// Package findings serves the experimental findings API under
// /api/experimental/findings: list, get and setStatus (Requirements 20.1,
// 20.2, 3.9, 3.10). Authentication is applied by the front door through the
// route table before a request reaches these handlers (20.11, 20.12), so the
// handlers never see an unauthenticated request.
package findings

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/api/listquery"
	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
)

// Prefix is the route prefix; handlers register full paths, so mount at "/".
const Prefix = "/api/experimental/findings"

// LocalActor is the status-change actor when no authenticated identity is on the request.
const LocalActor = "local-user"

// maxStatusBody bounds a setStatus body; a reason is at most 1,024 characters.
const maxStatusBody = 16 << 10

// maxIDLen bounds the id path segment. Finding ids are 32 hex characters.
const maxIDLen = 128

// Spec is the list query contract of GET /findings.
var Spec = listquery.Spec{
	Filters:     listquery.AllFilters,
	Sorts:       []string{findings.SortLastSeen, findings.SortFirstSeen, findings.SortSeverity, findings.SortRiskScore},
	DefaultSort: "-" + findings.SortLastSeen,
}

type handler struct{ store *findings.Store }

// New returns a handler serving the three routes. See Mount.
func New(store *findings.Store, enabled bool) http.Handler {
	mux := http.NewServeMux()
	Mount(mux, store, enabled)
	return mux
}

// Mount registers the findings routes on mux. When the security_findings flag
// is off (enabled false) or there is no store, the routes answer 404.
func Mount(mux *http.ServeMux, store *findings.Store, enabled bool) {
	list, get, set := "GET "+Prefix, "GET "+Prefix+"/{id}", "POST "+Prefix+"/{id}/status"
	if !enabled || store == nil {
		for _, p := range []string{list, get, set} {
			mux.HandleFunc(p, func(w http.ResponseWriter, _ *http.Request) { notFound(w, "findings are not enabled") })
		}
		return
	}
	h := &handler{store: store}
	mux.HandleFunc(list, h.list)
	mux.HandleFunc(get, h.get)
	mux.HandleFunc(set, h.setStatus)
}

// ---- wire types ----

type wireFinding struct {
	ID              string                 `json:"id"`
	RuleID          string                 `json:"ruleId"`
	Title           string                 `json:"title"`
	Description     string                 `json:"description"`
	Category        string                 `json:"category"`
	Type            string                 `json:"type"`
	Severity        string                 `json:"severity"`
	Status          string                 `json:"status"`
	AssetID         string                 `json:"assetId"`
	Evidence        []findings.EvidenceRef `json:"evidence"`
	FirstSeen       string                 `json:"firstSeen"`
	LastSeen        string                 `json:"lastSeen"`
	ResolvedAt      string                 `json:"resolvedAt,omitempty"`
	Source          string                 `json:"source"`
	SourceRevision  string                 `json:"sourceRevision,omitempty"`
	RulePackVersion string                 `json:"rulePackVersion,omitempty"`
	Occurrences     int                    `json:"occurrences"`
	RiskScore       *float64               `json:"riskScore,omitempty"`
	Unmapped        bool                   `json:"unmappedSeverity,omitempty"`
	Details         json.RawMessage        `json:"details,omitempty"`
}

type wireEvent struct {
	Seq    int64  `json:"seq"`
	At     string `json:"at"`
	Actor  string `json:"actor"`
	Prev   string `json:"prevStatus,omitempty"`
	New    string `json:"newStatus"`
	Reason string `json:"reason,omitempty"`
}

type wireDetail struct {
	wireFinding
	Events []wireEvent `json:"events"`
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func toWire(f findings.Finding) wireFinding {
	w := wireFinding{ID: f.ID, RuleID: f.RuleID, Title: f.Title, Description: f.Description,
		Category: string(f.Category), Type: string(f.Type), Severity: string(f.Severity), Status: string(f.Status),
		AssetID: f.AssetID, Evidence: f.Evidence, FirstSeen: ts(f.FirstSeen), LastSeen: ts(f.LastSeen),
		Source: f.Source, SourceRevision: f.SourceRevision, RulePackVersion: f.RulePackVersion,
		Occurrences: f.Occurrences, RiskScore: f.RiskScore, Unmapped: f.UnmappedSeverity, Details: f.Details}
	if w.Evidence == nil {
		w.Evidence = []findings.EvidenceRef{}
	}
	if f.ResolvedAt != nil {
		w.ResolvedAt = ts(*f.ResolvedAt)
	}
	return w
}

func toDetail(f findings.Finding, events []findings.StatusEvent) wireDetail {
	d := wireDetail{wireFinding: toWire(f), Events: make([]wireEvent, 0, len(events))}
	for _, e := range events {
		d.Events = append(d.Events, wireEvent{Seq: e.Seq, At: ts(e.At), Actor: e.Actor, Prev: string(e.Prev), New: string(e.New), Reason: e.Reason})
	}
	return d
}

// ---- handlers ----

func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	q, err := Spec.Parse(r.URL.Query())
	if listquery.WriteIfInvalid(w, err) {
		return
	}
	fq, err := listquery.ToFindings(q)
	if listquery.WriteIfInvalid(w, err) {
		return
	}
	ctx, cancel := listquery.Budget(r.Context())
	defer cancel()
	pg, err := h.store.List(ctx, fq)
	out := listquery.Page[wireFinding]{Items: []wireFinding{}}
	switch {
	case err != nil && listquery.Truncated(ctx, err):
		out.Truncated = true
	case err != nil:
		fail(w, err)
		return
	default:
		for _, f := range pg.Items {
			out.Items = append(out.Items, toWire(f))
		}
		if pg.NextCursor != "" {
			out.NextCursor = q.NextCursor(pg.NextCursor)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handler) get(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	f, events, err := h.store.Get(r.Context(), id)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toDetail(f, events))
}

type statusBody struct {
	Status string  `json:"status"`
	Reason string  `json:"reason"`
	Until  *string `json:"until"`
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
		invalid(w, "body", "must be a JSON object {status, reason?, until?}")
		return
	}
	if strings.TrimSpace(body.Status) == "" {
		invalid(w, "status", "required")
		return
	}
	var until *time.Time
	if body.Until != nil {
		t, err := time.Parse(time.RFC3339, *body.Until)
		if err != nil {
			invalid(w, "until", "must be an RFC 3339 timestamp")
			return
		}
		until = &t
	}
	err := h.store.SetStatus(r.Context(), id, findings.Status(body.Status), findings.Actor{ID: actorOf(r.Context())}, body.Reason, until)
	if err != nil {
		fail(w, err)
		return
	}
	f, events, err := h.store.Get(r.Context(), id)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toDetail(f, events))
}

// actorOf is the authenticated local identity, or LocalActor when none is attached.
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
	var ie *findings.InvalidError
	switch {
	case errors.As(err, &ie):
		field := ie.Field
		if field == "expires" {
			field = "until" // the request names it until
		}
		invalid(w, field, ie.Msg)
	case errors.Is(err, findings.ErrNotFound):
		notFound(w, "finding not found")
	case errors.Is(err, findings.ErrTransition):
		writeJSON(w, http.StatusConflict, map[string]string{"_tag": "ConflictError", "message": err.Error(), "code": "transition_not_allowed"})
	case errors.Is(err, findings.ErrAuditWriteFailed):
		writeJSON(w, http.StatusInternalServerError, map[string]string{"_tag": "UnknownError", "message": "status change was not saved: audit write failed", "code": "audit_write_failed"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"_tag": "UnknownError", "message": "internal error"})
	}
}
