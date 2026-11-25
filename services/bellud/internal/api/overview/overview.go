// Package overview serves the experimental overview API under
// /api/experimental/overview: all nine category summaries in one call, with an
// ETag from the summary revision so the app can poll cheaply (Requirements
// 1.5, 20.1). Authentication is applied by the front door through the route
// table before a request reaches these handlers (20.12).
package overview

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/overview"
)

// Prefix is the route prefix; handlers register full paths, so mount at "/".
const Prefix = "/api/experimental/overview"

// CategoriesPath is the full path of the categories route.
const CategoriesPath = Prefix + "/categories"

// retryAfterSeconds is the retry hint sent while the service has not started.
const retryAfterSeconds = "2"

// Source is the part of overview.Service the handler uses.
type Source interface {
	Summaries(ctx context.Context) (overview.Summaries, error)
}

type handler struct{ src Source }

// New returns a handler serving the overview routes. See Mount.
func New(src Source, enabled bool) http.Handler {
	mux := http.NewServeMux()
	Mount(mux, src, enabled)
	return mux
}

// Mount registers the overview routes on mux. When the security_overview flag
// is off (enabled false) or there is no service, the route answers 404.
func Mount(mux *http.ServeMux, src Source, enabled bool) {
	pattern := "GET " + CategoriesPath
	if !enabled || src == nil {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusNotFound, map[string]string{"_tag": "NotFoundError", "message": "overview is not enabled"})
		})
		return
	}
	mux.HandleFunc(pattern, (&handler{src: src}).categories)
}

// ---- wire types ----

type wireIssue struct {
	ID        string  `json:"id"`
	Title     string  `json:"title"`
	Severity  string  `json:"severity"`
	RiskScore float64 `json:"riskScore"`
}

type wireEmptyState struct {
	MissingSource string `json:"missingSource"`
	SetupLink     string `json:"setupLink"`
}

type wireCategory struct {
	Category    string          `json:"category"`
	Title       string          `json:"title"`
	Subtitle    string          `json:"subtitle"`
	EntityCount int             `json:"entityCount"`
	Severity    map[string]int  `json:"severity"`
	TopIssues   []wireIssue     `json:"topIssues"`
	EmptyState  *wireEmptyState `json:"emptyState,omitempty"`
	Kinds       map[string]int  `json:"kinds"`
}

type wireSummaries struct {
	Revision   uint64         `json:"revision"`
	Categories []wireCategory `json:"categories"`
}

func toWire(s overview.Summaries) wireSummaries {
	out := wireSummaries{Revision: s.Revision, Categories: make([]wireCategory, 0, len(s.Categories))}
	for _, c := range s.Categories {
		w := wireCategory{Category: string(c.Category), Title: c.Title, Subtitle: c.Subtitle, EntityCount: c.EntityCount,
			Severity: make(map[string]int, len(findings.AllSeverities)), TopIssues: make([]wireIssue, 0, len(c.TopIssues)),
			Kinds: c.Extra}
		for _, v := range findings.AllSeverities {
			w.Severity[string(v)] = c.Severity[v]
		}
		if w.Kinds == nil {
			w.Kinds = map[string]int{}
		}
		for _, i := range c.TopIssues {
			w.TopIssues = append(w.TopIssues, wireIssue{ID: i.ID, Title: i.Title, Severity: string(i.Severity), RiskScore: i.RiskScore})
		}
		if c.EmptyState != nil {
			w.EmptyState = &wireEmptyState{MissingSource: c.EmptyState.MissingSource, SetupLink: c.EmptyState.SetupLink}
		}
		out.Categories = append(out.Categories, w)
	}
	return out
}

// ---- handler ----

func (h *handler) categories(w http.ResponseWriter, r *http.Request) {
	s, err := h.src.Summaries(r.Context())
	if err != nil {
		fail(w, err)
		return
	}
	etag := ETag(s.Revision)
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache")
	if matches(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeJSON(w, http.StatusOK, toWire(s))
}

// ETag is the weak entity tag of a summary revision.
func ETag(revision uint64) string { return `W/"rev-` + strconv.FormatUint(revision, 10) + `"` }

// matches reports whether an If-None-Match header lists etag, comparing weakly
// (RFC 9110 8.8.3.2) or contains "*".
func matches(header, etag string) bool {
	want := strings.TrimPrefix(etag, "W/")
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "*" || strings.TrimPrefix(part, "W/") == want {
			return true
		}
	}
	return false
}

// ---- responses ----

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, err error) {
	if errors.Is(err, overview.ErrNotStarted) {
		w.Header().Set("Retry-After", retryAfterSeconds)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"_tag": "ServiceUnavailableError", "message": "overview is starting; retry shortly", "service": "overview", "code": "overview_starting"})
		return
	}
	writeJSON(w, http.StatusInternalServerError, map[string]string{"_tag": "UnknownError", "message": "internal error"})
}
