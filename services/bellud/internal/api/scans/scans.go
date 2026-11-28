// Package scans serves the experimental scan API under /api/experimental/scans:
// enqueue, list, get, cancel, the scanner list and schedules (Requirements
// 18.1, 18.7, 18.12, 18.13, 20.1). Authentication is applied by the front door
// through the route table, so the handlers never see an unauthenticated request.
package scans

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/api/listquery"
	"github.com/bellu/bellucode/services/bellud/internal/scanners"
)

// Prefix is the route prefix; handlers register full paths, so mount at "/".
const Prefix = "/api/experimental/scans"

const (
	maxBody  = 16 << 10
	maxIDLen = 512 // a target id may be a local path
)

// Deps is what the handlers need. Adapters is called per request because
// adapters are registered after the Manager starts.
type Deps struct {
	Orch     scanners.Orchestrator
	Adapters func() []scanners.Adapter
}

type handler struct{ d Deps }

// New returns a handler serving the routes. See Mount.
func New(d Deps, enabled bool) http.Handler {
	mux := http.NewServeMux()
	Mount(mux, d, enabled)
	return mux
}

// Mount registers the scan routes on mux. When the security_scanners flag is
// off (enabled false) or there is no orchestrator, the routes answer 404.
func Mount(mux *http.ServeMux, d Deps, enabled bool) {
	pats := []string{
		"POST " + Prefix, "GET " + Prefix, "GET " + Prefix + "/scanners",
		"GET " + Prefix + "/{id}", "POST " + Prefix + "/{id}/cancel", "PUT " + Prefix + "/schedules/{id}",
	}
	if !enabled || d.Orch == nil {
		for _, p := range pats {
			mux.HandleFunc(p, func(w http.ResponseWriter, _ *http.Request) { notFound(w, "scans are not enabled") })
		}
		return
	}
	h := &handler{d: d}
	mux.HandleFunc(pats[0], h.enqueue)
	mux.HandleFunc(pats[1], h.list)
	mux.HandleFunc(pats[2], h.scanners)
	mux.HandleFunc(pats[3], h.get)
	mux.HandleFunc(pats[4], h.cancel)
	mux.HandleFunc(pats[5], h.schedule)
}

// ---- wire types ----

type wireJob struct {
	ID              string            `json:"id"`
	Kind            string            `json:"kind"`
	TargetType      string            `json:"targetType"`
	TargetID        string            `json:"targetId"`
	Status          string            `json:"status"`
	Reason          string            `json:"reason,omitempty"`
	QueuedAt        string            `json:"queuedAt"`
	StartedAt       string            `json:"startedAt,omitempty"`
	EndedAt         string            `json:"endedAt,omitempty"`
	Created         int               `json:"created"`
	Updated         int               `json:"updated"`
	Resolved        int               `json:"resolved"`
	DurationMs      *int64            `json:"durationMs,omitempty"`
	ScannerVersions map[string]string `json:"scannerVersions"`
}

type wireScanner struct {
	Name      string            `json:"name"`
	Kind      string            `json:"kind"`
	Version   string            `json:"version"`
	License   string            `json:"license"`
	Libraries map[string]string `json:"libraries,omitempty"`
	LastRun   *wireJob          `json:"lastRun,omitempty"`
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func toWire(j scanners.Job) wireJob {
	w := wireJob{ID: j.ID, Kind: string(j.Kind), TargetType: string(j.Target.Type), TargetID: j.Target.ID,
		Status: string(j.Status), Reason: j.Reason, QueuedAt: ts(j.QueuedAt), Created: j.Created,
		Updated: j.Updated, Resolved: j.Resolved, ScannerVersions: j.ScannerVersions}
	if w.ScannerVersions == nil {
		w.ScannerVersions = map[string]string{}
	}
	if j.StartedAt != nil {
		w.StartedAt = ts(*j.StartedAt)
	}
	if j.EndedAt != nil {
		w.EndedAt = ts(*j.EndedAt)
	}
	if j.Duration != nil {
		ms := j.Duration.Milliseconds()
		w.DurationMs = &ms
	}
	return w
}

// ---- validation ----

var kinds = map[scanners.Kind]bool{
	scanners.KindSBOM: true, scanners.KindVulnerability: true, scanners.KindMisconfiguration: true,
	scanners.KindSecret: true, scanners.KindPosture: true, scanners.KindDataClassification: true, scanners.KindAIInventory: true,
}

var targetTypes = map[scanners.TargetType]bool{
	scanners.TargetRepository: true, scanners.TargetImage: true, scanners.TargetHost: true,
	scanners.TargetCloudAccount: true, scanners.TargetCluster: true,
}

type enqueueBody struct {
	Kind       string `json:"kind"`
	TargetType string `json:"targetType"`
	TargetID   string `json:"targetId"`
}

func decode(w http.ResponseWriter, r *http.Request, v any, shape string) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		invalid(w, "body", "must be a JSON object "+shape)
		return false
	}
	return true
}

// target validates the kind and target fields shared by enqueue and schedule.
func target(w http.ResponseWriter, kind, typ, id string) (scanners.Kind, scanners.Target, bool) {
	k, tt := scanners.Kind(kind), scanners.TargetType(typ)
	switch {
	case !kinds[k]:
		invalid(w, "kind", "must be one of sbom, vulnerability, misconfiguration, secret, posture, data_classification, ai_inventory")
	case !targetTypes[tt]:
		invalid(w, "targetType", "must be one of repository, image, host, cloud_account, cluster")
	case strings.TrimSpace(id) == "" || len(id) > maxIDLen:
		invalid(w, "targetId", "must be 1 to 512 characters")
	default:
		return k, scanners.Target{Type: tt, ID: id}, true
	}
	return "", scanners.Target{}, false
}

// ---- handlers ----

func (h *handler) enqueue(w http.ResponseWriter, r *http.Request) {
	var b enqueueBody
	if !decode(w, r, &b, "{kind, targetType, targetId}") {
		return
	}
	k, t, ok := target(w, b.Kind, b.TargetType, b.TargetID)
	if !ok {
		return
	}
	j, err := h.d.Orch.Enqueue(r.Context(), k, t)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, toWire(j))
}

func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	jq := scanners.JobQuery{Status: scanners.Status(q.Get("status")), Kind: scanners.Kind(q.Get("kind"))}
	if jq.Status != "" {
		switch jq.Status {
		case scanners.StatusQueued, scanners.StatusRunning, scanners.StatusSucceeded, scanners.StatusFailed, scanners.StatusCancelled, scanners.StatusSkippedUnchanged:
		default:
			invalid(w, "status", "must be queued, running, succeeded, failed, cancelled or skipped_unchanged")
			return
		}
	}
	if jq.Kind != "" && !kinds[jq.Kind] {
		invalid(w, "kind", "unknown scan kind")
		return
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			invalid(w, "limit", "must be an integer from 1 to 500")
			return
		}
		jq.Limit = n
	}
	jobs, err := h.d.Orch.List(r.Context(), jq)
	if err != nil {
		fail(w, err)
		return
	}
	out := listquery.Page[wireJob]{Items: make([]wireJob, 0, len(jobs))}
	for _, j := range jobs {
		out.Items = append(out.Items, toWire(j))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handler) get(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	j, err := h.d.Orch.Get(r.Context(), id)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toWire(j))
}

func (h *handler) cancel(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := h.d.Orch.Cancel(r.Context(), id); err != nil {
		fail(w, err)
		return
	}
	j, err := h.d.Orch.Get(r.Context(), id)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toWire(j))
}

func (h *handler) scanners(w http.ResponseWriter, r *http.Request) {
	out := listquery.Page[wireScanner]{Items: []wireScanner{}}
	var as []scanners.Adapter
	if h.d.Adapters != nil {
		as = h.d.Adapters()
	}
	for _, a := range as {
		info := a.Info()
		s := wireScanner{Name: info.Name, Kind: string(a.Kind()), Version: info.Version, License: info.License, Libraries: info.Libraries}
		jobs, err := h.d.Orch.List(r.Context(), scanners.JobQuery{Kind: a.Kind(), Limit: 1})
		if err != nil {
			fail(w, err)
			return
		}
		if len(jobs) > 0 {
			j := toWire(jobs[0])
			s.LastRun = &j
		}
		out.Items = append(out.Items, s)
	}
	writeJSON(w, http.StatusOK, out)
}

// scheduleBody is the PUT body. The path id is the target id; intervalSeconds is
// 900 to 2592000 (15 minutes to 30 days).
type scheduleBody struct {
	Kind            string `json:"kind"`
	TargetType      string `json:"targetType"`
	IntervalSeconds int64  `json:"intervalSeconds"`
	Enabled         bool   `json:"enabled"`
}

type wireSchedule struct {
	Kind            string `json:"kind"`
	TargetType      string `json:"targetType"`
	TargetID        string `json:"targetId"`
	IntervalSeconds int64  `json:"intervalSeconds"`
	Enabled         bool   `json:"enabled"`
}

func (h *handler) schedule(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var b scheduleBody
	if !decode(w, r, &b, "{kind, targetType, intervalSeconds, enabled}") {
		return
	}
	k, t, ok := target(w, b.Kind, b.TargetType, id)
	if !ok {
		return
	}
	if b.IntervalSeconds < 1 || b.IntervalSeconds > int64(scanners.MaxScheduleInterval/time.Second) {
		invalid(w, "intervalSeconds", "must be 900 to 2592000 (15 minutes to 30 days)")
		return
	}
	s := scanners.Schedule{Kind: k, Target: t, Interval: time.Duration(b.IntervalSeconds) * time.Second, Enabled: b.Enabled}
	if err := h.d.Orch.Schedule(r.Context(), s); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, wireSchedule{Kind: b.Kind, TargetType: b.TargetType, TargetID: id, IntervalSeconds: b.IntervalSeconds, Enabled: b.Enabled})
}

func idParam(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if id == "" || len(id) > maxIDLen {
		invalid(w, "id", "must be 1 to 512 characters")
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

func conflict(w http.ResponseWriter, code, msg string) {
	writeJSON(w, http.StatusConflict, map[string]string{"_tag": "ConflictError", "message": msg, "code": code})
}

func fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, scanners.ErrKindNotApplicable):
		listquery.WriteError(w, &listquery.Error{Param: "kind", Msg: "kind_not_applicable: " + err.Error()})
	case errors.Is(err, scanners.ErrTargetNotFound):
		listquery.WriteError(w, &listquery.Error{Param: "targetId", Msg: "target_not_found: " + err.Error()})
	case errors.Is(err, scanners.ErrQueueFull):
		conflict(w, "queue_full", "the queue for this target is full: "+err.Error())
	case errors.Is(err, scanners.ErrInvalidInterval):
		invalid(w, "intervalSeconds", "must be 900 to 2592000 (15 minutes to 30 days)")
	case errors.Is(err, scanners.ErrJobNotFound):
		notFound(w, "scan job not found")
	case errors.Is(err, scanners.ErrNotCancellable):
		conflict(w, "not_cancellable", "job is not queued or running")
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"_tag": "UnknownError", "message": "internal error"})
	}
}
