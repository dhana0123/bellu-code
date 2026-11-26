// Package runtime serves the experimental runtime API under
// /api/experimental/runtime: GET /runtime/status, GET /runtime/events and
// POST /runtime/ingest (Requirements 15.6, 15.13, 20.1). Ingest accepts only
// requests carrying a verified mTLS client certificate; local sensors use the
// Unix socket instead. Authentication is applied by the front door.
package runtime

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/bellu/bellucode/services/bellud/internal/api/listquery"
	"github.com/bellu/bellucode/services/bellud/internal/runtimeevents"
	"github.com/bellu/bellucode/services/bellud/internal/runtimeevents/wire"
)

// Prefix is the route prefix; handlers register full paths, so mount at "/".
const Prefix = "/api/experimental/runtime"

const maxIngestBody = wire.MaxFrameBytes

// Source is the part of *runtimeevents.Server the handlers use.
type Source interface {
	Events(ctx context.Context, typ string, before int64, limit int) ([]runtimeevents.Stored, error)
	Sensors(ctx context.Context) ([]runtimeevents.Sensor, error)
	Ingest(ctx context.Context, node string, e wire.Event) error
	Rejected() int64
}

// Spec is the list query contract of GET /runtime/events.
var Spec = listquery.Spec{
	Filters: []string{listquery.Type},
	Domains: map[string][]string{listquery.Type: {
		wire.TypeProcessExec, wire.TypeNetworkConnect, wire.TypeFileWrite,
		wire.TypeShellSpawn, wire.TypePrivilegeChange, wire.TypeContainerEscape,
	}},
}

// Status is the body of GET /runtime/status.
type Status struct {
	Sensors       []runtimeevents.Sensor `json:"sensors"`
	RejectedTotal int64                  `json:"rejectedTotal"`
}

// Mount registers the runtime routes on mux. When security_runtime is off
// (enabled false) or there is no source, the routes answer 404.
func Mount(mux *http.ServeMux, src Source, enabled bool) {
	status, events, ingest := "GET "+Prefix+"/status", "GET "+Prefix+"/events", "POST "+Prefix+"/ingest"
	if !enabled || src == nil {
		for _, p := range []string{status, events, ingest} {
			mux.HandleFunc(p, func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusNotFound, map[string]string{"_tag": "NotFoundError", "message": "runtime is not enabled"})
			})
		}
		return
	}
	h := &handler{src: src}
	mux.HandleFunc(status, h.status)
	mux.HandleFunc(events, h.events)
	mux.HandleFunc(ingest, h.ingest)
}

type handler struct{ src Source }

func internalError(w http.ResponseWriter) {
	writeJSON(w, http.StatusInternalServerError, map[string]string{"_tag": "UnknownError", "message": "internal error"})
}

func (h *handler) status(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := listquery.Budget(r.Context())
	defer cancel()
	s, err := h.src.Sensors(ctx)
	if err != nil {
		internalError(w)
		return
	}
	writeJSON(w, http.StatusOK, Status{Sensors: s, RejectedTotal: h.src.Rejected()})
}

func (h *handler) events(w http.ResponseWriter, r *http.Request) {
	q, err := Spec.Parse(r.URL.Query())
	if listquery.WriteIfInvalid(w, err) {
		return
	}
	var before int64
	if q.Position != "" {
		if before, err = strconv.ParseInt(q.Position, 10, 64); err != nil || before <= 0 {
			listquery.WriteError(w, &listquery.Error{Param: "cursor", Msg: "malformed cursor"})
			return
		}
	}
	typ := ""
	if len(q.Types) > 0 {
		typ = q.Types[0]
	}
	ctx, cancel := listquery.Budget(r.Context())
	defer cancel()
	items, err := h.src.Events(ctx, typ, before, q.Limit+1)
	out := listquery.Page[runtimeevents.Stored]{Items: []runtimeevents.Stored{}}
	switch {
	case err != nil && listquery.Truncated(ctx, err):
		out.Truncated = true
	case err != nil:
		internalError(w)
		return
	default:
		if len(items) > q.Limit {
			items = items[:q.Limit]
			out.NextCursor = q.NextCursor(strconv.FormatInt(items[len(items)-1].Seq, 10))
		}
		out.Items = items
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handler) ingest(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		writeJSON(w, http.StatusForbidden, map[string]string{"_tag": "ForbiddenError", "message": "ingest requires a verified client certificate"})
		return
	}
	var e wire.Event
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxIngestBody)).Decode(&e); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"_tag": "BadRequestError", "message": "invalid event"})
		return
	}
	node := r.TLS.PeerCertificates[0].Subject.CommonName
	if err := h.src.Ingest(r.Context(), node, e); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"_tag": "BadRequestError", "message": "event rejected"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
