// Package sse serves Change_Events as a Server-Sent Events stream.
package sse

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/engine"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/subscribe"
)

// DefaultPingInterval is the keep-alive period.
const DefaultPingInterval = 15 * time.Second

// Source is the part of *engine.Core the handler needs.
type Source interface {
	Resolve(ref string) (engine.EntityID, error)
	Subscribe(ctx context.Context, o engine.SubscribeOpts) (*subscribe.Sub[engine.ChangeView], error)
	LocalID(id engine.EntityID) string
}

// Options tune a Handler. Zero values use defaults.
type Options struct {
	// PingInterval is the keep-alive period (default 15 s).
	PingInterval time.Duration
	// NewTicker, when set, replaces time.NewTicker (for tests). It returns
	// the tick channel and a stop function.
	NewTicker func(d time.Duration) (<-chan time.Time, func())
}

// Handler serves GET /api/experimental/graph/subscribe.
type Handler struct {
	src Source
	opt Options
}

// New returns a Handler over src.
func New(src Source, opt Options) *Handler {
	if opt.PingInterval <= 0 {
		opt.PingInterval = DefaultPingInterval
	}
	if opt.NewTicker == nil {
		opt.NewTicker = func(d time.Duration) (<-chan time.Time, func()) {
			t := time.NewTicker(d)
			return t.C, t.Stop
		}
	}
	return &Handler{src: src, opt: opt}
}

type changeJSON struct {
	Seq          uint64 `json:"seq"`
	Kind         string `json:"kind"`
	Subject      string `json:"subject"`
	Entity       string `json:"entity"`
	LocalID      string `json:"local_id"`
	From         string `json:"from"`
	To           string `json:"to"`
	RelationType string `json:"relation_type"`
	ObservedAt   string `json:"observed_at"`
	RecordedAt   string `json:"recorded_at"`
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	q := r.URL.Query()
	var o engine.SubscribeOpts
	kind, subject := q.Get("kind"), q.Get("subject")
	switch engine.ChangeKind(kind) {
	case "", engine.ChangeAdded, engine.ChangeChanged, engine.ChangeRemoved:
	default:
		http.Error(w, "invalid kind", http.StatusBadRequest)
		return
	}
	switch engine.ChangeSubject(subject) {
	case "", engine.SubjectEntity, engine.SubjectRelation:
	default:
		http.Error(w, "invalid subject", http.StatusBadRequest)
		return
	}
	o.Filter.Kind, o.Filter.Subject = engine.ChangeKind(kind), engine.ChangeSubject(subject)
	o.Filter.EntityKind = q.Get("entity_kind")
	if ref := q.Get("entity"); ref != "" {
		id, err := h.src.Resolve(ref)
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, errs.NotFound) {
				status = http.StatusNotFound
			}
			http.Error(w, err.Error(), status)
			return
		}
		o.Filter.Entity = id
	}
	from := r.Header.Get("Last-Event-ID")
	if v := q.Get("from"); v != "" {
		from = v
	}
	if from != "" {
		n, err := strconv.ParseUint(from, 10, 64)
		if err != nil {
			http.Error(w, "invalid resume sequence", http.StatusBadRequest)
			return
		}
		o.From = &n
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	sub, err := h.src.Subscribe(ctx, o)
	if err != nil {
		var gone *engine.GoneError
		switch {
		case errors.As(err, &gone):
			h.start(w, fl)
			writeError(w, fl, fmt.Sprintf(`{"code":"graph_gone","oldest_seq":%d}`, gone.Oldest))
		case errors.Is(err, errs.Validation):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case errors.Is(err, errs.Unavailable):
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
		default:
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return
	}
	defer sub.Close()
	h.start(w, fl)

	tick, stop := h.opt.NewTicker(h.opt.PingInterval)
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		case cv, open := <-sub.C():
			if !open {
				h.finish(w, fl, sub)
				return
			}
			if err := h.writeChange(w, fl, cv); err != nil {
				return
			}
		}
	}
}

func (h *Handler) start(w http.ResponseWriter, fl http.Flusher) {
	hd := w.Header()
	hd.Set("Content-Type", "text/event-stream")
	hd.Set("Cache-Control", "no-store")
	hd.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fl.Flush()
}

func (h *Handler) finish(w http.ResponseWriter, fl http.Flusher, sub *subscribe.Sub[engine.ChangeView]) {
	err := sub.Err()
	var ov *subscribe.OverflowError
	var gone *engine.GoneError
	switch {
	case errors.As(err, &ov):
		writeError(w, fl, fmt.Sprintf(`{"code":"graph_overflow","resume_from":%d}`, ov.LastSeq))
	case errors.As(err, &gone):
		writeError(w, fl, fmt.Sprintf(`{"code":"graph_gone","oldest_seq":%d}`, gone.Oldest))
	case err != nil:
		writeError(w, fl, `{"code":"graph_internal"}`)
	}
}

func writeError(w http.ResponseWriter, fl http.Flusher, data string) {
	fmt.Fprintf(w, "event: error\ndata: %s\n\n", data)
	fl.Flush()
}

func (h *Handler) writeChange(w http.ResponseWriter, fl http.Flusher, cv engine.ChangeView) error {
	j := changeJSON{
		Seq: cv.Seq, Kind: string(cv.Kind), Subject: string(cv.Subject),
		Entity: cv.Entity, From: cv.From, To: cv.To, RelationType: cv.RelationType,
		ObservedAt: cv.ObservedAt.UTC().Format(time.RFC3339Nano),
		RecordedAt: cv.RecordedAt.UTC().Format(time.RFC3339Nano),
	}
	if cv.Subject == engine.SubjectEntity && cv.Entity != "" {
		j.LocalID = h.src.LocalID(cv.Entity)
	}
	b, err := json.Marshal(j)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "id: %d\nevent: change\ndata: %s\n\n", cv.Seq, b); err != nil {
		return err
	}
	fl.Flush()
	return nil
}
