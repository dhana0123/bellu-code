package graph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	intelsync "github.com/bellu/bellucode/services/bellud/internal/intel/sync"
	"github.com/bellu/bellucode/services/bellud/internal/lens"
	"github.com/bellu/bellucode/services/bellud/internal/overlay"
)

// Option configures optional routes of the graph API handler.
type Option func(*handler)

// WithIntel serves GET /intel/status from fn. fn must not block.
func WithIntel(fn func() intelsync.Status) Option {
	return func(h *handler) { h.intel = fn }
}

// WithLens serves GET /lenses and GET /slice from svc.
func WithLens(svc *lens.Service) Option {
	return func(h *handler) { h.lens = svc }
}

// WithOverlay serves GET /overlay from hub.
func WithOverlay(hub *overlay.Hub) Option {
	return func(h *handler) { h.overlay = hub }
}

// sliceTimeout bounds one slice build.
const sliceTimeout = 5 * time.Second

// lenses answers the lens catalog.
func (h *handler) lenses(w http.ResponseWriter, _ *http.Request) {
	if h.lens == nil {
		unavailable(w, "graph engine unavailable: lenses not configured")
		return
	}
	writeJSON(w, http.StatusOK, h.lens.Catalog())
}

// intParam parses an optional positive integer query parameter.
func intParam(w http.ResponseWriter, r *http.Request, name string, def int) (int, bool) {
	s := r.URL.Query().Get(name)
	if s == "" {
		return def, true
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		invalid(w, name, name+" must be a positive integer")
		return 0, false
	}
	return n, true
}

// slice answers one Lens_Slice. depth is clamped to lens.MaxDepth and limit
// to the HTTP node budget; the edge budget is fixed.
func (h *handler) slice(w http.ResponseWriter, r *http.Request) {
	if h.lens == nil {
		unavailable(w, "graph engine unavailable: lenses not configured")
		return
	}
	depth, ok := intParam(w, r, "depth", lens.DefaultDepth)
	if !ok {
		return
	}
	limit, ok := intParam(w, r, "limit", lens.DefaultMaxNodes)
	if !ok {
		return
	}
	q := r.URL.Query()
	ctx, cancel := context.WithTimeout(r.Context(), sliceTimeout)
	defer cancel()
	s, err := h.lens.Slice(ctx, q.Get("lens"), lens.Params{
		Entity:   q.Get("entity"),
		Target:   q.Get("target"),
		Depth:    min(depth, lens.MaxDepth),
		MaxNodes: min(limit, lens.DefaultMaxNodes),
		MaxEdges: lens.DefaultMaxEdges,
	})
	var unknown lens.ErrUnknownLens
	var bad lens.ErrInvalidParam
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, s)
	case errors.As(err, &unknown):
		notFound(w, err.Error())
	case errors.As(err, &bad):
		invalid(w, bad.Field, err.Error())
	case errors.Is(err, lens.ErrUnavailable), errors.Is(err, context.DeadlineExceeded):
		unavailable(w, "graph engine unavailable: "+err.Error())
	default:
		fail(w, err)
	}
}

type wireIntelStatus struct {
	State        string `json:"state"`
	Version      string `json:"version"`
	Records      int    `json:"records"`
	LastSyncedAt string `json:"last_synced_at"`
	LastError    string `json:"last_error"`
}

// intelStatus answers the intel sync state. Without an intel stack it reports
// not_configured. Unset timestamps are empty strings.
func (h *handler) intelStatus(w http.ResponseWriter, _ *http.Request) {
	out := wireIntelStatus{State: intelsync.StateNotConfigured}
	if h.intel != nil {
		s := h.intel()
		out = wireIntelStatus{State: s.State, Version: s.Version, Records: s.Records, LastError: s.LastError}
		if !s.LastSyncedAt.IsZero() {
			out.LastSyncedAt = s.LastSyncedAt.UTC().Format(time.RFC3339Nano)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// overlayKeepalive is the interval between SSE keepalive comments.
const overlayKeepalive = 15 * time.Second

// overlayStream serves overlay events as server-sent events. With ?replay=demo
// it replays the scripted demo for this connection only; otherwise it relays
// the hub. Events carry no history: a new connection sees only later events.
func (h *handler) overlayStream(w http.ResponseWriter, r *http.Request) {
	var src <-chan overlay.Event
	if script := r.URL.Query().Get("replay"); script != "" {
		if script != overlay.DemoScript {
			invalid(w, "replay", fmt.Sprintf("unknown replay script %q", script))
			return
		}
		if h.lens == nil {
			unavailable(w, "graph engine unavailable: lenses not configured")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), sliceTimeout)
		s, err := h.lens.Slice(ctx, lens.DefaultLens, lens.Params{
			Depth: lens.DefaultDepth, MaxNodes: lens.DefaultMaxNodes, MaxEdges: lens.DefaultMaxEdges,
		})
		cancel()
		if err != nil {
			if errors.Is(err, lens.ErrUnavailable) || errors.Is(err, context.DeadlineExceeded) {
				unavailable(w, "graph engine unavailable: "+err.Error())
			} else {
				fail(w, err)
			}
			return
		}
		ch, err := overlay.Replay(r.Context(), script, demoScript(s))
		if err != nil {
			fail(w, err)
			return
		}
		src = ch
	} else {
		if h.overlay == nil {
			unavailable(w, "overlay unavailable: hub not configured")
			return
		}
		ch, cancel := h.overlay.Subscribe()
		defer cancel()
		src = ch
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		fail(w, errors.New("streaming unsupported"))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fl.Flush()
	tick := time.NewTicker(overlayKeepalive)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
			fmt.Fprint(w, ":keepalive\n\n")
			fl.Flush()
		case e, open := <-src:
			if !open {
				if r.URL.Query().Get("replay") != "" {
					fmt.Fprint(w, ":done\n\n")
					fl.Flush()
				}
				return
			}
			data, err := overlay.Encode(e)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "id: %d\nevent: overlay\ndata: %s\n\n", e.Seq, data)
			fl.Flush()
		}
	}
}

// demoScript builds the scripted replay from s: focus the highest-risk
// vulnerability (else the first node), walk the shortest chain of slice edges
// to an internet-exposed node, then propose upgrading the vulnerable package.
// An empty slice gives no events.
func demoScript(s lens.Slice) []overlay.Event {
	if len(s.Nodes) == 0 {
		return nil
	}
	byID := make(map[string]lens.Node, len(s.Nodes))
	adj := map[string][]string{}
	for _, n := range s.Nodes {
		byID[n.ID] = n
	}
	for _, e := range s.Edges {
		adj[e.From] = append(adj[e.From], e.To)
		adj[e.To] = append(adj[e.To], e.From)
	}
	start := s.Nodes[0]
	best := -1.0
	for _, n := range s.Nodes {
		if n.Kind == "vulnerability" && n.Risk != nil && n.Risk.Score > best {
			start, best = n, n.Risk.Score
		}
	}
	label := func(n lens.Node) string {
		if n.Label != "" {
			return n.Label
		}
		return n.ID
	}
	out := []overlay.Event{{
		Entity: start.ID, Action: overlay.ActionFocusNode,
		Explanation: fmt.Sprintf("Starting at %s, the highest-risk finding in this slice.", label(start)),
	}}
	prev := map[string]string{start.ID: ""}
	queue := []string{start.ID}
	exposed := ""
	for len(queue) > 0 && exposed == "" {
		id := queue[0]
		queue = queue[1:]
		for _, next := range adj[id] {
			if _, seen := prev[next]; seen {
				continue
			}
			prev[next] = id
			if byID[next].Attrs["internet_exposed"] == "true" {
				exposed = next
				break
			}
			queue = append(queue, next)
		}
	}
	if exposed != "" {
		var path []string
		for id := exposed; id != ""; id = prev[id] {
			path = append([]string{id}, path...)
		}
		out = append(out, overlay.Event{
			Entity: exposed, Action: overlay.ActionWalkPath, Path: path,
			Explanation: fmt.Sprintf("%s connects to %s, which is internet exposed.", label(start), label(byID[exposed])),
		})
	}
	if start.Kind == "vulnerability" {
		for _, id := range adj[start.ID] {
			if pkg := byID[id]; pkg.Kind == "package" {
				msg := fmt.Sprintf("Upgrade %s to fix %s.", label(pkg), label(start))
				if fixed := start.Attrs["fixed_in"]; fixed != "" {
					msg = fmt.Sprintf("Upgrade %s to %s to fix %s.", label(pkg), fixed, label(start))
				}
				out = append(out, overlay.Event{Entity: pkg.ID, Action: overlay.ActionProposedChange, Explanation: msg})
				break
			}
		}
	}
	return out
}
