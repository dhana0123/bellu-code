// Package graph serves the experimental graph read API under
// /api/experimental/graph. Wire shapes follow packages/schema/src/graph.ts and
// packages/protocol/src/groups/experimental-graph.ts.
package graph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/tschild"
)

// Prefix is the route prefix; the handler registers full paths, so mount it at "/".
const Prefix = "/api/experimental/graph"

// ChildState is the wire value of Graph.ChildState.
type ChildState string

const (
	ChildStarting   ChildState = "starting"
	ChildReady      ChildState = "ready"
	ChildRestarting ChildState = "restarting"
	ChildDegraded   ChildState = "degraded"
	ChildStopped    ChildState = "stopped"
)

// ChildStateOf maps the supervisor state to its wire value.
func ChildStateOf(s tschild.State) ChildState {
	switch s {
	case tschild.StateStarting:
		return ChildStarting
	case tschild.StateRunning:
		return ChildReady
	case tschild.StateDegraded:
		return ChildDegraded
	default:
		return ChildStopped
	}
}

var idPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*:[0-9a-f]{32}$`)

type handler struct {
	engine graph.Engine
	child  func() ChildState
}

// New returns the graph API handler. child may be nil (reported as stopped);
// it must not block. engine may be nil (reported as disabled, routes answer 503).
func New(engine graph.Engine, child func() ChildState) http.Handler {
	h := &handler{engine: engine, child: child}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+Prefix+"/entities", h.find)
	mux.HandleFunc("GET "+Prefix+"/entities/{id}", h.entity)
	mux.HandleFunc("GET "+Prefix+"/entities/{id}/neighbors", h.neighbors)
	mux.HandleFunc("GET "+Prefix+"/entities/{id}/history", h.history)
	mux.HandleFunc("GET "+Prefix+"/changes", h.changes)
	mux.HandleFunc("GET "+Prefix+"/diff", h.diff)
	mux.HandleFunc("GET "+Prefix+"/schema", h.schema)
	mux.HandleFunc("GET "+Prefix+"/status", h.status)
	return mux
}

// ---- wire types ----

type wireEntity struct {
	ID         string         `json:"id"`
	Type       string         `json:"type"`
	Label      string         `json:"label,omitempty"`
	Attributes map[string]any `json:"attributes"`
	ObservedAt string         `json:"observed_at"`
	RecordedAt string         `json:"recorded_at"`
}

type wireEdge struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Type      string `json:"type"`
	Direction string `json:"direction"`
	Hops      int    `json:"hops"`
}

type wireChange struct {
	Kind         string `json:"kind"`
	Subject      string `json:"subject"`
	Entity       string `json:"entity,omitempty"`
	From         string `json:"from,omitempty"`
	To           string `json:"to,omitempty"`
	RelationType string `json:"relation_type,omitempty"`
	ObservedAt   string `json:"observed_at"`
	RecordedAt   string `json:"recorded_at"`
}

type page[T any] struct {
	Items     []T  `json:"items"`
	Total     int  `json:"total"`
	Truncated bool `json:"truncated"`
	Limit     int  `json:"limit"`
}

type wireDiff struct {
	From      string       `json:"from"`
	To        string       `json:"to"`
	Added     []wireEntity `json:"added"`
	Changed   []wireEntity `json:"changed"`
	Removed   []string     `json:"removed"`
	Truncated bool         `json:"truncated"`
}

type schemaType struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Count       int    `json:"count"`
}

type wireSchema struct {
	EntityTypes   []schemaType `json:"entity_types"`
	RelationTypes []schemaType `json:"relation_types"`
}

type wireStatus struct {
	Engine  string `json:"engine"`
	TSChild string `json:"ts_child"`
	Detail  string `json:"detail,omitempty"`
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func toEntity(e graph.Entity) wireEntity {
	attrs := e.Attributes
	if attrs == nil {
		attrs = map[string]any{}
	}
	return wireEntity{ID: string(e.ID), Type: e.Type, Label: e.Label, Attributes: attrs, ObservedAt: ts(e.ObservedAt), RecordedAt: ts(e.RecordedAt)}
}

func toChange(c graph.Change) wireChange {
	return wireChange{
		Kind: string(c.Kind), Subject: string(c.Subject), Entity: string(c.Entity),
		From: string(c.From), To: string(c.To), RelationType: c.RelationType,
		ObservedAt: ts(c.ObservedAt), RecordedAt: ts(c.RecordedAt),
	}
}

// ---- responses ----

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func invalid(w http.ResponseWriter, field, msg string) {
	body := map[string]string{"_tag": "InvalidRequestError", "message": msg, "kind": "validation"}
	if field != "" {
		body["field"] = field
	}
	writeJSON(w, http.StatusBadRequest, body)
}

func unavailable(w http.ResponseWriter, msg string) {
	// _tag/message/service follow ServiceUnavailableError; code is the stable
	// graph_unavailable marker required by Requirement 16.9.
	writeJSON(w, http.StatusServiceUnavailable, map[string]string{
		"_tag": "ServiceUnavailableError", "message": msg, "service": "graph", "code": graph.CodeUnavailable,
	})
}

func notFound(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusNotFound, map[string]string{"_tag": "NotFoundError", "message": msg})
}

func fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, graph.ErrUnavailable):
		unavailable(w, err.Error())
	case errors.Is(err, graph.ErrNotFound):
		notFound(w, err.Error())
	case errors.Is(err, graph.ErrValidation):
		invalid(w, "", err.Error())
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"_tag": "UnknownError", "message": "internal error"})
	}
}

// query returns the engine query surface, or writes 503.
func (h *handler) query(w http.ResponseWriter) (graph.Query, bool) {
	if h.engine == nil {
		unavailable(w, "graph engine unavailable: disabled")
		return nil, false
	}
	if st := graph.StateOf(h.engine); st.Kind != graph.StateReady {
		unavailable(w, "graph engine unavailable: "+string(st.Kind)+reason(st.Reason))
		return nil, false
	}
	return h.engine.Query(), true
}

func reason(r string) string {
	if r == "" {
		return ""
	}
	return ": " + r
}

// ---- parameter parsing ----

// limitParam parses limit: absent is 100, above 1000 is clamped (Req 16.7),
// non-integers and values below 1 are rejected.
func limitParam(w http.ResponseWriter, r *http.Request) (int, bool) {
	s := r.URL.Query().Get("limit")
	if s == "" {
		return graph.DefaultPageSize, true
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		invalid(w, "limit", "limit must be an integer between 1 and 1000")
		return 0, false
	}
	return min(n, graph.MaxPageSize), true
}

func timeParam(w http.ResponseWriter, r *http.Request, name string) (time.Time, bool, bool) {
	s := r.URL.Query().Get(name)
	if s == "" {
		return time.Time{}, false, true
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		invalid(w, name, name+" must be an RFC 3339 timestamp")
		return time.Time{}, false, false
	}
	return t, true, true
}

func (h *handler) idParam(w http.ResponseWriter, r *http.Request) (graph.EntityID, bool) {
	id := r.PathValue("id")
	if !idPattern.MatchString(id) {
		invalid(w, "id", "malformed entity id")
		return "", false
	}
	return graph.EntityID(id), true
}

func rangeParams(w http.ResponseWriter, r *http.Request) (graph.TimeRange, bool) {
	var tr graph.TimeRange
	since, hasSince, ok := timeParam(w, r, "since")
	if !ok {
		return tr, false
	}
	until, hasUntil, ok := timeParam(w, r, "until")
	if !ok {
		return tr, false
	}
	if hasSince && hasUntil && until.Before(since) {
		invalid(w, "until", "until is before since")
		return tr, false
	}
	if hasSince {
		tr.From = since
	}
	if hasUntil {
		tr.To = until
	}
	return tr, true
}

// collect pages through every result of fetch (1000 per page).
func collect[T any](fetch func(graph.Paging) (graph.Page[T], error)) ([]T, error) {
	var all []T
	p := graph.Paging{PageSize: graph.MaxPageSize}
	for {
		pg, err := fetch(p)
		if err != nil {
			return nil, err
		}
		all = append(all, pg.Items...)
		if !pg.Truncated || pg.NextCursor == "" {
			return all, nil
		}
		p.Cursor = pg.NextCursor
	}
}

func slicePage[T any, W any](all []T, limit int, conv func(T) W) page[W] {
	pg := page[W]{Items: []W{}, Total: len(all), Limit: limit}
	n := min(limit, len(all))
	for _, it := range all[:n] {
		pg.Items = append(pg.Items, conv(it))
	}
	pg.Truncated = n < len(all)
	return pg
}

// ---- handlers ----

func (h *handler) find(w http.ResponseWriter, r *http.Request) {
	q, ok := h.query(w)
	if !ok {
		return
	}
	limit, ok := limitParam(w, r)
	if !ok {
		return
	}
	if _, _, ok := timeParam(w, r, "as_of"); !ok {
		return
	}
	typ := r.URL.Query().Get("type")
	match := strings.ToLower(r.URL.Query().Get("match"))
	if match == "" {
		pg, err := q.Find(r.Context(), graph.FindQuery{Type: typ, Paging: graph.Paging{PageSize: limit}})
		if err != nil {
			fail(w, err)
			return
		}
		out := page[wireEntity]{Items: []wireEntity{}, Total: pg.Total, Truncated: pg.Truncated, Limit: pg.Limit}
		for _, e := range pg.Items {
			out.Items = append(out.Items, toEntity(e))
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	all, err := collect(func(p graph.Paging) (graph.Page[graph.Entity], error) {
		return q.Find(r.Context(), graph.FindQuery{Type: typ, Paging: p})
	})
	if err != nil {
		fail(w, err)
		return
	}
	var hits []graph.Entity
	for _, e := range all {
		if matches(e, match) {
			hits = append(hits, e)
		}
	}
	writeJSON(w, http.StatusOK, slicePage(hits, limit, toEntity))
}

// matches is a case-insensitive substring match over id, label and attribute values.
func matches(e graph.Entity, needle string) bool {
	if strings.Contains(strings.ToLower(string(e.ID)), needle) || strings.Contains(strings.ToLower(e.Label), needle) {
		return true
	}
	for _, v := range e.Attributes {
		if strings.Contains(strings.ToLower(fmt.Sprint(v)), needle) {
			return true
		}
	}
	return false
}

func (h *handler) entity(w http.ResponseWriter, r *http.Request) {
	q, ok := h.query(w)
	if !ok {
		return
	}
	id, ok := h.idParam(w, r)
	if !ok {
		return
	}
	asOf, has, ok := timeParam(w, r, "as_of")
	if !ok {
		return
	}
	var at *time.Time
	if has {
		at = &asOf
	}
	e, err := q.Entity(r.Context(), id, at)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toEntity(e))
}

func (h *handler) neighbors(w http.ResponseWriter, r *http.Request) {
	q, ok := h.query(w)
	if !ok {
		return
	}
	id, ok := h.idParam(w, r)
	if !ok {
		return
	}
	limit, ok := limitParam(w, r)
	if !ok {
		return
	}
	if _, _, ok := timeParam(w, r, "as_of"); !ok {
		return
	}
	dir := r.URL.Query().Get("direction")
	switch dir {
	case "", graph.DirOut, graph.DirIn, graph.DirBoth:
	default:
		invalid(w, "direction", "direction must be out, in or both")
		return
	}
	pg, err := q.Neighbors(r.Context(), id, graph.NeighborOpts{Direction: dir, RelationType: r.URL.Query().Get("type"), Paging: graph.Paging{PageSize: limit}})
	if err != nil {
		fail(w, err)
		return
	}
	out := page[wireEdge]{Items: []wireEdge{}, Total: pg.Total, Truncated: pg.Truncated, Limit: pg.Limit}
	for _, e := range pg.Items {
		out.Items = append(out.Items, wireEdge{From: string(e.From), To: string(e.To), Type: e.Type, Direction: e.Direction, Hops: e.Hops})
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handler) history(w http.ResponseWriter, r *http.Request) {
	q, ok := h.query(w)
	if !ok {
		return
	}
	id, ok := h.idParam(w, r)
	if !ok {
		return
	}
	limit, ok := limitParam(w, r)
	if !ok {
		return
	}
	tr, ok := rangeParams(w, r)
	if !ok {
		return
	}
	pg, err := q.History(r.Context(), id, tr, graph.Paging{PageSize: limit})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, changePage(pg))
}

func changePage(pg graph.Page[graph.Change]) page[wireChange] {
	out := page[wireChange]{Items: []wireChange{}, Total: pg.Total, Truncated: pg.Truncated, Limit: pg.Limit}
	for _, c := range pg.Items {
		out.Items = append(out.Items, toChange(c))
	}
	return out
}

func (h *handler) changes(w http.ResponseWriter, r *http.Request) {
	q, ok := h.query(w)
	if !ok {
		return
	}
	limit, ok := limitParam(w, r)
	if !ok {
		return
	}
	tr, ok := rangeParams(w, r)
	if !ok {
		return
	}
	typ := r.URL.Query().Get("type")
	if typ == "" {
		pg, err := q.Changes(r.Context(), tr, graph.ChangeFilter{Paging: graph.Paging{PageSize: limit}})
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, changePage(pg))
		return
	}
	// type filters by relation type, or by the type of the (currently live)
	// subject entity.
	all, err := collect(func(p graph.Paging) (graph.Page[graph.Change], error) {
		return q.Changes(r.Context(), tr, graph.ChangeFilter{Paging: p})
	})
	if err != nil {
		fail(w, err)
		return
	}
	types, err := entityTypes(r.Context(), q)
	if err != nil {
		fail(w, err)
		return
	}
	var hits []graph.Change
	for _, c := range all {
		if c.Subject == graph.SubjectRelation && c.RelationType == typ || c.Subject == graph.SubjectEntity && types[c.Entity] == typ {
			hits = append(hits, c)
		}
	}
	writeJSON(w, http.StatusOK, slicePage(hits, limit, toChange))
}

func entityTypes(ctx context.Context, q graph.Query) (map[graph.EntityID]string, error) {
	all, err := collect(func(p graph.Paging) (graph.Page[graph.Entity], error) {
		return q.Find(ctx, graph.FindQuery{Paging: p})
	})
	if err != nil {
		return nil, err
	}
	m := make(map[graph.EntityID]string, len(all))
	for _, e := range all {
		m[e.ID] = e.Type
	}
	return m, nil
}

func (h *handler) diff(w http.ResponseWriter, r *http.Request) {
	q, ok := h.query(w)
	if !ok {
		return
	}
	limit, ok := limitParam(w, r)
	if !ok {
		return
	}
	from, has, ok := timeParam(w, r, "from")
	if !ok {
		return
	}
	if !has {
		invalid(w, "from", "from is required")
		return
	}
	to, has, ok := timeParam(w, r, "to")
	if !ok {
		return
	}
	if !has {
		invalid(w, "to", "to is required")
		return
	}
	if to.Before(from) {
		invalid(w, "to", "to is before from")
		return
	}
	d, err := q.Diff(r.Context(), from, to)
	if err != nil {
		fail(w, err)
		return
	}
	typ := r.URL.Query().Get("type")
	out := wireDiff{From: ts(d.From), To: ts(d.To), Added: []wireEntity{}, Changed: []wireEntity{}, Removed: []string{}, Truncated: d.Truncated}
	conv := func(src []graph.Entity, dst *[]wireEntity) {
		var kept []graph.Entity
		for _, e := range src {
			if typ == "" || e.Type == typ {
				kept = append(kept, e)
			}
		}
		if len(kept) > limit {
			kept = kept[:limit]
			out.Truncated = true
		}
		for _, e := range kept {
			*dst = append(*dst, toEntity(e))
		}
	}
	conv(d.Added, &out.Added)
	conv(d.Changed, &out.Changed)
	// Removed entities are bare ids; the type filter cannot apply to them.
	for i, id := range d.Removed {
		if i >= limit {
			out.Truncated = true
			break
		}
		out.Removed = append(out.Removed, string(id))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handler) schema(w http.ResponseWriter, r *http.Request) {
	q, ok := h.query(w)
	if !ok {
		return
	}
	ents, err := collect(func(p graph.Paging) (graph.Page[graph.Entity], error) {
		return q.Find(r.Context(), graph.FindQuery{Paging: p})
	})
	if err != nil {
		fail(w, err)
		return
	}
	chs, err := collect(func(p graph.Paging) (graph.Page[graph.Change], error) {
		return q.Changes(r.Context(), graph.TimeRange{}, graph.ChangeFilter{Subject: graph.SubjectRelation, Paging: p})
	})
	if err != nil {
		fail(w, err)
		return
	}
	out := wireSchema{EntityTypes: []schemaType{}, RelationTypes: []schemaType{}}
	counts := map[string]int{}
	for _, e := range ents {
		counts[e.Type]++
	}
	out.EntityTypes = sortedTypes(counts)

	// A relation is live when its latest change is not a removal.
	sort.SliceStable(chs, func(i, j int) bool {
		if !chs[i].ObservedAt.Equal(chs[j].ObservedAt) {
			return chs[i].ObservedAt.Before(chs[j].ObservedAt)
		}
		return chs[i].RecordedAt.Before(chs[j].RecordedAt)
	})
	type key struct{ from, to, typ string }
	live := map[key]bool{}
	for _, c := range chs {
		live[key{string(c.From), string(c.To), c.RelationType}] = c.Kind != graph.ChangeRemoved
	}
	rel := map[string]int{}
	for k, ok := range live {
		if ok && k.typ != "" {
			rel[k.typ]++
		}
	}
	out.RelationTypes = sortedTypes(rel)
	writeJSON(w, http.StatusOK, out)
}

func sortedTypes(m map[string]int) []schemaType {
	out := make([]schemaType, 0, len(m))
	for n, c := range m {
		if n != "" {
			out = append(out, schemaType{Name: n, Count: c})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// status never touches the store, so it answers immediately in every state.
func (h *handler) status(w http.ResponseWriter, _ *http.Request) {
	st := graph.State{Kind: graph.StateDisabled}
	if h.engine != nil {
		st = graph.StateOf(h.engine)
	}
	child := ChildStopped
	if h.child != nil {
		child = h.child()
	}
	writeJSON(w, http.StatusOK, wireStatus{Engine: string(st.Kind), TSChild: string(child), Detail: st.Reason})
}
